"""LSB steganography over RGB channels with a length-prefixed CPXG header."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

from PIL import Image

from cryptopixel_guard.constants import (
    BITS_PER_BYTE,
    CHANNELS_PER_PIXEL,
    HEADER_SIZE,
    LENGTH_SIZE,
    LOSSLESS_SUFFIXES,
    MAGIC,
    MAGIC_SIZE,
)
from cryptopixel_guard.exceptions import CapacityError, FormatError, ImageError


@dataclass(frozen=True)
class StegoInfo:
    """Non-secret metadata extracted from a cover or stego image."""

    path: Path
    width: int
    height: int
    mode: str
    capacity_bytes: int
    has_magic: bool
    payload_length: int | None
    header_bytes: int
    total_embedded_bytes: int | None


class StegoEngine:
    """Embed and extract arbitrary binary payloads via 1-bit LSB RGB steganography."""

    def capacity_bytes(self, image: Image.Image) -> int:
        """Usable payload bytes (excluding nothing — caller reserves the header)."""
        width, height = image.size
        return (width * height * CHANNELS_PER_PIXEL) // BITS_PER_BYTE

    def usable_payload_bytes(self, image: Image.Image) -> int:
        """Bytes available for the inner blob after the 8-byte CPXG header."""
        total = self.capacity_bytes(image)
        remaining = total - HEADER_SIZE
        return max(0, remaining)

    def load_cover(self, path: Path) -> Image.Image:
        """Open an image and convert it to RGB for deterministic channel layout."""
        try:
            image = Image.open(path)
            image.load()
        except Exception as exc:
            raise ImageError(f"Unable to open image '{path}': {exc}") from exc
        try:
            return image.convert("RGB")
        except Exception as exc:
            raise ImageError(f"Unable to convert '{path}' to RGB: {exc}") from exc

    def embed(self, cover: Image.Image, payload: bytes) -> Image.Image:
        """Write MAGIC || length(BE32) || payload into RGB LSBs of a copy of *cover*."""
        if not isinstance(payload, (bytes, bytearray)):
            raise FormatError("Stego payload must be bytes.")
        if len(payload) > 0xFFFFFFFF:
            raise CapacityError("Payload exceeds the 4-byte length field (4 GiB - 1).")

        framed = MAGIC + len(payload).to_bytes(LENGTH_SIZE, "big") + bytes(payload)
        capacity = self.capacity_bytes(cover)
        if len(framed) > capacity:
            raise CapacityError(
                f"Image capacity is {capacity} bytes; framed payload needs {len(framed)} "
                f"bytes (header {HEADER_SIZE} + blob {len(payload)})."
            )

        bits = self._bytes_to_bits(framed)
        pixels = list(cover.convert("RGB").getdata())
        stego_pixels = self._apply_bits(pixels, bits)
        output = Image.new("RGB", cover.size)
        output.putdata(stego_pixels)
        return output

    def extract(self, stego: Image.Image) -> bytes:
        """Read and validate the CPXG frame, returning the inner blob."""
        capacity = self.capacity_bytes(stego)
        if capacity < HEADER_SIZE:
            raise CapacityError("Image is too small to contain a CPXG header.")

        pixels = list(stego.convert("RGB").getdata())
        header = self._read_bytes(pixels, 0, HEADER_SIZE)
        magic = header[:MAGIC_SIZE]
        if magic != MAGIC:
            raise FormatError(
                "CPXG magic bytes not found. This image does not contain a CryptoPixel Guard payload."
            )

        payload_length = int.from_bytes(header[MAGIC_SIZE:HEADER_SIZE], "big")
        total = HEADER_SIZE + payload_length
        if total > capacity:
            raise FormatError(
                f"Declared payload length {payload_length} exceeds image capacity {capacity - HEADER_SIZE}."
            )
        return self._read_bytes(pixels, HEADER_SIZE, payload_length)

    def inspect(self, path: Path) -> StegoInfo:
        """Return capacity and header facts without decrypting."""
        image = self.load_cover(path)
        capacity = self.capacity_bytes(image)
        has_magic = False
        payload_length: int | None = None
        total_embedded: int | None = None

        if capacity >= HEADER_SIZE:
            pixels = list(image.getdata())
            header = self._read_bytes(pixels, 0, HEADER_SIZE)
            if header[:MAGIC_SIZE] == MAGIC:
                has_magic = True
                declared = int.from_bytes(header[MAGIC_SIZE:HEADER_SIZE], "big")
                if HEADER_SIZE + declared <= capacity:
                    payload_length = declared
                    total_embedded = HEADER_SIZE + declared

        return StegoInfo(
            path=path,
            width=image.size[0],
            height=image.size[1],
            mode="RGB",
            capacity_bytes=capacity,
            has_magic=has_magic,
            payload_length=payload_length,
            header_bytes=HEADER_SIZE,
            total_embedded_bytes=total_embedded,
        )

    def save_lossless(self, image: Image.Image, path: Path) -> None:
        """Persist a stego image using a lossless container (PNG default)."""
        suffix = path.suffix.lower()
        if suffix not in LOSSLESS_SUFFIXES:
            raise ImageError(
                f"Refusing to write '{path}'. LSB steganography requires a lossless "
                f"format ({', '.join(sorted(LOSSLESS_SUFFIXES))})."
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            image.save(path)
        except Exception as exc:
            raise ImageError(f"Unable to write stego image '{path}': {exc}") from exc

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        bits: list[int] = []
        for byte in data:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        return bits

    @staticmethod
    def _apply_bits(
        pixels: Sequence[tuple[int, int, int]], bits: Sequence[int]
    ) -> list[tuple[int, int, int]]:
        bit_iter: Iterator[int] = iter(bits)
        output: list[tuple[int, int, int]] = []
        remaining = len(bits)

        for pixel in pixels:
            if remaining <= 0:
                output.append(pixel)
                continue
            channels = list(pixel)
            for channel_index in range(CHANNELS_PER_PIXEL):
                if remaining <= 0:
                    break
                try:
                    bit = next(bit_iter)
                except StopIteration:
                    remaining = 0
                    break
                channels[channel_index] = (channels[channel_index] & 0xFE) | bit
                remaining -= 1
            output.append((channels[0], channels[1], channels[2]))
        return output

    @staticmethod
    def _read_bytes(
        pixels: Sequence[tuple[int, int, int]], offset: int, length: int
    ) -> bytes:
        if length == 0:
            return b""
        start_bit = offset * BITS_PER_BYTE
        bit_count = length * BITS_PER_BYTE
        bits: list[int] = []
        bit_index = 0

        for pixel in pixels:
            for channel in pixel[:CHANNELS_PER_PIXEL]:
                if bit_index >= start_bit + bit_count:
                    break
                if bit_index >= start_bit:
                    bits.append(channel & 1)
                bit_index += 1
            if bit_index >= start_bit + bit_count:
                break

        if len(bits) < bit_count:
            raise FormatError(
                f"Ran out of pixels while reading {length} bytes (got {len(bits)} of {bit_count} bits)."
            )

        out = bytearray(length)
        for byte_index in range(length):
            value = 0
            base = byte_index * BITS_PER_BYTE
            for bit_pos in range(BITS_PER_BYTE):
                value = (value << 1) | bits[base + bit_pos]
            out[byte_index] = value
        return bytes(out)
