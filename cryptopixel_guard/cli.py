"""ArgumentParser CLI: encrypt, decrypt, inspect."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from cryptopixel_guard.constants import (
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    CRYPTO_OVERHEAD,
    HEADER_SIZE,
    PBKDF2_ITERATIONS,
)
from cryptopixel_guard.crypto_engine import CryptoEngine
from cryptopixel_guard.exceptions import (
    AuthenticationError,
    CapacityError,
    CryptoPixelError,
)
from cryptopixel_guard.stego_engine import StegoEngine, StegoInfo


class CLIHandler:
    """Orchestrates CryptoEngine and StegoEngine behind an argparse interface."""

    def __init__(
        self,
        crypto: Optional[CryptoEngine] = None,
        stego: Optional[StegoEngine] = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
    ) -> None:
        self._crypto = crypto or CryptoEngine()
        self._stego = stego or StegoEngine()
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="cryptopixel-guard",
            description=f"{APP_NAME} v{APP_VERSION} — {APP_DESCRIPTION}",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "Examples:\n"
                "  cryptopixel-guard encrypt -c cover.png -i secret.zip -o stego.png\n"
                "  cryptopixel-guard decrypt -s stego.png -o secret.zip\n"
                "  cryptopixel-guard inspect -s stego.png\n"
            ),
        )
        parser.add_argument(
            "--version",
            action="version",
            version=f"{APP_NAME} {APP_VERSION}",
        )
        subparsers = parser.add_subparsers(dest="command", required=True)

        encrypt = subparsers.add_parser(
            "encrypt",
            help="Encrypt a file and hide the ciphertext in a cover image.",
        )
        encrypt.add_argument(
            "-c",
            "--cover",
            type=Path,
            required=True,
            help="Cover image path (any Pillow-readable format; converted to RGB).",
        )
        encrypt.add_argument(
            "-i",
            "--input",
            type=Path,
            required=True,
            help="Payload file (any binary: documents, archives, images, etc.).",
        )
        encrypt.add_argument(
            "-o",
            "--output",
            type=Path,
            required=True,
            help="Output stego image (must be lossless: .png, .bmp, .tif).",
        )
        encrypt.add_argument(
            "-p",
            "--password",
            default=None,
            help="Passphrase. If omitted, prompted via getpass (no echo).",
        )
        encrypt.set_defaults(handler=self.cmd_encrypt)

        decrypt = subparsers.add_parser(
            "decrypt",
            help="Extract and authenticate-decrypt a payload from a stego image.",
        )
        decrypt.add_argument(
            "-s",
            "--stego",
            type=Path,
            required=True,
            help="Stego image produced by the encrypt command.",
        )
        decrypt.add_argument(
            "-o",
            "--output",
            type=Path,
            required=True,
            help="Destination path for the recovered binary payload.",
        )
        decrypt.add_argument(
            "-p",
            "--password",
            default=None,
            help="Passphrase. If omitted, prompted via getpass (no echo).",
        )
        decrypt.set_defaults(handler=self.cmd_decrypt)

        inspect = subparsers.add_parser(
            "inspect",
            help="Show image capacity and CPXG header metadata (no password required).",
        )
        inspect.add_argument(
            "-s",
            "--stego",
            type=Path,
            required=True,
            help="Image to inspect.",
        )
        inspect.set_defaults(handler=self.cmd_inspect)

        return parser

    def run(self, argv: Optional[Sequence[str]] = None) -> int:
        parser = self.build_parser()
        try:
            args = parser.parse_args(argv)
            return int(args.handler(args))
        except AuthenticationError as exc:
            self._error(str(exc))
            return 2
        except CapacityError as exc:
            self._error(str(exc))
            return 3
        except CryptoPixelError as exc:
            self._error(str(exc))
            return 1
        except KeyboardInterrupt:
            self._error("Aborted.")
            return 130

    def cmd_encrypt(self, args: argparse.Namespace) -> int:
        password = self._resolve_password(args.password, confirm=True)
        plaintext = self._read_bytes(args.input)
        cover = self._stego.load_cover(args.cover)

        framed_need = HEADER_SIZE + self._crypto.encrypted_size(len(plaintext))
        capacity = self._stego.capacity_bytes(cover)
        if framed_need > capacity:
            raise CapacityError(
                f"Cover '{args.cover}' holds {capacity} bytes; "
                f"encrypted payload needs {framed_need} bytes "
                f"(file {len(plaintext)} + crypto overhead {CRYPTO_OVERHEAD} "
                f"+ header {HEADER_SIZE}). Use a larger image."
            )

        blob = self._crypto.encrypt(plaintext, password)
        stego_image = self._stego.embed(cover, blob)
        self._stego.save_lossless(stego_image, args.output)
        self._print(
            f"Embedded {len(plaintext)} byte payload into '{args.output}' "
            f"({len(blob)} byte ciphertext, {capacity} byte capacity, "
            f"PBKDF2-HMAC-SHA256 {PBKDF2_ITERATIONS:,} iterations)."
        )
        return 0

    def cmd_decrypt(self, args: argparse.Namespace) -> int:
        password = self._resolve_password(args.password, confirm=False)
        image = self._stego.load_cover(args.stego)
        blob = self._stego.extract(image)
        plaintext = self._crypto.decrypt(blob, password)
        self._write_bytes(args.output, plaintext)
        self._print(f"Recovered {len(plaintext)} bytes to '{args.output}'.")
        return 0

    def cmd_inspect(self, args: argparse.Namespace) -> int:
        info = self._stego.inspect(args.stego)
        self._print(self._format_inspect(info))
        return 0

    def _resolve_password(self, provided: Optional[str], confirm: bool) -> str:
        if provided is not None:
            if not provided:
                raise CryptoPixelError("Password must not be empty.")
            return provided
        first = getpass.getpass("Password: ")
        if not first:
            raise CryptoPixelError("Password must not be empty.")
        if confirm:
            second = getpass.getpass("Confirm password: ")
            if first != second:
                raise CryptoPixelError("Passwords do not match.")
        return first

    def _read_bytes(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            raise CryptoPixelError(f"Unable to read payload '{path}': {exc}") from exc

    def _write_bytes(self, path: Path, data: bytes) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as extra:
            raise CryptoPixelError(f"Unable to write '{path}': {extra}") from extra

    def _format_inspect(self, info: StegoInfo) -> str:
        lines = [
            f"{APP_NAME} inspect",
            f"  path            : {info.path}",
            f"  dimensions      : {info.width}x{info.height} {info.mode}",
            f"  capacity        : {info.capacity_bytes} bytes",
            f"  header          : {info.header_bytes} bytes (magic + BE32 length)",
            f"  usable payload  : {max(0, info.capacity_bytes - info.header_bytes)} bytes",
            f"  cpxg magic      : {'yes' if info.has_magic else 'no'}",
        ]
        if info.has_magic and info.payload_length is not None:
            lines.append(f"  blob length     : {info.payload_length} bytes")
            lines.append(f"  total embedded  : {info.total_embedded_bytes} bytes")
        elif info.has_magic:
            lines.append("  blob length     : invalid (exceeds capacity)")
        else:
            lines.append("  blob length     : n/a")
        return "\n".join(lines)

    def _print(self, message: str) -> None:
        self._stdout.write(message + "\n")

    def _error(self, message: str) -> None:
        self._stderr.write(f"error: {message}\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    return CLIHandler().run(argv)


if __name__ == "__main__":
    sys.exit(main())
