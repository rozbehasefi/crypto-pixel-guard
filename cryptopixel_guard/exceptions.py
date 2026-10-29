"""Typed exception hierarchy for CryptoPixel Guard."""

from __future__ import annotations


class CryptoPixelError(Exception):
    """Base exception for all CryptoPixel Guard failures."""


class CapacityError(CryptoPixelError):
    """Cover image cannot hold the serialized payload."""


class FormatError(CryptoPixelError):
    """Embedded bitstream is missing, truncated, or not a CPXG container."""


class AuthenticationError(CryptoPixelError):
    """Decryption failed: wrong password or tampered ciphertext (GCM InvalidTag)."""


class CryptoError(CryptoPixelError):
    """Unexpected cryptographic subsystem failure."""


class ImageError(CryptoPixelError):
    """Cover or stego image cannot be opened or converted."""


class PayloadError(CryptoPixelError):
    """Payload file cannot be read or output path cannot be written."""
