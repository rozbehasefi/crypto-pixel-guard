"""CryptoPixel Guard — AES-256-GCM + LSB image steganography."""

from cryptopixel_guard.constants import APP_VERSION
from cryptopixel_guard.crypto_engine import CryptoEngine
from cryptopixel_guard.exceptions import (
    AuthenticationError,
    CapacityError,
    CryptoPixelError,
    FormatError,
)
from cryptopixel_guard.stego_engine import StegoEngine, StegoInfo

__all__ = [
    "APP_VERSION",
    "AuthenticationError",
    "CapacityError",
    "CryptoEngine",
    "CryptoPixelError",
    "FormatError",
    "StegoEngine",
    "StegoInfo",
]

__version__ = APP_VERSION
