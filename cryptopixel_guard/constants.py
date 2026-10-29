"""Protocol constants for CryptoPixel Guard.

Wire format (LSB bitstream, MSB-first per byte):

    [magic 4][payload_length 4 BE][salt 16][nonce 12][ciphertext || tag]

The inner cryptographic blob is produced by CryptoEngine. The outer
header is applied by StegoEngine so capacity and integrity checks can
run without deriving keys.
"""

from __future__ import annotations

MAGIC: bytes = b"CPXG"
MAGIC_SIZE: int = 4
LENGTH_SIZE: int = 4
HEADER_SIZE: int = MAGIC_SIZE + LENGTH_SIZE

SALT_SIZE: int = 16
NONCE_SIZE: int = 12
KEY_SIZE: int = 32
GCM_TAG_SIZE: int = 16
PBKDF2_ITERATIONS: int = 100_000

CHANNELS_PER_PIXEL: int = 3
BITS_PER_BYTE: int = 8

CRYPTO_OVERHEAD: int = SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE

LOSSLESS_SUFFIXES: frozenset[str] = frozenset({".png", ".bmp", ".tif", ".tiff"})

APP_NAME: str = "CryptoPixel Guard"
APP_VERSION: str = "1.0.0"
APP_DESCRIPTION: str = (
    "Authenticated AES-256-GCM encryption combined with LSB image steganography."
)
