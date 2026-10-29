"""AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 KDF."""

from __future__ import annotations

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptopixel_guard.constants import (
    GCM_TAG_SIZE,
    KEY_SIZE,
    NONCE_SIZE,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
)
from cryptopixel_guard.exceptions import AuthenticationError, CryptoError, PayloadError


class CryptoEngine:
    """Military-grade authenticated encryption for arbitrary binary payloads.

    Blob layout (no extra framing here; StegoEngine adds magic + length):

        salt (16) || nonce (12) || AES-256-GCM(ciphertext || 16-byte tag)
    """

    _KDF_ALGORITHM: Final = hashes.SHA256()

    def encrypt(self, plaintext: bytes, password: str) -> bytes:
        """Encrypt *plaintext* under *password*.

        Returns the concatenated salt, nonce, ciphertext, and GCM tag.
        Derived key material is overwritten before return.
        """
        if not password:
            raise PayloadError("Password must be a non-empty string.")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise PayloadError("Plaintext must be bytes.")

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        password_buf = bytearray(password.encode("utf-8"))
        key_buf = bytearray()
        try:
            key_buf = self._derive_key(password_buf, salt)
            aesgcm = AESGCM(bytes(key_buf))
            ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), associated_data=None)
        except AuthenticationError:
            raise
        except Exception as exc:
            raise CryptoError(f"Encryption failed: {exc}") from exc
        finally:
            self._secure_zero(key_buf)
            self._secure_zero(password_buf)

        if len(ciphertext) < GCM_TAG_SIZE:
            raise CryptoError("AES-GCM produced an unexpectedly short ciphertext.")
        return salt + nonce + ciphertext

    def decrypt(self, blob: bytes, password: str) -> bytes:
        """Decrypt a blob produced by :meth:`encrypt`.

        Raises AuthenticationError on wrong password or bit-flipped ciphertext
        (cryptography InvalidTag).
        """
        if not password:
            raise PayloadError("Password must be a non-empty string.")
        minimum = SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < minimum:
            raise CryptoError(
                f"Ciphertext blob is truncated (need at least {minimum} bytes, got "
                f"{0 if blob is None else len(blob)})."
            )

        salt = bytes(blob[:SALT_SIZE])
        nonce = bytes(blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE])
        ciphertext = bytes(blob[SALT_SIZE + NONCE_SIZE :])

        password_buf = bytearray(password.encode("utf-8"))
        key_buf = bytearray()
        try:
            key_buf = self._derive_key(password_buf, salt)
            aesgcm = AESGCM(bytes(key_buf))
            return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except InvalidTag as exc:
            raise AuthenticationError(
                "Authentication failed: wrong password or the stego image was tampered with."
            ) from exc
        except AuthenticationError:
            raise
        except Exception as exc:
            raise CryptoError(f"Decryption failed: {exc}") from exc
        finally:
            self._secure_zero(key_buf)
            self._secure_zero(password_buf)

    def encrypted_size(self, plaintext_len: int) -> int:
        """Return ciphertext blob size for a given plaintext length."""
        if plaintext_len < 0:
            raise PayloadError("Plaintext length cannot be negative.")
        return plaintext_len + SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE

    def _derive_key(self, password_buf: bytearray, salt: bytes) -> bytearray:
        if len(salt) != SALT_SIZE:
            raise CryptoError(f"Salt must be exactly {SALT_SIZE} bytes.")
        kdf = PBKDF2HMAC(
            algorithm=self._KDF_ALGORITHM,
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        derived = kdf.derive(bytes(password_buf))
        if len(derived) != KEY_SIZE:
            self._secure_zero(bytearray(derived))
            raise CryptoError("KDF returned an unexpected key length.")
        return bytearray(derived)

    @staticmethod
    def _secure_zero(buf: bytearray) -> None:
        """Best-effort overwrite of mutable secret buffers."""
        if not buf:
            return
        for index in range(len(buf)):
            buf[index] = 0
        buf.clear()
