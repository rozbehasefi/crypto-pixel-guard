# CryptoPixel Guard

Authenticated AES-256-GCM encryption combined with Least Significant Bit (LSB) image steganography.

CryptoPixel Guard hides arbitrary binary files (archives, documents, images, not just text) inside a cover image. The payload is encrypted before embedding. A wrong password or a tampered stego image fails closed via GCM tag verification.

## Cryptographic design

| Property | Value |
| --- | --- |
| Cipher | AES-256-GCM |
| Key derivation | PBKDF2-HMAC-SHA256 |
| Iterations | 100,000 |
| Salt | 16 random bytes per encryption |
| Nonce | 12 random bytes per encryption |
| Auth tag | 16-byte GCM tag (InvalidTag on failure) |

Derived key material is overwritten after use.

## Container format

LSB bitstream, MSB-first per byte, RGB channels only:

```
magic (4, "CPXG") || payload_length (4, big-endian) || salt (16) || nonce (12) || ciphertext || tag (16)
```

Capacity is checked before encryption is committed to disk. Output images must be lossless (PNG, BMP, TIFF). JPEG is rejected on write because lossy compression destroys LSBs.

## Requirements

- Python 3.10+
- `cryptography`
- `Pillow`

```bash
pip install --break-system-packages -r requirements.txt
```

## Usage

```bash
python cryptopixel_guard.py encrypt -c cover.png -i secret.zip -o stego.png
python cryptopixel_guard.py decrypt -s stego.png -o secret.zip
python cryptopixel_guard.py inspect -s stego.png
```

Password is prompted with no echo unless `-p` is supplied. Confirm is required on encrypt.

```bash
python -m cryptopixel_guard encrypt -c cover.png -i payload.bin -o stego.png -p 'passphrase'
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General CryptoPixel error |
| 2 | Authentication failure (wrong password or tamper) |
| 3 | Cover image capacity exceeded |
| 130 | Interrupted |

## Architecture

```
cryptopixel_guard/
  constants.py      Protocol sizes and magic
  exceptions.py     Typed error hierarchy
  crypto_engine.py  CryptoEngine (KDF + AES-GCM)
  stego_engine.py   StegoEngine (LSB embed/extract/inspect)
  cli.py            CLIHandler (argparse: encrypt, decrypt, inspect)
```

## Capacity

Usable bytes = `floor(width * height * 3 / 8) - 8` (header) minus 44 bytes of crypto overhead (salt + nonce + tag).

A 1920x1080 RGB image holds about 777,600 bytes of framed data.

## Security notes

- This is not a traffic-analysis-resistant covert channel. LSB statistical attacks can detect embedding.
- Use a high-entropy passphrase. PBKDF2 with 100k iterations slows guessing; it does not replace a strong password.
- Never reuse a stego PNG as a cover for a second payload if an adversary has the previous version (visual/bit-diff leak).
- Keep cover images you do not publish in the clear alongside the stego image.

## License

Use and modify freely in your own projects.
