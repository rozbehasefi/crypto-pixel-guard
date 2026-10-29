#!/usr/bin/env python3
"""Drop-in launcher for CryptoPixel Guard."""

from __future__ import annotations

import sys

from cryptopixel_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
