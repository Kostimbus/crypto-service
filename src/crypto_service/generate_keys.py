# src/crypto_service/generate_keys.py
"""
CI-friendly key generator for the crypto service.

Usage (project root):
  # run as module (recommended after `pip install -e .` in CI or locally):
  python -m crypto_service.generate_keys --kid ci --overwrite

  # or run directly (without installing package)
  python src/crypto_service/generate_keys.py --kid ci --overwrite
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from tempfile import NamedTemporaryFile

KEY_DIR: Final[Path] = Path(__file__).resolve().parent / "keys"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write bytes to a file atomically and set permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # NamedTemporaryFile in the same directory to keep atomic rename on same filesystem
    with NamedTemporaryFile(dir=str(path.parent), delete=False) as tf:
        tf.write(data)
        tf.flush()
        tmp_name = Path(tf.name)
    tmp_name.chmod(mode)
    tmp_name.replace(path)  # atomic on most POSIX systems


def generate_signing_keypair(kid: str = "k1", out_dir: Path | None = None, overwrite: bool = False) -> None:
    """
    Generate an Ed25519 private/public raw key pair and write them to files:
      <out_dir>/signing_<kid>.priv   (private raw bytes)
      <out_dir>/signing_<kid>.pub    (public raw bytes)
    Private key permissions: 0o600
    Public key permissions: 0o644
    """
    out_dir = (out_dir or KEY_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    priv_path = out_dir / f"signing_{kid}.priv"
    pub_path = out_dir / f"signing_{kid}.pub"

    if any(p.exists() for p in (priv_path, pub_path)) and not overwrite:
        raise FileExistsError(f"Key files exist and overwrite is False: {priv_path}, {pub_path}")

    priv: Ed25519PrivateKey = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    _atomic_write(priv_path, priv_bytes, mode=0o600)
    _atomic_write(pub_path, pub_bytes, mode=0o644)


def generate_aead_key(kid: str = "k1", out_dir: Path | None = None, overwrite: bool = False) -> None:
    """
    Generate a 32-byte AEAD key (raw bytes) and write:
      <out_dir>/aead_<kid>.bin
    Permissions: 0o600
    """
    out_dir = (out_dir or KEY_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    key_path = out_dir / f"aead_{kid}.bin"

    if key_path.exists() and not overwrite:
        raise FileExistsError(f"AEAD key exists and overwrite is False: {key_path}")

    key = os.urandom(32)
    _atomic_write(key_path, key, mode=0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate dev/test keys for crypto_service (CI-friendly).")
    parser.add_argument("--kid", "-k", default="k1", help="Key ID (kid) to use, e.g. k1, k2.")
    parser.add_argument("--out-dir", "-d", default=str(KEY_DIR), help="Output directory (default: src/crypto_service/keys).")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing keys if present.")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    try:
        generate_signing_keypair(kid=args.kid, out_dir=out_dir, overwrite=args.overwrite)
        generate_aead_key(kid=args.kid, out_dir=out_dir, overwrite=args.overwrite)
    except FileExistsError as e:
        print(f"ERROR: {e}")
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

    print(f"Generated keys for kid={args.kid} in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
