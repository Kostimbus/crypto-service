from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)


def load_ed25519_pair(priv_path: str, pub_path: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.from_private_bytes(Path(priv_path).read_bytes())
    pub = Ed25519PublicKey.from_public_bytes(Path(pub_path).read_bytes())
    return priv, pub

def load_aead_key(path: str) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    return key
