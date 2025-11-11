import os
import base64
from typing import Optional
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature


class SignResult(TypedDict):
    kid: str
    sig: str

class Envelope(TypedDict):
    v: int
    alg: str
    kid: str
    nonce: str
    aad: str
    ct: str


def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())


class Signer:
    def __init__(self, sk: Ed25519PrivateKey, pk: Ed25519PublicKey, kid: str):
        self.sk, self.pk, self.kid = sk, pk, kid

    def sign(self, msg: bytes) -> SignResult:
        sig = self.sk.sign(msg)
        return {"kid": self.kid, "sig": b64e(sig)}

    def verify(self, msg: bytes, sig_b64: str) -> bool:
        try:
            self.pk.verify(b64d(sig_b64), msg)
            return True
        except InvalidSignature:
            return False


class AEAD:
    def __init__(self, key: bytes, kid: str):
        self.aead, self.kid = ChaCha20Poly1305(key), kid

    def encrypt(self, pt: bytes, aad: Optional[bytes]=None) -> Envelope:
        nonce = os.urandom(12)
        ct = self.aead.encrypt(nonce, pt, aad or b"")
        return {"v":1,"alg":"CHACHA20-POLY1305","kid":self.kid,
                "nonce": b64e(nonce), "aad": b64e(aad or b""), "ct": b64e(ct)}

    def decrypt(self, obj: Envelope) -> bytes:
        return self.aead.decrypt(b64d(obj["nonce"]), b64d(obj["ct"]), b64d(obj["aad"]))
