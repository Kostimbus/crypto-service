import os
from hypothesis import given, strategies as st
from crypto_service.crypto import AEAD, Signer, b64e
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def gen_signer():
    sk = Ed25519PrivateKey.generate()
    return Signer(sk, sk.public_key(), "t")

@given(st.binary())
def test_sign_verify_roundtrip(msg):
    s = gen_signer()
    sig = s.sign(msg)["sig"]
    assert s.verify(msg, sig)
    # any tamper ⇒ invalid
    if len(msg)>0:
        tampered = msg[:-1] + bytes([(msg[-1]^0x01)])
        assert not s.verify(tampered, sig)

@given(st.binary(), st.binary())
def test_aead_confidentiality(pt, aad):
    a = AEAD(os.urandom(32), "t")
    e1 = a.encrypt(pt, aad)
    e2 = a.encrypt(pt, aad)
    assert e1["ct"] != e2["ct"]  # fresh nonce ⇒ different ciphertext
    # wrong AAD ⇒ decrypt fails
    from pytest import raises
    bad = dict(e1)
    bad["aad"] = b64e(aad + b"x")
    with raises(Exception):
        a.decrypt(bad)
