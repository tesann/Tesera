"""Tests for the key management module (Specification Section 3, Test Vector 9.2)."""

import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tes_core import fingerprint, generate_key_pair, sign, verify

# Specification Section 9.2: Key Fingerprint test vector
TEST_VECTOR_2_PUBLIC_KEY_HEX = (
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
TEST_VECTOR_2_FINGERPRINT = "39f713d0a644253f04529421b9f51b9b"

HEX_128_RE = re.compile(r"^[0-9a-f]{128}$")
HEX_32_RE = re.compile(r"^[0-9a-f]{32}$")


def test_sign_and_verify_roundtrip() -> None:
    """Generate a key pair, sign b"test data", verify with public key. Assert True."""
    public_pem, private_pem = generate_key_pair()
    data = b"test data"
    signature = sign(data, private_pem)
    assert verify(data, signature, public_pem) is True


def test_verify_fails_wrong_key() -> None:
    """Sign with key pair A. Verify with key pair B's public key. Assert False."""
    _, private_a = generate_key_pair()
    public_b, _ = generate_key_pair()
    data = b"test data"
    signature = sign(data, private_a)
    assert verify(data, signature, public_b) is False


def test_verify_fails_tampered_data() -> None:
    """Sign b"original data". Verify signature against b"tampered data". Assert False."""
    public_pem, private_pem = generate_key_pair()
    signature = sign(b"original data", private_pem)
    assert verify(b"tampered data", signature, public_pem) is False


def test_verify_fails_tampered_signature() -> None:
    """Sign data, flip a character in the hex signature, verify. Assert False."""
    public_pem, private_pem = generate_key_pair()
    data = b"test data"
    signature = sign(data, private_pem)
    # Flip one character in the hex string
    tampered = signature[:-1] + ("f" if signature[-1] == "0" else "0")
    assert verify(data, tampered, public_pem) is False


def test_fingerprint_deterministic() -> None:
    """Generate a key pair. Compute fingerprint twice. Assert identical."""
    public_pem, _ = generate_key_pair()
    first = fingerprint(public_pem)
    second = fingerprint(public_pem)
    assert first == second


def test_fingerprint_format() -> None:
    """Generate a key pair. Fingerprint is 32 chars and matches ^[0-9a-f]{32}$."""
    public_pem, _ = generate_key_pair()
    result = fingerprint(public_pem)
    assert len(result) == 32
    assert HEX_32_RE.match(result) is not None


def test_fingerprint_different_keys() -> None:
    """Generate two key pairs. Assert their fingerprints are different."""
    public_a, _ = generate_key_pair()
    public_b, _ = generate_key_pair()
    assert fingerprint(public_a) != fingerprint(public_b)


def test_fingerprint_test_vector_2() -> None:
    """Specification Section 9.2: given public key raw hex, fingerprint must match.

    Public key raw bytes (hex): 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    Expected fingerprint: 39f713d0a644253f04529421b9f51b9b
    """
    raw_bytes = bytes.fromhex(TEST_VECTOR_2_PUBLIC_KEY_HEX)
    public_key = Ed25519PublicKey.from_public_bytes(raw_bytes)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    result = fingerprint(public_key_pem)
    assert result == TEST_VECTOR_2_FINGERPRINT


def test_signature_format() -> None:
    """Sign some data. Signature is 128 chars and matches ^[0-9a-f]{128}$."""
    _, private_pem = generate_key_pair()
    signature = sign(b"some data", private_pem)
    assert len(signature) == 128
    assert HEX_128_RE.match(signature) is not None
