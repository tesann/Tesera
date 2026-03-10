"""Ed25519 key generation, signing, verification, and key fingerprint (Spec Section 3)."""

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_key_pair() -> tuple[str, str]:
    """Generate an Ed25519 key pair using a cryptographically secure random source.

    Returns (public_key_pem, private_key_pem) as PEM-encoded strings.
    """
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return (public_key_pem, private_key_pem)


def sign(data: bytes, private_key_pem: str) -> str:
    """Sign the provided bytes with the Ed25519 private key.

    Returns the 64-byte signature as a 128-character lowercase hex string.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Key is not an Ed25519 private key")
    signature_bytes = private_key.sign(data)
    return signature_bytes.hex()


def verify(data: bytes, signature_hex: str, public_key_pem: str) -> bool:
    """Verify the Ed25519 signature against the data and public key.

    Decodes the hex signature to bytes, then verifies. Returns True if valid,
    False if invalid. Does not raise on invalid signatures.
    """
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(sig_bytes) != 64:
        return False
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception:
        return False
    try:
        public_key.verify(sig_bytes, data)
        return True
    except Exception:
        return False


def fingerprint(public_key_pem: str) -> str:
    """Derive a 32-character hex fingerprint from the public key (Spec Section 3.3).

    Extracts the raw 32-byte public key from the PEM, computes SHA-256 of those bytes,
    takes the first 16 bytes of the digest, returns as 32-character lowercase hex.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    raw_32 = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw_32).digest()
    return digest[:16].hex()
