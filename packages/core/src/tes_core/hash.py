"""Media hashing and MIME detection for Tesera provenance records."""

import hashlib

CHUNK_SIZE = 65536  # 64 KB


def hash_file(path: str) -> str:
    """Compute SHA-256 of a file by streaming in 64 KB chunks.

    Does not load the entire file into memory.
    Returns a 64-character lowercase hex digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def hash_buffer(data: bytes) -> str:
    """Compute SHA-256 of raw bytes.

    Returns a 64-character lowercase hex digest.
    """
    return hashlib.sha256(data).hexdigest()


def detect_media_type(path: str) -> str:
    """Detect MIME type from file content (magic bytes), not file extension.

    Returns the detected MIME type (e.g. image/jpeg), or application/octet-stream
    if detection fails (missing file, I/O error, unknown type, or libmagic unavailable).
    """
    try:
        import magic

        mime = magic.from_file(path, mime=True)
        return (mime or "application/octet-stream").strip()
    except Exception:
        return "application/octet-stream"
