"""Tests for the media hashing module (Test Vector 1, Section 9.1)."""

import re
from pathlib import Path

from tes_core import detect_media_type, hash_buffer, hash_file

# Repo root: packages/core/tests -> packages/core -> packages -> root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = _REPO_ROOT / "fixtures" / "test_input.bin"

# Test Vector 1 from specification (Section 9.1): SHA-256 of b"test media content"
TEST_VECTOR_1_HASH = "77610e3a886e553d6a12b01186b0855b433029a101ddeb5af929dfedfad3a9e9"

HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def test_hash_file_matches_test_vector_1() -> None:
    """Hash fixtures/test_input.bin and assert result equals Test Vector 1."""
    result = hash_file(str(FIXTURE_PATH))
    assert result == TEST_VECTOR_1_HASH


def test_hash_file_idempotent() -> None:
    """Hashing the same file twice yields the same digest."""
    first = hash_file(str(FIXTURE_PATH))
    second = hash_file(str(FIXTURE_PATH))
    assert first == second
    assert first == TEST_VECTOR_1_HASH


def test_hash_buffer_matches_hash_file() -> None:
    """hash_buffer(b'test media content') equals hash_file on the fixture."""
    buffer_hash = hash_buffer(b"test media content")
    file_hash = hash_file(str(FIXTURE_PATH))
    assert buffer_hash == file_hash
    assert buffer_hash == TEST_VECTOR_1_HASH


def test_hash_output_format() -> None:
    """Hash is exactly 64 lowercase hex characters."""
    result = hash_file(str(FIXTURE_PATH))
    assert len(result) == 64
    assert HEX_64_RE.match(result) is not None


def test_detect_media_type_fixture_is_octet_stream() -> None:
    """Fixture is raw bytes; detect_media_type returns application/octet-stream."""
    result = detect_media_type(str(FIXTURE_PATH))
    assert result == "application/octet-stream"
