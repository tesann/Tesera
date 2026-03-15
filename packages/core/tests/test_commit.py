"""Tests for the commit module (Spec Section 9.3, create/verify/serialize, validation)."""

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from tes_core import (
    TesCommit,
    canonicalize,
    create_commit,
    deserialize_commit,
    generate_key_pair,
    serialize_commit,
    verify_commit,
)

# Repo root: packages/core/tests -> packages/core -> packages -> root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = _REPO_ROOT / "fixtures" / "test_input.bin"

# Test Vector 1 (Section 9.1): SHA-256 of fixture content
TEST_VECTOR_1_HASH = "77610e3a886e553d6a12b01186b0855b433029a101ddeb5af929dfedfad3a9e9"

# Test Vector 3 (Section 9.3) expected canonical output (exact string)
TEST_VECTOR_3_EXPECTED = (
    '{"media_hash":"77610e3a886e553d6a12b01186b0855b433029a101ddeb5af929dfedfad3a9e9",'
    '"media_type":"image/jpeg","operation":"create","parent_ids":[],"signer":{'
    '"key_id":"39f713d0a644253f04529421b9f51b9b"},"timestamp":"2026-03-10T14:30:00Z",'
    '"version":1}'
)

HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def test_create_commit_basic() -> None:
    """Create a commit for fixture with operation create; assert media_hash, version, parent_ids, operation."""
    _, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    assert commit.media_hash == TEST_VECTOR_1_HASH
    assert commit.version == 1
    assert commit.parent_ids == []
    assert commit.operation == "create"


def test_verify_commit_valid() -> None:
    """Create a commit, verify with same public key; returns True."""
    public_pem, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    assert verify_commit(commit, public_pem) is True


def test_verify_commit_wrong_key() -> None:
    """Create with key A, verify with key B; returns False."""
    _, private_a = generate_key_pair()
    public_b, _ = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_a, "create")
    assert verify_commit(commit, public_b) is False


def test_verify_commit_tampered_field() -> None:
    """Change media_hash on commit; verify returns False."""
    public_pem, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    tampered = TesCommit(
        id=commit.id,
        version=commit.version,
        media_hash="0" * 64,
        media_type=commit.media_type,
        parent_ids=commit.parent_ids,
        operation=commit.operation,
        timestamp=commit.timestamp,
        signer=commit.signer,
        metadata=commit.metadata,
        signature=commit.signature,
    )
    assert verify_commit(tampered, public_pem) is False


def test_verify_commit_tampered_signature() -> None:
    """Flip a character in the signature; verify returns False."""
    public_pem, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    flipped = commit.signature[:-1] + ("f" if commit.signature[-1] == "0" else "0")
    tampered = TesCommit(
        id=commit.id,
        version=commit.version,
        media_hash=commit.media_hash,
        media_type=commit.media_type,
        parent_ids=commit.parent_ids,
        operation=commit.operation,
        timestamp=commit.timestamp,
        signer=commit.signer,
        metadata=commit.metadata,
        signature=flipped,
    )
    assert verify_commit(tampered, public_pem) is False


def test_commit_id_deterministic() -> None:
    """Same inputs and fixed timestamp produce the same commit ID."""
    fixed_ts = "2026-03-10T12:00:00Z"
    with patch("tes_core.commit.datetime") as mock_dt:
        mock_dt.now.return_value.strftime.return_value = fixed_ts
        _, private_pem = generate_key_pair()
        commit1 = create_commit(str(FIXTURE_PATH), private_pem, "create")
        commit2 = create_commit(str(FIXTURE_PATH), private_pem, "create")
    assert commit1.id == commit2.id


def test_commit_id_format() -> None:
    """Commit ID is 64 chars and matches ^[0-9a-f]{64}$."""
    _, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    assert len(commit.id) == 64
    assert HEX_64_RE.match(commit.id) is not None


def test_parent_ids_sorted() -> None:
    """derive with unsorted parent_ids; commit.parent_ids is sorted ascending."""
    _, private_pem = generate_key_pair()
    parent_ids = ["ff" * 32, "aa" * 32, "cc" * 32]
    commit = create_commit(
        str(FIXTURE_PATH), private_pem, "derive", parent_ids=parent_ids
    )
    assert commit.parent_ids == ["aa" * 32, "cc" * 32, "ff" * 32]


def test_create_edit_requires_one_parent() -> None:
    """operation edit with empty parent_ids raises ValueError."""
    _, private_pem = generate_key_pair()
    try:
        create_commit(str(FIXTURE_PATH), private_pem, "edit", parent_ids=[])
    except ValueError as e:
        assert "edit" in str(e).lower() and "parent" in str(e).lower()
    else:
        raise AssertionError("expected ValueError")


def test_create_create_rejects_parents() -> None:
    """operation create with non-empty parent_ids raises ValueError."""
    _, private_pem = generate_key_pair()
    try:
        create_commit(
            str(FIXTURE_PATH),
            private_pem,
            "create",
            parent_ids=["a" * 64],
        )
    except ValueError as e:
        assert "create" in str(e).lower() and "parent" in str(e).lower()
    else:
        raise AssertionError("expected ValueError")


def test_serialize_deserialize_roundtrip() -> None:
    """Serialize commit, deserialize; every field matches original."""
    _, private_pem = generate_key_pair()
    original = create_commit(str(FIXTURE_PATH), private_pem, "create")
    json_str = serialize_commit(original)
    restored = deserialize_commit(json_str)
    assert restored.id == original.id
    assert restored.version == original.version
    assert restored.media_hash == original.media_hash
    assert restored.media_type == original.media_type
    assert restored.parent_ids == original.parent_ids
    assert restored.operation == original.operation
    assert restored.timestamp == original.timestamp
    assert restored.signer == original.signer
    assert restored.metadata == original.metadata
    assert restored.signature == original.signature


def test_canonicalize_matches_test_vector_3() -> None:
    """Section 9.3: canonicalize(body) equals the exact spec string; version as int 1."""
    body = {
        "media_hash": "77610e3a886e553d6a12b01186b0855b433029a101ddeb5af929dfedfad3a9e9",
        "media_type": "image/jpeg",
        "operation": "create",
        "parent_ids": [],
        "signer": {"key_id": "39f713d0a644253f04529421b9f51b9b"},
        "timestamp": "2026-03-10T14:30:00Z",
        "version": 1,
    }
    result = canonicalize(body)
    assert result == TEST_VECTOR_3_EXPECTED


def test_metadata_omitted_when_none() -> None:
    """Create commit with no metadata; serialized string does not contain "metadata" key."""
    _, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    json_str = serialize_commit(commit)
    assert "metadata" not in json_str


def test_create_commit_from_bytes() -> None:
    """Create commit from raw bytes; media_hash equals Test Vector 1."""
    _, private_pem = generate_key_pair()
    commit = create_commit(b"test media content", private_pem, "create")
    assert commit.media_hash == TEST_VECTOR_1_HASH


def test_create_commit_bytes_matches_file() -> None:
    """Commit from file path and from same bytes yield the same media_hash."""
    _, private_pem = generate_key_pair()
    fixture_bytes = FIXTURE_PATH.read_bytes()
    commit_from_path = create_commit(str(FIXTURE_PATH), private_pem, "create")
    commit_from_bytes = create_commit(fixture_bytes, private_pem, "create")
    assert commit_from_path.media_hash == commit_from_bytes.media_hash


def test_create_commit_explicit_media_type() -> None:
    """Commit from bytes with explicit media_type; commit.media_type is that value."""
    _, private_pem = generate_key_pair()
    commit = create_commit(
        b"test media content", private_pem, "create", media_type="image/png"
    )
    assert commit.media_type == "image/png"


def test_create_commit_rejects_wrong_input_type() -> None:
    """Passing non-str, non-bytes as media raises TypeError."""
    _, private_pem = generate_key_pair()
    with pytest.raises(TypeError, match="media must be a file path \\(str\\) or raw bytes \\(bytes\\)"):
        create_commit(123, private_pem, "create")

