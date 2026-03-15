"""Tests for the Tesera public API (Build Step 6)."""

import re
import sys
from pathlib import Path

import pytest

from tes_core import Tesera, hash_file

# Repo root: packages/core/tests -> packages/core -> packages -> root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = _REPO_ROOT / "fixtures" / "test_input.bin"

# Test Vector 1 (Spec Section 9.1)
TEST_VECTOR_1_HASH = "77610e3a886e553d6a12b01186b0855b433029a101ddeb5af929dfedfad3a9e9"

HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def test_init_creates_directory(tmp_path: Path) -> None:
    """Initialize Tesera with a path inside tmp_path; assert directory, DB, and key files exist."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    assert path.is_dir()
    assert (path / "tesera.db").exists()
    assert (path / "keys" / "default.pem").exists()
    assert (path / "keys" / "default.pub.pem").exists()
    t.close()


@pytest.mark.skipif(sys.platform == "win32", reason="Unix-only file permissions")
def test_init_creates_key_with_permissions(tmp_path: Path) -> None:
    """Private key file should have permissions 0o600 (Unix/Mac only)."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    priv_path = path / "keys" / "default.pem"
    assert (priv_path.stat().st_mode & 0o777) == 0o600
    t.close()


def test_init_loads_existing_keys(tmp_path: Path) -> None:
    """First init creates keys; second init at same path loads same key (same fingerprint)."""
    path = tmp_path / "t"
    t1 = Tesera(path=str(path))
    commit1 = t1.commit(str(FIXTURE_PATH), operation="create")
    fingerprint1 = commit1.signer["key_id"]
    t1.close()

    t2 = Tesera(path=str(path))
    commit2 = t2.commit(str(FIXTURE_PATH), operation="create")
    fingerprint2 = commit2.signer["key_id"]
    assert fingerprint1 == fingerprint2
    t2.close()


def test_commit_and_verify(tmp_path: Path) -> None:
    """Commit fixture as create, then verify same file; one result, complete."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(str(FIXTURE_PATH), operation="create")
    results = t.verify(str(FIXTURE_PATH))
    assert len(results) == 1
    assert results[0].complete is True
    t.close()


def test_commit_and_history(tmp_path: Path) -> None:
    """Commit fixture as create, then copy+modify and commit as edit; history on second file."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    first = t.commit(str(FIXTURE_PATH), operation="create")

    second_file = tmp_path / "second.bin"
    second_file.write_bytes(FIXTURE_PATH.read_bytes() + b"x")
    t.commit(str(second_file), operation="edit", parents=[first.id])

    hist = t.history(str(second_file))
    assert len(hist) >= 1
    t.close()


def test_commit_returns_correct_fields(tmp_path: Path) -> None:
    """Returned commit has valid id (64 hex), version 1, media_hash, operation, non-empty signature."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    commit = t.commit(str(FIXTURE_PATH), operation="create")
    assert HEX_64_RE.match(commit.id)
    assert commit.version == 1
    assert commit.media_hash == hash_file(str(FIXTURE_PATH))
    assert commit.operation == "create"
    assert len(commit.signature) > 0
    t.close()


def test_verify_unknown_file(tmp_path: Path) -> None:
    """Verify a file that was never committed returns empty list."""
    path = tmp_path / "t"
    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"never committed")
    t = Tesera(path=str(path))
    results = t.verify(str(unknown))
    assert results == []
    t.close()


def test_get_commit(tmp_path: Path) -> None:
    """After commit, get(commit.id) returns the same commit."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    committed = t.commit(str(FIXTURE_PATH), operation="create")
    retrieved = t.get(committed.id)
    assert retrieved is not None
    assert retrieved.id == committed.id
    assert retrieved.media_hash == committed.media_hash
    t.close()


def test_get_not_found(tmp_path: Path) -> None:
    """get with nonexistent commit ID returns None."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    result = t.get("a" * 64)
    assert result is None
    t.close()


def test_export_and_import(tmp_path: Path) -> None:
    """Commit in t1, export; t2 at different path imports; get in t2 returns matching commit."""
    path_a = tmp_path / "a"
    path_b = tmp_path / "b"
    t1 = Tesera(path=str(path_a))
    committed = t1.commit(str(FIXTURE_PATH), operation="create")
    exported = t1.export(committed.id)
    t1.close()

    t2 = Tesera(path=str(path_b))
    t2.import_commit(exported)
    retrieved = t2.get(committed.id)
    assert retrieved is not None
    assert retrieved.id == committed.id
    assert retrieved.media_hash == committed.media_hash
    assert retrieved.operation == committed.operation
    t2.close()


def test_export_not_found(tmp_path: Path) -> None:
    """Export with nonexistent commit ID raises ValueError."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    with pytest.raises(ValueError, match="Commit not found"):
        t.export("a" * 64)
    t.close()


def test_context_manager(tmp_path: Path) -> None:
    """Use Tesera as context manager; commit inside block; store closed after exit."""
    path = tmp_path / "cm"
    with Tesera(path=str(path)) as t:
        cid = t.commit(str(FIXTURE_PATH), operation="create").id
    # After block, t.close() was called; using the store should raise
    with pytest.raises(Exception):
        t.get(cid)


def test_static_hash() -> None:
    """Tesera.hash(fixture) returns Test Vector 1 hash."""
    result = Tesera.hash(str(FIXTURE_PATH))
    assert result == TEST_VECTOR_1_HASH


def test_static_generate_keys() -> None:
    """Tesera.generate_keys() returns (public_pem, private_pem), both PEM (contain BEGIN)."""
    pub, priv = Tesera.generate_keys()
    assert isinstance(pub, str) and isinstance(priv, str)
    assert "BEGIN" in pub and "BEGIN" in priv


def test_multiple_commits_same_file(tmp_path: Path) -> None:
    """Commit same file twice as create (distinct metadata so distinct IDs); verify returns two results."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(str(FIXTURE_PATH), operation="create", metadata={"n": 1})
    t.commit(str(FIXTURE_PATH), operation="create", metadata={"n": 2})
    results = t.verify(str(FIXTURE_PATH))
    assert len(results) == 2
    t.close()


def test_commit_bytes(tmp_path: Path) -> None:
    """Commit raw bytes, then verify with same bytes; one result."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(b"test media content", operation="create")
    results = t.verify(b"test media content")
    assert len(results) == 1
    t.close()


def test_commit_bytes_matches_file(tmp_path: Path) -> None:
    """Commit fixture by path and by bytes; same media_hash."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    by_path = t.commit(str(FIXTURE_PATH), operation="create")
    fixture_bytes = FIXTURE_PATH.read_bytes()
    by_bytes = t.commit(fixture_bytes, operation="create")
    assert by_path.media_hash == by_bytes.media_hash
    t.close()


def test_commit_default_media_type(tmp_path: Path) -> None:
    """Init with media_type; commit bytes uses that type."""
    path = tmp_path / "t"
    t = Tesera(path=str(path), media_type="image/png")
    commit = t.commit(b"test media content", operation="create")
    assert commit.media_type == "image/png"
    t.close()


def test_commit_override_media_type(tmp_path: Path) -> None:
    """Init default media_type overridden by per-commit media_type."""
    path = tmp_path / "t"
    t = Tesera(path=str(path), media_type="image/png")
    commit = t.commit(b"test media content", operation="create", media_type="image/jpeg")
    assert commit.media_type == "image/jpeg"
    t.close()


def test_verify_bytes(tmp_path: Path) -> None:
    """Commit file by path, verify with raw bytes of same file."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(str(FIXTURE_PATH), operation="create")
    fixture_bytes = FIXTURE_PATH.read_bytes()
    results = t.verify(fixture_bytes)
    assert len(results) == 1
    t.close()


def test_history_bytes(tmp_path: Path) -> None:
    """Commit file by path, then history with raw bytes returns commits."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(str(FIXTURE_PATH), operation="create")
    fixture_bytes = FIXTURE_PATH.read_bytes()
    hist = t.history(fixture_bytes)
    assert len(hist) >= 1
    t.close()
