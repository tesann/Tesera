"""Tests for the Tesera public API (Build Step 6)."""

import re
import sys
import time
from pathlib import Path

import pytest

from tes_core import Tesera, fingerprint, generate_key_pair, hash_buffer, hash_file

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


# --- Key loading: explicit, env, filesystem, auto-generate ---

HEX_32_RE = re.compile(r"^[0-9a-f]{32}$")


def test_key_explicit_parameter(tmp_path: Path) -> None:
    """Pass private key directly to Tesera(); commit and verify; fingerprint matches."""
    public_pem, private_pem = generate_key_pair()
    path = tmp_path / "t"
    t = Tesera(path=str(path), private_key=private_pem)
    t.commit(str(FIXTURE_PATH), operation="create")
    results = t.verify(str(FIXTURE_PATH))
    assert len(results) == 1
    assert results[0].complete is True
    assert t.key_fingerprint == fingerprint(public_pem)
    t.close()


def test_key_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """TESERA_PRIVATE_KEY set; Tesera() uses it; fingerprint matches."""
    public_pem, private_pem = generate_key_pair()
    monkeypatch.setenv("TESERA_PRIVATE_KEY", private_pem)
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(str(FIXTURE_PATH), operation="create")
    assert t.key_fingerprint == fingerprint(public_pem)
    t.close()


def test_key_env_var_with_escaped_newlines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TESERA_PRIVATE_KEY with literal \\n; SDK replaces with real newlines."""
    public_pem, private_pem = generate_key_pair()
    escaped = private_pem.replace("\n", "\\n")
    monkeypatch.setenv("TESERA_PRIVATE_KEY", escaped)
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    assert t.key_fingerprint == fingerprint(public_pem)
    t.close()


def test_key_priority_explicit_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit private_key wins over TESERA_PRIVATE_KEY."""
    pub_a, priv_a = generate_key_pair()
    pub_b, priv_b = generate_key_pair()
    monkeypatch.setenv("TESERA_PRIVATE_KEY", priv_a)
    path = tmp_path / "t"
    t = Tesera(path=str(path), private_key=priv_b)
    assert t.key_fingerprint == fingerprint(pub_b)
    assert t.key_fingerprint != fingerprint(pub_a)
    t.close()


def test_key_priority_env_over_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TESERA_PRIVATE_KEY wins over key on filesystem."""
    pub_a, priv_a = generate_key_pair()
    pub_b, priv_b = generate_key_pair()
    path = tmp_path / "t"
    path.mkdir()
    keys_dir = path / "keys"
    keys_dir.mkdir()
    (keys_dir / "default.pem").write_text(priv_a, encoding="utf-8")
    (keys_dir / "default.pub.pem").write_text(pub_a, encoding="utf-8")
    monkeypatch.setenv("TESERA_PRIVATE_KEY", priv_b)
    t = Tesera(path=str(path))
    assert t.key_fingerprint == fingerprint(pub_b)
    assert t.key_fingerprint != fingerprint(pub_a)
    t.close()


def test_key_auto_generate(tmp_path: Path) -> None:
    """Fresh dir, no env: Tesera() creates key file and valid accessors."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    assert (path / "keys" / "default.pem").exists()
    assert t.public_key.startswith("-----BEGIN PUBLIC KEY-----")
    assert len(t.key_fingerprint) == 32
    assert HEX_32_RE.match(t.key_fingerprint)
    t.close()


def test_key_fingerprint_accessor(tmp_path: Path) -> None:
    """key_fingerprint is 32 lowercase hex characters."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    assert len(t.key_fingerprint) == 32
    assert HEX_32_RE.match(t.key_fingerprint)
    t.close()


def test_public_key_accessor(tmp_path: Path) -> None:
    """public_key returns PEM starting with BEGIN PUBLIC KEY."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    assert t.public_key.startswith("-----BEGIN PUBLIC KEY-----")
    t.close()


def test_invalid_explicit_key(tmp_path: Path) -> None:
    """Invalid private_key raises ValueError."""
    path = tmp_path / "t"
    with pytest.raises(ValueError, match="Invalid private key"):
        Tesera(path=str(path), private_key="not a real key")


def test_invalid_env_var_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid TESERA_PRIVATE_KEY raises ValueError mentioning env var."""
    monkeypatch.setenv("TESERA_PRIVATE_KEY", "garbage")
    path = tmp_path / "t"
    with pytest.raises(ValueError, match="TESERA_PRIVATE_KEY"):
        Tesera(path=str(path))


def test_explicit_key_no_filesystem(tmp_path: Path) -> None:
    """Explicit key only: no .tesera/keys or store created until first use."""
    _, private_pem = generate_key_pair()
    path = tmp_path / "proj"
    t = Tesera(path=str(path), private_key=private_pem)
    assert not (path / "keys").exists()
    assert not (path / "tesera.db").exists()
    t.close()


# --- Edit workflow, lookup, parent parameters ---


def test_commit_edit_with_existing_parent(tmp_path: Path) -> None:
    """commit_edit with existing parent: returns edit commit linked to original."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    original_bytes = b"generated image bytes"
    original_commit = t.commit(original_bytes, operation="create")
    edited_bytes = b"cropped version"
    edit_commit = t.commit_edit(original=original_bytes, edited=edited_bytes)
    assert edit_commit.operation == "edit"
    assert edit_commit.parent_ids == [original_commit.id]
    t.close()


def test_commit_edit_chain_links_correctly(tmp_path: Path) -> None:
    """commit_edit then history(edited) contains both edit and original create."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    original_bytes = b"original content"
    t.commit(original_bytes, operation="create")
    edited_bytes = b"edited content"
    t.commit_edit(original=original_bytes, edited=edited_bytes)
    hist = t.history(edited_bytes)
    operations = [c.operation for c in hist]
    assert "edit" in operations
    assert "create" in operations
    t.close()


def test_commit_edit_unverified_upload(tmp_path: Path) -> None:
    """commit_edit with unverified original: creates import then edit; parent links to import."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    original_bytes = b"unknown image data"
    edited_bytes = b"edited image data"
    edit_commit = t.commit_edit(original=original_bytes, edited=edited_bytes)
    assert edit_commit.operation == "edit"
    import_found = t.lookup(original_bytes)
    assert import_found is not None
    assert import_found.operation == "import"
    assert import_found.id in edit_commit.parent_ids
    t.close()


def test_commit_edit_unverified_creates_import(tmp_path: Path) -> None:
    """commit_edit unverified: import commit has operation import, empty parent_ids, correct media_hash."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    original_bytes = b"unverified upload bytes"
    t.commit_edit(original=original_bytes, edited=b"edited")
    import_commit = t.lookup(original_bytes)
    assert import_commit is not None
    assert import_commit.operation == "import"
    assert import_commit.parent_ids == []
    assert import_commit.media_hash == hash_buffer(original_bytes)
    t.close()


def test_commit_edit_from_upload_returns_both(tmp_path: Path) -> None:
    """commit_edit_from_upload returns (import_commit, edit_commit); edit parent is import."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    result = t.commit_edit_from_upload(
        original=b"original data", edited=b"edited data"
    )
    assert isinstance(result, tuple)
    assert len(result) == 2
    import_commit, edit_commit = result
    assert import_commit.operation == "import"
    assert edit_commit.operation == "edit"
    assert edit_commit.parent_ids == [import_commit.id]
    t.close()


def test_commit_edit_from_upload_chain(tmp_path: Path) -> None:
    """commit_edit_from_upload then history(edited) returns full chain: edit -> import."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    original_bytes = b"upload data"
    edited_bytes = b"edited upload data"
    t.commit_edit_from_upload(original=original_bytes, edited=edited_bytes)
    hist = t.history(edited_bytes)
    operations = [c.operation for c in hist]
    assert "edit" in operations
    assert "import" in operations
    t.close()


def test_commit_parent_parameter(tmp_path: Path) -> None:
    """commit(..., parent=original.id) produces edit with single parent."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    original_commit = t.commit(b"original", operation="create")
    edited_commit = t.commit(
        b"edited", operation="edit", parent=original_commit.id
    )
    assert edited_commit.parent_ids == [original_commit.id]
    t.close()


def test_commit_parents_parameter(tmp_path: Path) -> None:
    """commit(..., parents=[A.id, B.id]) for derive produces parent_ids containing both."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    commit_a = t.commit(b"media a", operation="create")
    commit_b = t.commit(b"media b", operation="create")
    derived = t.commit(
        b"derived", operation="derive", parents=[commit_a.id, commit_b.id]
    )
    assert set(derived.parent_ids) == {commit_a.id, commit_b.id}
    t.close()


def test_commit_parent_and_parents_conflict(tmp_path: Path) -> None:
    """Passing both parent and parents raises ValueError."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    with pytest.raises(ValueError, match="Cannot specify both"):
        t.commit(
            b"x",
            operation="edit",
            parent="a" * 64,
            parents=["b" * 64],
        )
    t.close()


def test_lookup_found(tmp_path: Path) -> None:
    """lookup after commit returns that commit."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    committed = t.commit(b"some media", operation="create")
    found = t.lookup(b"some media")
    assert found is not None
    assert found.id == committed.id
    t.close()


def test_lookup_not_found(tmp_path: Path) -> None:
    """lookup with never-committed bytes returns None."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    result = t.lookup(b"never committed")
    assert result is None
    t.close()


def test_lookup_bytes_and_path(tmp_path: Path) -> None:
    """Commit by path; lookup with same file bytes returns the commit."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    t.commit(str(FIXTURE_PATH), operation="create")
    fixture_bytes = FIXTURE_PATH.read_bytes()
    found = t.lookup(fixture_bytes)
    assert found is not None
    assert found.media_hash == hash_file(str(FIXTURE_PATH))
    t.close()


def test_lookup_returns_most_recent(tmp_path: Path) -> None:
    """lookup returns the commit with the latest timestamp when multiple exist."""
    path = tmp_path / "t"
    t = Tesera(path=str(path))
    media = b"same content"
    first = t.commit(media, operation="create", metadata={"n": 1})
    time.sleep(1)
    second = t.commit(media, operation="create", metadata={"n": 2})
    found = t.lookup(media)
    assert found is not None
    assert found.id == second.id
    assert found.timestamp >= first.timestamp
    t.close()
