"""Tests for the store module (Build Step 4). Runs against InMemory and Sqlite stores."""

from pathlib import Path
from unittest.mock import patch

import pytest

from tes_core import (
    InMemoryCommitStore,
    SqliteCommitStore,
    create_commit,
    generate_key_pair,
)

# Repo root: packages/core/tests -> packages/core -> packages -> root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = _REPO_ROOT / "fixtures" / "test_input.bin"
FIXTURE_PATH2 = _REPO_ROOT / "fixtures" / "test_input2.bin"


@pytest.fixture
def store_factory(request: pytest.FixtureRequest):
    """Parametrized: 'memory' -> InMemoryCommitStore(), 'sqlite' -> SqliteCommitStore(':memory:')."""
    kind = request.param
    if kind == "memory":
        yield InMemoryCommitStore()
    else:
        store = SqliteCommitStore(":memory:")
        try:
            yield store
        finally:
            store.close()


def _make_linear_chain(path: Path, length: int = 5):
    """Create a linear chain of commits (create -> edit -> ...) with distinct timestamps.
    Returns (public_pem, private_pem, list of TesCommit from root to tip).
    """
    from tes_core import create_commit

    public_pem, private_pem = generate_key_pair()
    path_str = str(path)
    base_ts = "2026-03-10T12:00:00Z"
    # Build list of timestamps so each create_commit gets a unique ID
    timestamps = [
        f"2026-03-10T12:00:{i:02d}Z"
        for i in range(length)
    ]
    call_count = [0]

    def fake_now(tz=None):
        class FakeDatetime:
            def strftime(self, fmt):
                idx = min(call_count[0], len(timestamps) - 1)
                call_count[0] += 1
                return timestamps[idx]
        return FakeDatetime()

    with patch("tes_core.commit.datetime") as m:
        m.now.return_value = fake_now()
        m.now.side_effect = lambda tz=None: fake_now(tz)
        chain = []
        for i in range(length):
            if i == 0:
                commit = create_commit(path_str, private_pem, "create")
            else:
                commit = create_commit(
                    path_str, private_pem, "edit", parent_ids=[chain[-1].id]
                )
            chain.append(commit)
    return public_pem, private_pem, chain


def _make_branching_chain(path: Path):
    """Create A (create), B and C (edits of A), D (derive from B and C). Returns (_, _, [A, B, C, D])."""
    from tes_core import create_commit

    public_pem, private_pem = generate_key_pair()
    path_str = str(path)
    timestamps = [
        "2026-03-10T12:00:00Z",
        "2026-03-10T12:01:00Z",
        "2026-03-10T12:02:00Z",
        "2026-03-10T12:03:00Z",
    ]
    call_count = [0]

    def fake_now(tz=None):
        class FakeDatetime:
            def strftime(self, fmt):
                idx = min(call_count[0], len(timestamps) - 1)
                call_count[0] += 1
                return timestamps[idx]
        return FakeDatetime()

    with patch("tes_core.commit.datetime") as m:
        m.now.side_effect = lambda tz=None: fake_now(tz)
        A = create_commit(path_str, private_pem, "create")
        B = create_commit(path_str, private_pem, "edit", parent_ids=[A.id])
        C = create_commit(path_str, private_pem, "edit", parent_ids=[A.id])
        D = create_commit(
            path_str, private_pem, "derive", parent_ids=[B.id, C.id]
        )
    return public_pem, private_pem, [A, B, C, D]


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_save_and_get_by_id(store_factory) -> None:
    _, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store_factory.save(commit)
    got = store_factory.get_by_commit_id(commit.id)
    assert got is not None
    assert got.id == commit.id
    assert got.version == commit.version
    assert got.media_hash == commit.media_hash
    assert got.media_type == commit.media_type
    assert got.parent_ids == commit.parent_ids
    assert got.operation == commit.operation
    assert got.timestamp == commit.timestamp
    assert got.signer == commit.signer
    assert got.metadata == commit.metadata
    assert got.signature == commit.signature


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_by_id_not_found(store_factory) -> None:
    assert store_factory.get_by_commit_id("0" * 64) is None


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_save_idempotent(store_factory) -> None:
    _, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store_factory.save(commit)
    store_factory.save(commit)
    got = store_factory.get_by_commit_id(commit.id)
    assert got is not None
    assert got.id == commit.id


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_by_media_hash(store_factory) -> None:
    _, private_pem = generate_key_pair()
    c1 = create_commit(str(FIXTURE_PATH), private_pem, "create")
    c2 = create_commit(str(FIXTURE_PATH2), private_pem, "create")
    store_factory.save(c1)
    store_factory.save(c2)
    results = store_factory.get_by_media_hash(c1.media_hash)
    assert len(results) == 1
    assert results[0].id == c1.id


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_by_media_hash_multiple(store_factory) -> None:
    _, private_pem1 = generate_key_pair()
    _, private_pem2 = generate_key_pair()
    c1 = create_commit(str(FIXTURE_PATH), private_pem1, "create")
    c2 = create_commit(str(FIXTURE_PATH), private_pem2, "create")
    store_factory.save(c1)
    store_factory.save(c2)
    results = store_factory.get_by_media_hash(c1.media_hash)
    assert len(results) == 2
    ids = {r.id for r in results}
    assert c1.id in ids and c2.id in ids


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_children(store_factory) -> None:
    _, _, chain = _make_linear_chain(FIXTURE_PATH, length=2)
    parent, child = chain[0], chain[1]
    store_factory.save(parent)
    store_factory.save(child)
    children = store_factory.get_children(parent.id)
    assert len(children) == 1
    assert children[0].id == child.id


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_children_none(store_factory) -> None:
    _, private_pem = generate_key_pair()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store_factory.save(commit)
    assert store_factory.get_children(commit.id) == []


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_ancestors_linear_chain(store_factory) -> None:
    _, _, chain = _make_linear_chain(FIXTURE_PATH, length=5)
    for c in chain:
        store_factory.save(c)
    tip = chain[-1]
    ancestors = store_factory.get_ancestors(tip.id)
    assert len(ancestors) == 4
    ancestor_ids = {a.id for a in ancestors}
    for c in chain[:-1]:
        assert c.id in ancestor_ids


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_ancestors_respects_max_depth(store_factory) -> None:
    _, _, chain = _make_linear_chain(FIXTURE_PATH, length=5)
    for c in chain:
        store_factory.save(c)
    tip = chain[-1]
    ancestors = store_factory.get_ancestors(tip.id, max_depth=2)
    assert len(ancestors) == 2


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_ancestors_branching(store_factory) -> None:
    _, _, chain = _make_branching_chain(FIXTURE_PATH)
    A, B, C, D = chain[0], chain[1], chain[2], chain[3]
    for c in chain:
        store_factory.save(c)
    ancestors = store_factory.get_ancestors(D.id)
    assert len(ancestors) == 3
    ancestor_ids = {a.id for a in ancestors}
    assert A.id in ancestor_ids and B.id in ancestor_ids and C.id in ancestor_ids


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_get_ancestors_not_found(store_factory) -> None:
    assert store_factory.get_ancestors("0" * 64) == []


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_list_commits_ordering(store_factory) -> None:
    timestamps = [
        "2026-03-10T12:02:00Z",
        "2026-03-10T12:00:00Z",
        "2026-03-10T12:01:00Z",
    ]
    call_count = [0]

    def fake_now(tz=None):
        class FakeDatetime:
            def strftime(self, fmt):
                idx = min(call_count[0], len(timestamps) - 1)
                call_count[0] += 1
                return timestamps[idx]
        return FakeDatetime()

    with patch("tes_core.commit.datetime") as m:
        m.now.side_effect = lambda tz=None: fake_now(tz)
        _, private_pem = generate_key_pair()
        for _ in range(3):
            commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
            store_factory.save(commit)
    listed = store_factory.list_commits()
    assert len(listed) == 3
    # Descending timestamp order
    assert listed[0].timestamp >= listed[1].timestamp >= listed[2].timestamp


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"], indirect=True)
def test_list_commits_pagination(store_factory) -> None:
    _, _, chain = _make_linear_chain(FIXTURE_PATH, length=5)
    for c in chain:
        store_factory.save(c)
    page1 = store_factory.list_commits(limit=2, offset=0)
    page2 = store_factory.list_commits(limit=2, offset=2)
    assert len(page1) == 2 and len(page2) == 2
    ids1 = {c.id for c in page1}
    ids2 = {c.id for c in page2}
    assert ids1.isdisjoint(ids2)


def test_sqlite_context_manager() -> None:
    commit = create_commit(str(FIXTURE_PATH), generate_key_pair()[1], "create")
    with SqliteCommitStore(":memory:") as store:
        store.save(commit)
    # After block, connection should be closed
    with pytest.raises(Exception):
        store._conn.execute("SELECT 1")


def test_sqlite_schema_version() -> None:
    store = SqliteCommitStore(":memory:")
    try:
        cur = store._conn.execute(
            "SELECT value FROM metadata WHERE key = ?",
            ("schema_version",),
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "1"
    finally:
        store.close()
