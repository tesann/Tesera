"""Tests for the chain module (Build Step 5): verify_chain, get_provenance, find_common_ancestor."""

from pathlib import Path
from unittest.mock import patch

from tes_core import (
    TesCommit,
    InMemoryCommitStore,
    create_commit,
    find_common_ancestor,
    fingerprint,
    generate_key_pair,
    get_provenance,
    verify_chain,
)
from tes_core.chain import KeyResolver

# Repo root: packages/core/tests -> packages/core -> packages -> root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = _REPO_ROOT / "fixtures" / "test_input.bin"
FIXTURE_PATH2 = _REPO_ROOT / "fixtures" / "test_input2.bin"


def make_key_resolver_and_private_key() -> tuple[KeyResolver, str]:
    """Generate a key pair and return (resolver mapping key_id -> public_pem, private_pem)."""
    public_pem, private_pem = generate_key_pair()
    key_id = fingerprint(public_pem)

    def resolve(key_id_arg: str) -> str | None:
        return public_pem if key_id_arg == key_id else None

    return resolve, private_pem


def make_key_resolver_from_pairs(
    pairs: list[tuple[str, str]],
) -> KeyResolver:
    """Build a KeyResolver from a list of (public_pem, private_pem). Maps each fingerprint to its public key."""
    key_map: dict[str, str] = {}
    for public_pem, _ in pairs:
        key_map[fingerprint(public_pem)] = public_pem

    def resolve(key_id_arg: str) -> str | None:
        return key_map.get(key_id_arg)

    return resolve


def _make_linear_chain(path: Path, length: int):
    """Linear chain create -> edit -> ... with patched timestamps. Returns (resolver, private_pem, list of commits)."""
    resolver, private_pem = make_key_resolver_and_private_key()
    path_str = str(path)
    timestamps = [f"2026-03-10T12:00:{i:02d}Z" for i in range(length)]
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
    return resolver, private_pem, chain


def _make_branching_chain(path: Path):
    """A (create), B and C (edits of A), D (derive from B and C). Returns (resolver, private_pem, [A, B, C, D])."""
    resolver, private_pem = make_key_resolver_and_private_key()
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
    return resolver, private_pem, [A, B, C, D]


# ---- Chain verification tests ----


def test_verify_chain_single_root() -> None:
    """One create commit, save, verify from its id -> complete, chain_length=1."""
    resolver, private_pem = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store.save(commit)
    result = verify_chain(commit.id, store, resolver)
    assert result.complete is True
    assert result.broken is False
    assert result.partial is False
    assert result.chain_length == 1
    assert result.valid_commits == [commit.id]
    assert result.invalid_commits == []
    assert result.missing_parents == []


def test_verify_chain_linear_complete() -> None:
    """A (create) -> B (edit) -> C (edit), save all, verify from C -> complete, chain_length=3."""
    resolver, _, chain = _make_linear_chain(FIXTURE_PATH, 3)
    store = InMemoryCommitStore()
    for c in chain:
        store.save(c)
    A, B, C = chain[0], chain[1], chain[2]
    result = verify_chain(C.id, store, resolver)
    assert result.complete is True
    assert result.chain_length == 3
    assert A.id in result.valid_commits
    assert B.id in result.valid_commits
    assert C.id in result.valid_commits


def test_verify_chain_broken_signature() -> None:
    """A -> B; save A and a tampered B (flipped signature). Verify from B -> broken, B in invalid_commits."""
    resolver, private_pem = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    path_str = str(FIXTURE_PATH)
    with patch("tes_core.commit.datetime") as m:
        m.now.return_value.strftime.return_value = "2026-03-10T12:00:00Z"
        A = create_commit(path_str, private_pem, "create")
        m.now.return_value.strftime.return_value = "2026-03-10T12:00:01Z"
        B = create_commit(path_str, private_pem, "edit", parent_ids=[A.id])
    store.save(A)
    flipped = B.signature[:-1] + (
        "f" if B.signature[-1] == "0" else "0"
    )
    tampered_b = TesCommit(
        id=B.id,
        version=B.version,
        media_hash=B.media_hash,
        media_type=B.media_type,
        parent_ids=list(B.parent_ids),
        operation=B.operation,
        timestamp=B.timestamp,
        signer=dict(B.signer),
        metadata=B.metadata,
        signature=flipped,
    )
    store.save(tampered_b)
    result = verify_chain(B.id, store, resolver)
    assert result.broken is True
    assert B.id in result.invalid_commits


def test_verify_chain_partial_missing_parent() -> None:
    """A (create), B (edit of A); save only B. Verify from B -> partial, B valid, A in missing_parents."""
    resolver, private_pem = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    with patch("tes_core.commit.datetime") as m:
        m.now.return_value.strftime.return_value = "2026-03-10T12:00:00Z"
        A = create_commit(str(FIXTURE_PATH), private_pem, "create")
        m.now.return_value.strftime.return_value = "2026-03-10T12:00:01Z"
        B = create_commit(
            str(FIXTURE_PATH), private_pem, "edit", parent_ids=[A.id]
        )
    store.save(B)
    result = verify_chain(B.id, store, resolver)
    assert result.partial is True
    assert B.id in result.valid_commits
    assert A.id in result.missing_parents


def test_verify_chain_unknown_key() -> None:
    """Commit saved; key_resolver returns None for all. Verify -> broken (unverifiable = invalid)."""
    _, private_pem = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store.save(commit)

    def no_key(key_id: str) -> str | None:
        return None

    result = verify_chain(commit.id, store, no_key)
    assert result.broken is True
    assert commit.id in result.invalid_commits


def test_verify_chain_not_found() -> None:
    """Verify with nonexistent commit_id -> chain_length=0, missing_parents contains id."""
    resolver, _ = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    fake_id = "a" * 64
    result = verify_chain(fake_id, store, resolver)
    assert result.chain_length == 0
    assert fake_id in result.missing_parents
    assert result.complete is False


def test_verify_chain_branching() -> None:
    """A -> B, A -> C, D (derive B,C); save all; verify from D -> complete, chain_length=4."""
    resolver, _, chain = _make_branching_chain(FIXTURE_PATH)
    store = InMemoryCommitStore()
    for c in chain:
        store.save(c)
    A, B, C, D = chain[0], chain[1], chain[2], chain[3]
    result = verify_chain(D.id, store, resolver)
    assert result.complete is True
    assert result.chain_length == 4
    assert A.id in result.valid_commits
    assert B.id in result.valid_commits
    assert C.id in result.valid_commits
    assert D.id in result.valid_commits


def test_verify_chain_max_depth_respected() -> None:
    """A -> B -> C -> D linear; verify from D -> chain_length=4, no duplicates in valid_commits."""
    resolver, _, chain = _make_linear_chain(FIXTURE_PATH, 4)
    store = InMemoryCommitStore()
    for c in chain:
        store.save(c)
    result = verify_chain(chain[-1].id, store, resolver)
    assert result.chain_length == 4
    assert len(result.valid_commits) == 4
    assert len(set(result.valid_commits)) == 4


# ---- Provenance lookup tests ----


def test_get_provenance_found() -> None:
    """One commit for test_input.bin, save; get_provenance(media_hash) -> one result, complete."""
    resolver, private_pem = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    commit = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store.save(commit)
    results = get_provenance(commit.media_hash, store, resolver)
    assert len(results) == 1
    assert results[0].complete is True


def test_get_provenance_not_found() -> None:
    """get_provenance with random hash -> empty list."""
    resolver, _ = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    results = get_provenance("0" * 64, store, resolver)
    assert results == []


def test_get_provenance_multiple_commits_same_hash() -> None:
    """Two commits for same file (two key pairs), save both; get_provenance -> two results."""
    store = InMemoryCommitStore()
    path_str = str(FIXTURE_PATH)
    pairs = [generate_key_pair() for _ in range(2)]
    resolver = make_key_resolver_from_pairs(pairs)
    commits = []
    for public_pem, private_pem in pairs:
        commit = create_commit(path_str, private_pem, "create")
        commits.append(commit)
        store.save(commit)
    media_hash = commits[0].media_hash
    results = get_provenance(media_hash, store, resolver)
    assert len(results) == 2


# ---- Common ancestor tests ----


def test_find_common_ancestor_direct() -> None:
    """A (create), B (edit A), C (edit A); find_common_ancestor(B.id, C.id) == A.id."""
    _, _, chain = _make_branching_chain(FIXTURE_PATH)
    A, B, C = chain[0], chain[1], chain[2]
    store = InMemoryCommitStore()
    for c in chain:
        store.save(c)
    assert find_common_ancestor(B.id, C.id, store) == A.id


def test_find_common_ancestor_deeper() -> None:
    """A -> B -> D and A -> C -> E; find_common_ancestor(D.id, E.id) == A.id."""
    resolver, private_pem = make_key_resolver_and_private_key()
    path_str = str(FIXTURE_PATH)
    timestamps = [
        "2026-03-10T12:00:00Z",
        "2026-03-10T12:01:00Z",
        "2026-03-10T12:02:00Z",
        "2026-03-10T12:03:00Z",
        "2026-03-10T12:04:00Z",
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
        D = create_commit(path_str, private_pem, "edit", parent_ids=[B.id])
        E = create_commit(path_str, private_pem, "edit", parent_ids=[C.id])
    store = InMemoryCommitStore()
    for c in [A, B, C, D, E]:
        store.save(c)
    assert find_common_ancestor(D.id, E.id, store) == A.id


def test_find_common_ancestor_none() -> None:
    """Two unrelated creates; find_common_ancestor returns None."""
    store = InMemoryCommitStore()
    with patch("tes_core.commit.datetime") as m:
        m.now.return_value.strftime.return_value = "2026-03-10T12:00:00Z"
        A = create_commit(str(FIXTURE_PATH), generate_key_pair()[1], "create")
        m.now.return_value.strftime.return_value = "2026-03-10T12:00:01Z"
        B = create_commit(
            str(FIXTURE_PATH2), generate_key_pair()[1], "create"
        )
    store.save(A)
    store.save(B)
    assert find_common_ancestor(A.id, B.id, store) is None


def test_find_common_ancestor_same_commit() -> None:
    """find_common_ancestor(A.id, A.id) == A.id."""
    _, private_pem = make_key_resolver_and_private_key()
    store = InMemoryCommitStore()
    A = create_commit(str(FIXTURE_PATH), private_pem, "create")
    store.save(A)
    assert find_common_ancestor(A.id, A.id, store) == A.id
