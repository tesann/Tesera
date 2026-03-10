"""Provenance chain traversal and verification (Spec Section 6, Build Step 5)."""

from collections import deque
from dataclasses import dataclass
from typing import Callable

from tes_core.commit import TesCommit, verify_commit
from tes_core.store import CommitStore

KeyResolver = Callable[[str], str | None]


@dataclass
class ChainVerificationResult:
    """Result of verifying a provenance chain (Spec Section 6.3)."""

    complete: bool  # True if chain reaches roots and all signatures valid
    broken: bool  # True if any commit has invalid signature or is unverifiable
    partial: bool  # True if some parents missing but all found commits valid
    chain_length: int  # total commits verified (valid + invalid)
    valid_commits: list[str]
    invalid_commits: list[str]
    missing_parents: list[str]


def verify_chain(
    commit_id: str,
    store: CommitStore,
    key_resolver: KeyResolver,
) -> ChainVerificationResult:
    """Verify the provenance chain from the given commit to roots (BFS).

    Uses key_resolver(signer key_id) to get public key; if None, commit is
    treated as unverifiable (invalid). Each commit is verified via verify_commit.
    """
    valid_commits: list[str] = []
    invalid_commits: list[str] = []
    missing_parents: list[str] = []

    commit = store.get_by_commit_id(commit_id)
    if commit is None:
        return ChainVerificationResult(
            complete=False,
            broken=False,
            partial=False,
            chain_length=0,
            valid_commits=[],
            invalid_commits=[],
            missing_parents=[commit_id],
        )

    visited: set[str] = set()
    queue: deque[str] = deque([commit_id])

    while queue:
        cid = queue.popleft()
        if cid in visited:
            continue
        visited.add(cid)

        c = store.get_by_commit_id(cid)
        if c is None:
            continue

        key_id = c.signer["key_id"]
        public_key_pem = key_resolver(key_id)

        if public_key_pem is None:
            invalid_commits.append(c.id)
        elif verify_commit(c, public_key_pem):
            valid_commits.append(c.id)
        else:
            invalid_commits.append(c.id)

        for pid in c.parent_ids:
            parent = store.get_by_commit_id(pid)
            if parent is None:
                if pid not in missing_parents:
                    missing_parents.append(pid)
            else:
                if pid not in visited:
                    queue.append(pid)

    broken = len(invalid_commits) > 0
    partial = not broken and len(missing_parents) > 0
    complete = not broken and len(missing_parents) == 0
    chain_length = len(valid_commits) + len(invalid_commits)

    return ChainVerificationResult(
        complete=complete,
        broken=broken,
        partial=partial,
        chain_length=chain_length,
        valid_commits=valid_commits,
        invalid_commits=invalid_commits,
        missing_parents=missing_parents,
    )


def get_provenance(
    media_hash: str,
    store: CommitStore,
    key_resolver: KeyResolver,
) -> list[ChainVerificationResult]:
    """Return verification results for all commits that reference the given media hash."""
    commits = store.get_by_media_hash(media_hash)
    return [verify_chain(c.id, store, key_resolver) for c in commits]


def find_common_ancestor(
    commit_id_a: str,
    commit_id_b: str,
    store: CommitStore,
) -> str | None:
    """Find the nearest common ancestor of two commits (graph traversal only)."""
    # BFS from b to get all ancestors (including b)
    visited_b: set[str] = set()
    queue_b: deque[str] = deque([commit_id_b])
    while queue_b:
        cid = queue_b.popleft()
        if cid in visited_b:
            continue
        visited_b.add(cid)
        commit = store.get_by_commit_id(cid)
        if commit is not None:
            for pid in commit.parent_ids:
                if pid not in visited_b:
                    queue_b.append(pid)

    # BFS from a; first id that is in visited_b is the common ancestor
    visited_a: set[str] = set()
    queue_a: deque[str] = deque([commit_id_a])
    while queue_a:
        cid = queue_a.popleft()
        if cid in visited_a:
            continue
        visited_a.add(cid)
        if cid in visited_b:
            return cid
        commit = store.get_by_commit_id(cid)
        if commit is not None:
            for pid in commit.parent_ids:
                if pid not in visited_a:
                    queue_a.append(pid)

    return None
