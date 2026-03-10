"""Abstract commit store interface and implementations (Build Step 4)."""

import sqlite3
from abc import ABC, abstractmethod
from collections import deque

from tes_core.commit import TesCommit, deserialize_commit, serialize_commit


class CommitStore(ABC):
    """Abstract base class for persisting and querying TesCommit instances."""

    @abstractmethod
    def save(self, commit: TesCommit) -> None:
        """Persist a commit. Idempotent: if same ID exists, do nothing."""
        ...

    @abstractmethod
    def get_by_commit_id(self, commit_id: str) -> TesCommit | None:
        """Retrieve a single commit by ID. Return None if not found."""
        ...

    @abstractmethod
    def get_by_media_hash(self, media_hash: str) -> list[TesCommit]:
        """Retrieve all commits that reference the given media hash."""
        ...

    @abstractmethod
    def get_children(self, commit_id: str) -> list[TesCommit]:
        """Retrieve all commits that have this commit_id in their parent_ids."""
        ...

    @abstractmethod
    def get_ancestors(self, commit_id: str, max_depth: int = 50) -> list[TesCommit]:
        """Walk parent graph upward; return ancestor commits up to max_depth levels (BFS)."""
        ...

    @abstractmethod
    def list_commits(self, limit: int = 100, offset: int = 0) -> list[TesCommit]:
        """Return commits ordered by timestamp descending, with pagination."""
        ...


class InMemoryCommitStore(CommitStore):
    """In-memory store for testing. Not persistent or thread-safe."""

    def __init__(self) -> None:
        self._commits: dict[str, TesCommit] = {}

    def save(self, commit: TesCommit) -> None:
        if commit.id not in self._commits:
            self._commits[commit.id] = commit

    def get_by_commit_id(self, commit_id: str) -> TesCommit | None:
        return self._commits.get(commit_id)

    def get_by_media_hash(self, media_hash: str) -> list[TesCommit]:
        return [c for c in self._commits.values() if c.media_hash == media_hash]

    def get_children(self, commit_id: str) -> list[TesCommit]:
        return [c for c in self._commits.values() if commit_id in c.parent_ids]

    def get_ancestors(self, commit_id: str, max_depth: int = 50) -> list[TesCommit]:
        commit = self._commits.get(commit_id)
        if commit is None:
            return []
        result: list[TesCommit] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for pid in commit.parent_ids:
            if pid not in visited:
                visited.add(pid)
                queue.append((pid, 1))
        while queue:
            cid, depth = queue.popleft()
            if depth > max_depth:
                continue
            ancestor = self._commits.get(cid)
            if ancestor is None:
                continue
            result.append(ancestor)
            if depth < max_depth:
                for pid in ancestor.parent_ids:
                    if pid not in visited:
                        visited.add(pid)
                        queue.append((pid, depth + 1))
        return result

    def list_commits(self, limit: int = 100, offset: int = 0) -> list[TesCommit]:
        ordered = sorted(
            self._commits.values(),
            key=lambda c: c.timestamp,
            reverse=True,
        )
        return ordered[offset : offset + limit]


class SqliteCommitStore(CommitStore):
    """SQLite-backed commit store with schema versioning and context manager support."""

    SCHEMA_VERSION = "1"

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS commits (
                id TEXT PRIMARY KEY,
                media_hash TEXT NOT NULL,
                media_type TEXT NOT NULL,
                operation TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                signer_key_id TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS commit_parents (
                commit_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                PRIMARY KEY (commit_id, parent_id)
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_media_hash ON commits(media_hash);
            CREATE INDEX IF NOT EXISTS idx_signer ON commits(signer_key_id);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON commits(timestamp);
            CREATE INDEX IF NOT EXISTS idx_parent_id ON commit_parents(parent_id);
        """)
        self._conn.commit()
        cur = self._conn.execute(
            "SELECT value FROM metadata WHERE key = ?",
            ("schema_version",),
        )
        row = cur.fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                ("schema_version", self.SCHEMA_VERSION),
            )
            self._conn.commit()
        elif row[0] != self.SCHEMA_VERSION:
            self._conn.close()
            raise RuntimeError(
                f"Schema version mismatch: expected {self.SCHEMA_VERSION!r}, got {row[0]!r}"
            )

    def save(self, commit: TesCommit) -> None:
        raw_json = serialize_commit(commit)
        signer_key_id = commit.signer["key_id"]
        self._conn.execute(
            """INSERT OR IGNORE INTO commits
               (id, media_hash, media_type, operation, timestamp, signer_key_id, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                commit.id,
                commit.media_hash,
                commit.media_type,
                commit.operation,
                commit.timestamp,
                signer_key_id,
                raw_json,
            ),
        )
        for parent_id in commit.parent_ids:
            self._conn.execute(
                "INSERT OR IGNORE INTO commit_parents (commit_id, parent_id) VALUES (?, ?)",
                (commit.id, parent_id),
            )
        self._conn.commit()

    def get_by_commit_id(self, commit_id: str) -> TesCommit | None:
        cur = self._conn.execute("SELECT raw_json FROM commits WHERE id = ?", (commit_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return deserialize_commit(row[0])

    def get_by_media_hash(self, media_hash: str) -> list[TesCommit]:
        cur = self._conn.execute(
            "SELECT raw_json FROM commits WHERE media_hash = ?",
            (media_hash,),
        )
        return [deserialize_commit(row[0]) for row in cur.fetchall()]

    def get_children(self, commit_id: str) -> list[TesCommit]:
        cur = self._conn.execute(
            """SELECT c.raw_json FROM commits c
               JOIN commit_parents p ON c.id = p.commit_id
               WHERE p.parent_id = ?""",
            (commit_id,),
        )
        return [deserialize_commit(row[0]) for row in cur.fetchall()]

    def get_ancestors(self, commit_id: str, max_depth: int = 50) -> list[TesCommit]:
        commit = self.get_by_commit_id(commit_id)
        if commit is None:
            return []
        result: list[TesCommit] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for pid in commit.parent_ids:
            if pid not in visited:
                visited.add(pid)
                queue.append((pid, 1))
        while queue:
            cid, depth = queue.popleft()
            if depth > max_depth:
                continue
            ancestor = self.get_by_commit_id(cid)
            if ancestor is None:
                continue
            result.append(ancestor)
            if depth < max_depth:
                cur = self._conn.execute(
                    "SELECT parent_id FROM commit_parents WHERE commit_id = ?",
                    (cid,),
                )
                for (pid,) in cur.fetchall():
                    if pid not in visited:
                        visited.add(pid)
                        queue.append((pid, depth + 1))
        return result

    def list_commits(self, limit: int = 100, offset: int = 0) -> list[TesCommit]:
        cur = self._conn.execute(
            "SELECT raw_json FROM commits ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [deserialize_commit(row[0]) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SqliteCommitStore":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
