"""High-level Tesera API: single-class interface for cryptographic media provenance."""

import glob
import os
from typing import Callable

from tes_core.commit import (
    TesCommit,
    create_commit,
    deserialize_commit,
    serialize_commit,
)
from tes_core.hash import hash_file
from tes_core.sign import fingerprint, generate_key_pair, get_public_key_pem
from tes_core.store import SqliteCommitStore
from tes_core.chain import ChainVerificationResult, get_provenance


class Tesera:
    """High-level interface for creating and verifying media provenance commits.

    Use a single Tesera instance (or context manager) to commit files, verify
    provenance, and query history. Keys and SQLite store live under the given path.
    """

    def __init__(self, path: str = ".tesera", key_name: str = "default") -> None:
        """Initialize Tesera at the given path with the named signing key.

        path: Directory for data (SQLite DB and keys). Created if missing. Default .tesera.
        key_name: Name of the key pair (files keys/{key_name}.pem and .pub.pem). Default default.
        """
        self._path = os.path.abspath(path)
        keys_dir = os.path.join(self._path, "keys")
        os.makedirs(keys_dir, exist_ok=True)

        db_path = os.path.join(self._path, "tesera.db")
        self._store = SqliteCommitStore(db_path)

        priv_path = os.path.join(keys_dir, f"{key_name}.pem")
        pub_path = os.path.join(keys_dir, f"{key_name}.pub.pem")
        priv_exists = os.path.isfile(priv_path)
        pub_exists = os.path.isfile(pub_path)

        if priv_exists and pub_exists:
            with open(priv_path, "r", encoding="utf-8") as f:
                self._private_key_pem = f.read()
            with open(pub_path, "r", encoding="utf-8") as f:
                self._public_key_pem = f.read()
        elif not priv_exists and not pub_exists:
            public_pem, private_pem = generate_key_pair()
            with open(priv_path, "w", encoding="utf-8") as f:
                f.write(private_pem)
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write(public_pem)
            os.chmod(priv_path, 0o600)
            self._private_key_pem = private_pem
            self._public_key_pem = public_pem
        else:
            raise RuntimeError(
                f"Key files inconsistent for {key_name!r}: "
                f"private exists={priv_exists}, public exists={pub_exists}. "
                "Both or neither must exist."
            )

        self._key_resolver_cache: dict[str, str] | None = None
        self._key_resolver_fn: Callable[[str], str | None] | None = None

    def _key_resolver(self, key_id: str) -> str | None:
        """Resolve key fingerprint to public PEM. Caches key dir scan on first use."""
        if self._key_resolver_fn is not None:
            return self._key_resolver_fn(key_id)
        keys_dir = os.path.join(self._path, "keys")
        pattern = os.path.join(keys_dir, "*.pub.pem")
        cache: dict[str, str] = {}
        for filepath in glob.glob(pattern):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    pem = f.read()
                fid = fingerprint(pem)
                cache[fid] = pem
            except Exception:
                continue
        self._key_resolver_cache = cache

        def resolve(kid: str) -> str | None:
            return cache.get(kid)

        self._key_resolver_fn = resolve
        return resolve(key_id)

    def commit(
        self,
        file_path: str,
        operation: str = "create",
        parents: list[str] | None = None,
        metadata: dict | None = None,
    ) -> TesCommit:
        """Create a provenance commit for the media file and save it to the store."""
        parent_ids = parents if parents is not None else []
        commit = create_commit(
            file_path,
            self._private_key_pem,
            operation,
            parent_ids=parent_ids,
            metadata=metadata,
        )
        self._store.save(commit)
        return commit

    def verify(self, file_path: str) -> list[ChainVerificationResult]:
        """Verify provenance for the file; returns verification results per matching commit."""
        media_hash = hash_file(file_path)
        return get_provenance(media_hash, self._store, self._key_resolver)

    def history(self, file_path: str) -> list[TesCommit]:
        """Return all commits for this file (by hash) plus ancestors, sorted by timestamp ascending."""
        media_hash = hash_file(file_path)
        commits = self._store.get_by_media_hash(media_hash)
        if not commits:
            return []
        seen: set[str] = set()
        all_commits: list[TesCommit] = []
        for c in commits:
            if c.id not in seen:
                seen.add(c.id)
                all_commits.append(c)
            for anc in self._store.get_ancestors(c.id):
                if anc.id not in seen:
                    seen.add(anc.id)
                    all_commits.append(anc)
        all_commits.sort(key=lambda c: c.timestamp)
        return all_commits

    def get(self, commit_id: str) -> TesCommit | None:
        """Retrieve a single commit by ID, or None if not found."""
        return self._store.get_by_commit_id(commit_id)

    def export(self, commit_id: str) -> str:
        """Serialize the commit to JSON. Raises ValueError if not found."""
        commit = self.get(commit_id)
        if commit is None:
            raise ValueError(f"Commit not found: {commit_id}")
        return serialize_commit(commit)

    def import_commit(self, json_str: str) -> TesCommit:
        """Deserialize a commit from JSON and save it to the store."""
        commit = deserialize_commit(json_str)
        self._store.save(commit)
        return commit

    def close(self) -> None:
        """Close the SQLite store."""
        self._store.close()

    def __enter__(self) -> "Tesera":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    @staticmethod
    def hash(file_path: str) -> str:
        """Compute the media hash of a file without initializing a Tesera instance."""
        return hash_file(file_path)

    @staticmethod
    def generate_keys() -> tuple[str, str]:
        """Generate a new key pair (public_pem, private_pem) without a Tesera instance."""
        return generate_key_pair()
