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
from tes_core.hash import hash_buffer, hash_file
from tes_core.sign import fingerprint, generate_key_pair, get_public_key_pem
from tes_core.store import SqliteCommitStore
from tes_core.chain import ChainVerificationResult, get_provenance


class Tesera:
    """High-level interface for creating and verifying media provenance commits.

    Use a single Tesera instance (or context manager) to commit files, verify
    provenance, and query history. Keys and SQLite store live under the given path.
    """

    def __init__(
        self,
        path: str = ".tesera",
        key_name: str = "default",
        media_type: str | None = None,
        private_key: str | None = None,
    ) -> None:
        """Initialize Tesera at the given path with the named signing key.

        path: Directory for data (SQLite DB and keys). Created if missing. Default .tesera.
        key_name: Name of the key pair (files keys/{key_name}.pem and .pub.pem). Default default.
        media_type: Optional default MIME type for commits (overridable per commit).
        private_key: Optional PEM-encoded Ed25519 private key. If provided, used directly;
            not saved to disk; .tesera directory is not created until first store use.
        """
        self._path = os.path.abspath(path)
        self._default_media_type = media_type
        self._key_resolver_cache = None
        self._key_resolver_fn = None

        # 1. Explicit private_key parameter
        if private_key is not None:
            try:
                self._public_key_pem = get_public_key_pem(private_key.strip())
            except (ValueError, Exception) as e:
                raise ValueError(
                    "Invalid private key: expected PEM-encoded Ed25519 private key"
                ) from e
            self._private_key_pem = private_key.strip()
            self._store = None
            return

        # 2. Environment variable TESERA_PRIVATE_KEY
        if "TESERA_PRIVATE_KEY" in os.environ:
            raw = os.environ["TESERA_PRIVATE_KEY"]
            if raw.strip():
                pem = raw.strip().replace("\\n", "\n")
                try:
                    self._public_key_pem = get_public_key_pem(pem)
                except (ValueError, Exception) as e:
                    raise ValueError(
                        "Invalid private key in TESERA_PRIVATE_KEY: "
                        "expected PEM-encoded Ed25519 private key"
                    ) from e
                self._private_key_pem = pem
                self._store = None
                return

        # 3 & 4. Filesystem or auto-generate
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

    def _ensure_store(self) -> None:
        """Create the SQLite store and path if using an explicit or env key (lazy init)."""
        if self._store is None:
            os.makedirs(self._path, exist_ok=True)
            db_path = os.path.join(self._path, "tesera.db")
            self._store = SqliteCommitStore(db_path)

    def _key_resolver(self, key_id: str) -> str | None:
        """Resolve key fingerprint to public PEM. Caches key dir scan on first use."""
        if key_id == fingerprint(self._public_key_pem):
            return self._public_key_pem
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
        media: str | bytes,
        operation: str = "create",
        parent: str | None = None,
        parents: list[str] | None = None,
        metadata: dict | None = None,
        media_type: str | None = None,
    ) -> TesCommit:
        """Create a provenance commit for the media (file path or raw bytes) and save it to the store."""
        self._ensure_store()
        if parent is not None and parents is not None:
            raise ValueError("Cannot specify both 'parent' and 'parents'")
        if parent is not None:
            parent_ids = [parent]
        elif parents is not None:
            parent_ids = parents
        else:
            parent_ids = []
        resolved_media_type = (
            media_type if media_type is not None else self._default_media_type
        )
        commit = create_commit(
            media,
            self._private_key_pem,
            operation,
            parent_ids=parent_ids,
            metadata=metadata,
            media_type=resolved_media_type,
        )
        self._store.save(commit)
        return commit

    def lookup(self, media: str | bytes) -> TesCommit | None:
        """
        Look up the most recent commit for a media file.
        Returns the commit if found, None if the media has no provenance.
        Does NOT verify signatures — just checks if a commit exists.
        """
        self._ensure_store()
        media_hash = (
            hash_buffer(media) if isinstance(media, bytes) else hash_file(media)
        )
        commits = self._store.get_by_media_hash(media_hash)
        if not commits:
            return None
        commits_sorted = sorted(commits, key=lambda c: c.timestamp)
        return commits_sorted[-1]

    def commit_edit(
        self,
        original: str | bytes,
        edited: str | bytes,
        metadata: dict | None = None,
        media_type: str | None = None,
    ) -> TesCommit:
        """
        Commit an edit. Automatically finds the parent commit for the original
        file and links the edited version to it.

        If the original has an existing Tesera commit, creates an edit commit
        with that commit as parent.

        If the original has no existing commit (unverified upload), creates
        an import commit for the original first, then an edit commit on top.

        Returns the edit commit (the commit for the edited file).
        """
        found = self.lookup(original)
        if found is not None:
            return self.commit(
                edited,
                operation="edit",
                parent=found.id,
                metadata=metadata,
                media_type=media_type,
            )
        import_commit = self.commit(original, operation="import")
        return self.commit(
            edited,
            operation="edit",
            parent=import_commit.id,
            metadata=metadata,
            media_type=media_type,
        )

    def commit_edit_from_upload(
        self,
        original: str | bytes,
        edited: str | bytes,
        metadata: dict | None = None,
        media_type: str | None = None,
    ) -> tuple[TesCommit, TesCommit]:
        """
        Handle an unverified upload: creates an import commit for the original,
        then an edit commit for the edited version. Returns (import_commit, edit_commit).

        Use this when you know the original has no existing provenance.
        Use commit_edit() instead if you want automatic detection.
        """
        import_commit = self.commit(original, operation="import")
        edit_commit = self.commit(
            edited,
            operation="edit",
            parent=import_commit.id,
            metadata=metadata,
            media_type=media_type,
        )
        return (import_commit, edit_commit)

    def verify(self, media: str | bytes) -> list[ChainVerificationResult]:
        """Verify provenance for the media (file path or raw bytes); returns verification results per matching commit."""
        self._ensure_store()
        media_hash = (
            hash_buffer(media) if isinstance(media, bytes) else hash_file(media)
        )
        return get_provenance(media_hash, self._store, self._key_resolver)

    def history(self, media: str | bytes) -> list[TesCommit]:
        """Return all commits for this media (by hash) plus ancestors, sorted by timestamp ascending."""
        self._ensure_store()
        media_hash = (
            hash_buffer(media) if isinstance(media, bytes) else hash_file(media)
        )
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
        self._ensure_store()
        return self._store.get_by_commit_id(commit_id)

    def export(self, commit_id: str) -> str:
        """Serialize the commit to JSON. Raises ValueError if not found."""
        commit = self.get(commit_id)
        if commit is None:
            raise ValueError(f"Commit not found: {commit_id}")
        return serialize_commit(commit)

    def import_commit(self, json_str: str) -> TesCommit:
        """Deserialize a commit from JSON and save it to the store."""
        self._ensure_store()
        commit = deserialize_commit(json_str)
        self._store.save(commit)
        return commit

    @property
    def public_key(self) -> str:
        """Returns the PEM-encoded public key."""
        return self._public_key_pem

    @property
    def key_fingerprint(self) -> str:
        """Returns the 32-character hex fingerprint of the active signing key."""
        return fingerprint(self._public_key_pem)

    def close(self) -> None:
        """Close the SQLite store."""
        if self._store is not None:
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
