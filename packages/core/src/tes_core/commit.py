"""Commit creation, canonical serialization, verification, and serialization (Spec Sections 2, 4, 5)."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from tes_core.hash import (
    detect_media_type,
    detect_media_type_from_buffer,
    hash_buffer,
    hash_file,
)
from tes_core.sign import fingerprint, get_public_key_pem, sign, verify

VALID_OPERATIONS = ("create", "edit", "derive", "import")
PARENT_ID_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class TesCommit:
    """Provenance commit: one attested event for a media file (Spec Section 2)."""

    id: str  # 64 hex; derived, not assigned
    version: int  # always 1
    media_hash: str  # 64 hex
    media_type: str  # MIME type
    parent_ids: list[str]  # sorted ascending; empty for creates
    operation: str  # create | edit | derive | import
    timestamp: str  # ISO 8601 UTC, no fractional seconds
    signer: dict  # key_id (required), name, uri optional
    metadata: dict | None  # optional; omitted from canonical/serialization if None
    signature: str  # 128 hex


def _drop_none(obj: dict) -> dict:
    """Return a copy with keys whose value is None removed, recursively."""
    out: dict = {}
    for k, v in obj.items():
        if v is None:
            continue
        if isinstance(v, dict):
            out[k] = _drop_none(v)
        elif isinstance(v, list):
            out[k] = [
                _drop_none(x) if isinstance(x, dict) else x
                for x in v
            ]
        else:
            out[k] = v
    return out


def canonicalize(obj: dict) -> str:
    """Canonical JSON string per RFC 8785 / JCS (Spec Section 5).

    Keys sorted alphabetically at every level, no whitespace, no nulls,
    integers as integers. Keys with None values are omitted recursively.
    """
    cleaned = _drop_none(obj)
    return json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def create_commit(
    media: str | bytes,
    private_key_pem: str,
    operation: str,
    parent_ids: list[str] | None = None,
    metadata: dict | None = None,
    signer_name: str | None = None,
    signer_uri: str | None = None,
    media_type: str | None = None,
) -> TesCommit:
    """Create a signed TesCommit for the media file or raw bytes.

    Hashes the media, builds the commit body, signs it, then derives the commit ID
    (Spec Sections 3.4 and 4). Returns a fully populated TesCommit.
    Validates inputs per Specification Section 7; raises ValueError on failure.
    """
    if type(media) not in (str, bytes):
        raise TypeError(
            "media must be a file path (str) or raw bytes (bytes)"
        )

    sorted_parent_ids = sorted(parent_ids) if parent_ids else []

    if operation not in VALID_OPERATIONS:
        raise ValueError(
            f"operation must be one of: create, edit, derive, import; got {operation!r}"
        )
    if operation == "create" and sorted_parent_ids:
        raise ValueError("operation is create but parent_ids is not empty")
    if operation == "edit":
        if len(sorted_parent_ids) != 1:
            raise ValueError(
                f"operation is edit but parent_ids must have exactly 1 element; got {len(sorted_parent_ids)}"
            )
    if operation == "derive":
        if len(sorted_parent_ids) < 1:
            raise ValueError(
                "operation is derive but parent_ids must have at least 1 element"
            )
    for i, pid in enumerate(sorted_parent_ids):
        if not PARENT_ID_RE.match(pid):
            raise ValueError(
                f"parent_ids[{i}] must be 64 lowercase hex characters; got {pid!r}"
            )

    if isinstance(media, bytes):
        media_hash = hash_buffer(media)
        resolved_media_type = (
            media_type
            if media_type is not None
            else detect_media_type_from_buffer(media)
        )
    else:
        media_hash = hash_file(media)
        resolved_media_type = (
            media_type if media_type is not None else detect_media_type(media)
        )
    public_key_pem = get_public_key_pem(private_key_pem)
    key_id = fingerprint(public_key_pem)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    signer: dict = {"key_id": key_id}
    if signer_name is not None:
        signer["name"] = signer_name
    if signer_uri is not None:
        signer["uri"] = signer_uri

    body: dict = {
        "media_hash": media_hash,
        "media_type": resolved_media_type,
        "operation": operation,
        "parent_ids": sorted_parent_ids,
        "timestamp": timestamp,
        "version": 1,
        "signer": signer,
    }
    if metadata is not None:
        body["metadata"] = metadata

    # Step 1: sign body (no id, no signature)
    canonical_for_sign = canonicalize(body)
    signature_hex = sign(canonical_for_sign.encode("utf-8"), private_key_pem)
    body["signature"] = signature_hex

    # Step 2: commit ID = SHA-256(canonical(body with signature, still no id))
    canonical_for_id = canonicalize(body)
    commit_id = hash_buffer(canonical_for_id.encode("utf-8"))

    return TesCommit(
        id=commit_id,
        version=1,
        media_hash=media_hash,
        media_type=resolved_media_type,
        parent_ids=sorted_parent_ids,
        operation=operation,
        timestamp=timestamp,
        signer=signer,
        metadata=metadata,
        signature=signature_hex,
    )


def verify_commit(commit: TesCommit, public_key_pem: str) -> bool:
    """Verify signature and commit ID (Spec Section 3.5). Returns True iff both pass."""
    body_without_sig: dict = {
        "media_hash": commit.media_hash,
        "media_type": commit.media_type,
        "operation": commit.operation,
        "parent_ids": list(commit.parent_ids),
        "timestamp": commit.timestamp,
        "version": commit.version,
        "signer": dict(commit.signer),
    }
    if commit.metadata is not None:
        body_without_sig["metadata"] = commit.metadata

    canonical_for_verify = canonicalize(body_without_sig)
    if not verify(
        canonical_for_verify.encode("utf-8"),
        commit.signature,
        public_key_pem,
    ):
        return False

    body_with_sig = {**body_without_sig, "signature": commit.signature}
    canonical_for_id = canonicalize(body_with_sig)
    expected_id = hash_buffer(canonical_for_id.encode("utf-8"))
    if expected_id != commit.id:
        return False
    return True


def _commit_to_dict(commit: TesCommit) -> dict:
    """Convert TesCommit to a JSON-serializable dict; omit metadata if None."""
    d: dict = {
        "id": commit.id,
        "version": commit.version,
        "media_hash": commit.media_hash,
        "media_type": commit.media_type,
        "parent_ids": list(commit.parent_ids),
        "operation": commit.operation,
        "timestamp": commit.timestamp,
        "signer": dict(commit.signer),
        "signature": commit.signature,
    }
    if commit.metadata is not None:
        d["metadata"] = commit.metadata
    return d


def serialize_commit(commit: TesCommit) -> str:
    """Serialize commit to human-readable JSON; metadata omitted if None."""
    return json.dumps(_commit_to_dict(commit), indent=2)


def deserialize_commit(json_str: str) -> TesCommit:
    """Parse JSON string into a TesCommit; metadata is None if absent."""
    data = json.loads(json_str)
    return TesCommit(
        id=data["id"],
        version=int(data["version"]),
        media_hash=data["media_hash"],
        media_type=data["media_type"],
        parent_ids=list(data["parent_ids"]),
        operation=data["operation"],
        timestamp=data["timestamp"],
        signer=dict(data["signer"]),
        metadata=data.get("metadata"),
        signature=data["signature"],
    )
