"""Tesera CLI: command-line interface for cryptographic media provenance."""

import json
import os

import typer

from tes_core.api import Tesera
from tes_core.commit import serialize_commit
from tes_core.store import SqliteCommitStore

app = typer.Typer(
    name="tesera",
    help="Tesera — cryptographic media provenance",
)

# Default Tesera directory relative to cwd
DEFAULT_TESERA_DIR = ".tesera"
KEY_NAME = "default"


def _tesera_dir(path: str | None) -> str:
    """Resolve Tesera directory; default is .tesera in current working directory."""
    if path:
        return os.path.abspath(path)
    return os.path.abspath(os.path.join(os.getcwd(), DEFAULT_TESERA_DIR))


def _is_initialized(tesera_dir: str) -> bool:
    """Return True if .tesera exists and default key exists."""
    keys_pem = os.path.join(tesera_dir, "keys", f"{KEY_NAME}.pem")
    return os.path.isdir(tesera_dir) and os.path.isfile(keys_pem)


def _ensure_initialized(tesera_dir: str) -> None:
    """If not initialized, print message and exit with code 1."""
    if not _is_initialized(tesera_dir):
        typer.echo("Not initialized. Run 'tesera init' first.")
        raise typer.Exit(1)


def _truncate_id(commit_id: str, length: int = 12) -> str:
    """Truncate commit id (or hash) for display."""
    if len(commit_id) <= length:
        return commit_id
    return commit_id[:length] + "..."


@app.command()
def init(
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
) -> None:
    """Create .tesera/ and generate a default signing key."""
    tesera_dir = _tesera_dir(path)
    if _is_initialized(tesera_dir):
        with Tesera(path=tesera_dir) as t:
            fp = t.key_fingerprint
        typer.echo("Already initialized.")
        typer.echo(f"Key fingerprint: {fp}")
        return
    with Tesera(path=tesera_dir) as t:
        fp = t.key_fingerprint
    typer.echo(f"Key fingerprint: {fp}")


def _parse_metadata(metadata: list[str]) -> dict[str, str] | None:
    """Parse repeated key=value into a dict. Returns None if empty."""
    if not metadata:
        return None
    out: dict[str, str] = {}
    for item in metadata:
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out if out else None


@app.command()
def commit(
    file: str = typer.Argument(..., help="Path to the media file"),
    op: str = typer.Option(..., "--op", help="Operation: create, edit, derive, import"),
    parent: str | None = typer.Option(None, "--parent", help="Parent commit ID (for edit)"),
    parents: str | None = typer.Option(
        None,
        "--parents",
        help="Comma-separated parent commit IDs (for derive)",
    ),
    metadata: list[str] = typer.Option(
        [],
        "--metadata",
        help="Metadata key=value (repeatable)",
    ),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Create a provenance commit for a file."""
    _ensure_initialized(_tesera_dir(path))
    if not os.path.isfile(file):
        typer.echo(f"File not found: {file}")
        raise typer.Exit(1)
    if parent and parents:
        typer.echo("Cannot specify both --parent and --parents.")
        raise typer.Exit(1)
    parent_ids = None
    if parent:
        parent_ids = [parent]
    elif parents:
        parent_ids = [p.strip() for p in parents.split(",") if p.strip()]
    meta = _parse_metadata(metadata)
    tesera_dir = _tesera_dir(path)
    with Tesera(path=tesera_dir) as t:
        try:
            c = t.commit(
                file,
                operation=op,
                parent=parent,
                parents=parent_ids if parents else None,
                metadata=meta,
            )
        except ValueError as e:
            typer.echo(str(e))
            raise typer.Exit(1)
    if json_output:
        typer.echo(serialize_commit(c))
        return
    short_id = _truncate_id(c.id)
    short_hash = _truncate_id(c.media_hash)
    typer.echo(f"Committed: {short_id} ({c.operation})")
    typer.echo(f"  media:   {c.media_type}")
    typer.echo(f"  hash:    {short_hash}")
    typer.echo(f"  signer:  {c.signer.get('key_id', '')}")
    typer.echo(f"  time:    {c.timestamp}")


@app.command()
def verify(
    file: str = typer.Argument(..., help="Path to the media file"),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Verify provenance for a file."""
    _ensure_initialized(_tesera_dir(path))
    if not os.path.isfile(file):
        typer.echo(f"File not found: {file}")
        raise typer.Exit(1)
    tesera_dir = _tesera_dir(path)
    with Tesera(path=tesera_dir) as t:
        lookup_commit = t.lookup(file)
        if lookup_commit is None:
            if json_output:
                typer.echo(json.dumps({"found": False}))
                return
            typer.echo("✗ No provenance found for this file")
            return
        results = t.verify(file)
        # Find the result that corresponds to the lookup commit (head of chain)
        result = None
        for r in results:
            if lookup_commit.id in r.valid_commits or lookup_commit.id in r.invalid_commits:
                result = r
                break
        if result is None:
            result = results[0] if results else None
        verified = result is not None and result.complete
        if json_output:
            out = {
                "found": True,
                "verified": verified,
                "commit": json.loads(serialize_commit(lookup_commit)),
            }
            typer.echo(json.dumps(out, indent=2))
            return
        if verified:
            typer.echo("✓ Verified")
        else:
            typer.echo("✗ Verification failed or incomplete")
        typer.echo(f"  commit:  {_truncate_id(lookup_commit.id)}")
        typer.echo(f"  op:     {lookup_commit.operation}")
        typer.echo(f"  signer: {lookup_commit.signer.get('key_id', '')}")
        typer.echo(f"  time:   {lookup_commit.timestamp}")


@app.command()
def history(
    file: str = typer.Argument(..., help="Path to the media file"),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show the full provenance chain for a file."""
    _ensure_initialized(_tesera_dir(path))
    if not os.path.isfile(file):
        typer.echo(f"File not found: {file}")
        raise typer.Exit(1)
    tesera_dir = _tesera_dir(path)
    with Tesera(path=tesera_dir) as t:
        commits = t.history(file)
    if json_output:
        arr = [json.loads(serialize_commit(c)) for c in commits]
        typer.echo(json.dumps(arr, indent=2))
        return
    for c in commits:
        signer_short = _truncate_id(c.signer.get("key_id", ""))
        typer.echo(f"{_truncate_id(c.id)}  {c.operation}  {c.timestamp}  {signer_short}")


@app.command()
def log(
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
    limit: int = typer.Option(20, "--limit", help="Maximum number of commits to show"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """List recent commits."""
    _ensure_initialized(_tesera_dir(path))
    tesera_dir = _tesera_dir(path)
    db_path = os.path.join(tesera_dir, "tesera.db")
    store = SqliteCommitStore(db_path)
    try:
        commits = store.list_commits(limit=limit, offset=0)
    finally:
        store.close()
    if json_output:
        arr = [json.loads(serialize_commit(c)) for c in commits]
        typer.echo(json.dumps(arr, indent=2))
        return
    for c in commits:
        typer.echo(f"{_truncate_id(c.id)}  {c.operation}  {c.media_type}  {c.timestamp}")


@app.command()
def show(
    commit_id: str = typer.Argument(..., help="Commit ID"),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Display full details of a commit."""
    _ensure_initialized(_tesera_dir(path))
    tesera_dir = _tesera_dir(path)
    with Tesera(path=tesera_dir) as t:
        c = t.get(commit_id)
    if c is None:
        typer.echo(f"Commit not found: {commit_id}")
        raise typer.Exit(1)
    if json_output:
        typer.echo(serialize_commit(c))
        return
    typer.echo(f"id:         {c.id}")
    typer.echo(f"version:    {c.version}")
    typer.echo(f"media_hash: {c.media_hash}")
    typer.echo(f"media_type: {c.media_type}")
    typer.echo(f"operation:  {c.operation}")
    typer.echo(f"timestamp:  {c.timestamp}")
    typer.echo(f"signer:     {c.signer}")
    typer.echo(f"parent_ids: {c.parent_ids}")
    if c.metadata:
        typer.echo(f"metadata:   {c.metadata}")
    typer.echo(f"signature:  {c.signature}")


keys_app = typer.Typer(help="Key management")
app.add_typer(keys_app, name="keys")


@keys_app.command("list")
def keys_list(
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
) -> None:
    """Show the active key name and fingerprint."""
    _ensure_initialized(_tesera_dir(path))
    tesera_dir = _tesera_dir(path)
    with Tesera(path=tesera_dir) as t:
        typer.echo(f"key:        {KEY_NAME}")
        typer.echo(f"fingerprint: {t.key_fingerprint}")


@keys_app.command("fingerprint")
def keys_fingerprint(
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
) -> None:
    """Print the active key fingerprint (for scripting)."""
    _ensure_initialized(_tesera_dir(path))
    tesera_dir = _tesera_dir(path)
    with Tesera(path=tesera_dir) as t:
        typer.echo(t.key_fingerprint)


def _export_cmd(
    commit_id: str = typer.Argument(..., help="Commit ID"),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Tesera directory (default: .tesera in current directory)",
    ),
) -> None:
    """Export a commit as JSON to stdout."""
    _ensure_initialized(_tesera_dir(path))
    tesera_dir = _tesera_dir(path)
    try:
        with Tesera(path=tesera_dir) as t:
            out = t.export(commit_id)
        typer.echo(out)
    except ValueError as e:
        if "not found" in str(e).lower() or "Commit not found" in str(e):
            typer.echo(f"Commit not found: {commit_id}")
        else:
            typer.echo(str(e))
        raise typer.Exit(1)


app.command("export")(_export_cmd)