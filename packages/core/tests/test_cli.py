"""Tests for the Tesera CLI."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tes_core.cli import app

# Repo root: packages/core/tests -> packages/core -> packages -> root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FIXTURE_PATH = _REPO_ROOT / "fixtures" / "test_input.bin"

runner = CliRunner()

# 32 hex chars for fingerprint
FINGERPRINT_RE = __import__("re").compile(r"[0-9a-f]{32}")


def test_init(tmp_path: Path) -> None:
    """Run tesera init in a temp directory. Assert exit code 0, .tesera/ created, output has fingerprint."""
    tesera_dir = str(tmp_path / ".tesera")
    result = runner.invoke(app, ["init", "--path", tesera_dir])
    assert result.exit_code == 0
    assert (tmp_path / ".tesera").is_dir()
    assert (tmp_path / ".tesera" / "keys" / "default.pem").exists()
    assert FINGERPRINT_RE.search(result.output) is not None


def test_init_already_exists(tmp_path: Path) -> None:
    """Run tesera init twice. Second run exits 0 and mentions already initialized."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    result = runner.invoke(app, ["init", "--path", tesera_dir])
    assert result.exit_code == 0
    assert "already" in result.output.lower() or "Already" in result.output
    assert FINGERPRINT_RE.search(result.output) is not None


def test_commit_create(tmp_path: Path) -> None:
    """Init, then tesera commit <fixture-file> --op create. Assert exit 0, output contains Committed and commit ID."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    test_file = tmp_path / "test.bin"
    shutil.copy(FIXTURE_PATH, test_file)
    result = runner.invoke(app, ["commit", str(test_file), "--op", "create", "--path", tesera_dir])
    assert result.exit_code == 0
    assert "Committed" in result.output
    # Commit ID is 64 hex; we show truncated 12 in human output
    assert "  media:" in result.output or "  time:" in result.output


def test_commit_json(tmp_path: Path) -> None:
    """Init, then tesera commit <fixture-file> --op create --json. Assert exit 0, valid JSON with id, media_hash, operation."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    test_file = tmp_path / "test.bin"
    shutil.copy(FIXTURE_PATH, test_file)
    result = runner.invoke(
        app, ["commit", str(test_file), "--op", "create", "--json", "--path", tesera_dir]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "id" in data
    assert "media_hash" in data
    assert "operation" in data
    assert data["operation"] == "create"


def test_verify_found(tmp_path: Path) -> None:
    """Init, commit a file, then tesera verify <same-file>. Assert exit 0, output contains Verified."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    test_file = tmp_path / "test.bin"
    shutil.copy(FIXTURE_PATH, test_file)
    runner.invoke(app, ["commit", str(test_file), "--op", "create", "--path", tesera_dir])
    result = runner.invoke(app, ["verify", str(test_file), "--path", tesera_dir])
    assert result.exit_code == 0
    assert "Verified" in result.output


def test_verify_not_found(tmp_path: Path) -> None:
    """Init, then tesera verify <uncommitted-file>. Assert exit 0, output contains No provenance found."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    # Use fixture path which we never committed in this tmp_path repo
    test_file = tmp_path / "uncommitted.bin"
    test_file.write_bytes(b"never committed")
    result = runner.invoke(app, ["verify", str(test_file), "--path", tesera_dir])
    assert result.exit_code == 0
    assert "No provenance found" in result.output


def test_history(tmp_path: Path) -> None:
    """Init, commit a file. Run tesera history <file>. Assert exit 0, output contains the commit ID."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    test_file = tmp_path / "test.bin"
    shutil.copy(FIXTURE_PATH, test_file)
    commit_result = runner.invoke(
        app, ["commit", str(test_file), "--op", "create", "--json", "--path", tesera_dir]
    )
    assert commit_result.exit_code == 0
    commit_data = json.loads(commit_result.output)
    commit_id = commit_data["id"]
    result = runner.invoke(app, ["history", str(test_file), "--path", tesera_dir])
    assert result.exit_code == 0
    # Truncated id is 12 chars + ...
    assert commit_id[:12] in result.output or commit_id in result.output


def test_log(tmp_path: Path) -> None:
    """Init, commit two files. Run tesera log. Assert exit 0, output shows both commits."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"file one")
    f2.write_bytes(b"file two")
    runner.invoke(app, ["commit", str(f1), "--op", "create", "--path", tesera_dir])
    runner.invoke(app, ["commit", str(f2), "--op", "create", "--path", tesera_dir])
    result = runner.invoke(app, ["log", "--path", tesera_dir])
    assert result.exit_code == 0
    # Both commits should appear (create, create)
    assert result.output.count("create") >= 2


def test_show(tmp_path: Path) -> None:
    """Init, commit a file, capture commit ID. Run tesera show <id>. Assert exit 0, output contains full commit details."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    test_file = tmp_path / "test.bin"
    shutil.copy(FIXTURE_PATH, test_file)
    commit_result = runner.invoke(
        app, ["commit", str(test_file), "--op", "create", "--json", "--path", tesera_dir]
    )
    assert commit_result.exit_code == 0
    commit_data = json.loads(commit_result.output)
    commit_id = commit_data["id"]
    result = runner.invoke(app, ["show", commit_id, "--path", tesera_dir])
    assert result.exit_code == 0
    assert "media_hash" in result.output
    assert "operation" in result.output
    assert commit_id in result.output


def test_export_json(tmp_path: Path) -> None:
    """Init, commit, capture ID. Run tesera export <id>. Assert output is valid JSON."""
    tesera_dir = str(tmp_path / ".tesera")
    runner.invoke(app, ["init", "--path", tesera_dir])
    test_file = tmp_path / "test.bin"
    shutil.copy(FIXTURE_PATH, test_file)
    commit_result = runner.invoke(
        app, ["commit", str(test_file), "--op", "create", "--json", "--path", tesera_dir]
    )
    assert commit_result.exit_code == 0
    commit_data = json.loads(commit_result.output)
    commit_id = commit_data["id"]
    result = runner.invoke(app, ["export", commit_id, "--path", tesera_dir])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["id"] == commit_id
    assert "signature" in data


def test_not_initialized(tmp_path: Path) -> None:
    """Run tesera verify <file> without running init first. Assert exit 1, output mentions init."""
    test_file = tmp_path / "any.bin"
    test_file.write_bytes(b"x")
    tesera_dir = str(tmp_path / ".tesera")
    # Don't run init; .tesera doesn't exist
    result = runner.invoke(app, ["verify", str(test_file), "--path", tesera_dir])
    assert result.exit_code == 1
    assert "init" in result.output.lower()
