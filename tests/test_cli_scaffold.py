"""CLI tests for `vibe-iterator new-scanner`."""

from pathlib import Path

from click.testing import CliRunner

from vibe_iterator.cli import cli


def _make_repo_tree(base: Path) -> None:
    """Minimal project directory structure the command expects."""
    (base / "vibe_iterator" / "scanners").mkdir(parents=True)
    (base / "tests" / "test_scanners").mkdir(parents=True)
    (base / "docs").mkdir()
    (base / "docs" / "SCANNERS.md").write_text(
        "## Scanner Registry\n\n"
        "| Scanner | Category | Stages | `requires_stack` | `requires_second_account` | Phase |\n"
        "|---------|----------|--------|-----------------|--------------------------|-------|\n"
        "| `existing_scanner` | Injection | pre-deploy | `['any']` | `False` | 2 |\n"
        "\n"
        "Some footnote text.\n",
        encoding="utf-8",
    )


def test_new_scanner_generates_files(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check", "--category", "injection"])
    assert result.exit_code == 0, result.output

    scanner = tmp_path / "vibe_iterator" / "scanners" / "stripe_check.py"
    test_file = tmp_path / "tests" / "test_scanners" / "test_stripe_check.py"
    assert scanner.exists()
    assert test_file.exists()

    scanner_content = scanner.read_text()
    assert 'name = "stripe_check"' in scanner_content
    assert 'category = "injection"' in scanner_content
    assert "['pre-deploy', 'post-deploy']" in scanner_content

    test_content = test_file.read_text()
    assert "from vibe_iterator.scanners.stripe_check import Scanner" in test_content


def test_new_scanner_updates_registry(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check", "--category", "injection"])
    assert result.exit_code == 0, result.output

    content = (tmp_path / "docs" / "SCANNERS.md").read_text()
    assert "`stripe_check`" in content
    assert "community" in content
    existing_pos = content.index("`existing_scanner`")
    stripe_pos = content.index("`stripe_check`")
    assert stripe_pos > existing_pos


def test_new_scanner_no_category(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "my_scanner"])
    assert result.exit_code == 0
    scanner = tmp_path / "vibe_iterator" / "scanners" / "my_scanner.py"
    assert scanner.exists()
    content = scanner.read_text()
    assert "['pre-deploy']" in content


def test_new_scanner_invalid_name(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["new-scanner", "BadName"])
    assert result.exit_code != 0
    assert "snake_case" in result.output or "Invalid" in result.output


def test_new_scanner_conflict(tmp_path, monkeypatch):
    _make_repo_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vibe_iterator" / "scanners" / "stripe_check.py").write_text("# existing\n")

    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check", "--category", "injection"])
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_new_scanner_wrong_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["new-scanner", "stripe_check"])
    assert result.exit_code != 0
    assert "project root" in result.output
