"""Unit tests for vibe_iterator/scaffold.py."""

from vibe_iterator.scaffold import (
    VALID_CATEGORIES,
    append_registry_row,
    build_registry_row,
    render_scanner,
    render_test,
)


def test_render_scanner_with_category():
    code = render_scanner("stripe_check", "injection")
    assert 'name = "stripe_check"' in code
    assert 'category = "injection"' in code
    assert "['pre-deploy', 'post-deploy']" in code
    assert "class Scanner(BaseScanner):" in code
    assert "def run(self, session, listeners, config)" in code
    assert "def _build_finding(" in code
    assert "def _build_llm_prompt(" in code


def test_render_scanner_without_category():
    code = render_scanner("my_scanner", None)
    assert 'name = "my_scanner"' in code
    assert "['pre-deploy']" in code


def test_render_scanner_all_categories():
    for cat in VALID_CATEGORIES:
        code = render_scanner(f"{cat}_scanner", cat)
        assert f'category = "{cat}"' in code
        stages = VALID_CATEGORIES[cat]
        assert repr(stages) in code


def test_render_test():
    code = render_test("stripe_check")
    assert "from vibe_iterator.scanners.stripe_check import Scanner" in code
    assert "@pytest.fixture(scope=" in code
    assert "def _run(vuln_app" in code
    assert "def test_vulnerability_detected(" in code
    assert "def test_clean_endpoint_no_finding(" in code


def test_build_registry_row():
    row = build_registry_row("stripe_check", "injection", ["pre-deploy", "post-deploy"], ["any"], False)
    assert "| `stripe_check`" in row
    assert "Injection" in row
    assert "pre-deploy, post-deploy" in row
    assert "community" in row


def test_append_registry_row(tmp_path):
    md = tmp_path / "SCANNERS.md"
    md.write_text(
        "## Scanner Registry\n\n"
        "| Scanner | Category | Stages | `requires_stack` | `requires_second_account` | Phase |\n"
        "|---------|----------|--------|-----------------|--------------------------|-------|\n"
        "| `existing` | Injection | pre-deploy | `['any']` | `False` | 2 |\n"
        "\n"
        "Some footnote text\n"
    )
    row = "| `stripe_check` | Injection | pre-deploy, post-deploy | `['any']` | `False` | community |"
    result = append_registry_row(str(md), row)
    assert result is True
    content = md.read_text()
    lines = content.splitlines()
    existing_idx = next(i for i, line in enumerate(lines) if "`existing`" in line)
    stripe_idx = next(i for i, line in enumerate(lines) if "`stripe_check`" in line)
    assert stripe_idx == existing_idx + 1  # appended immediately after last table row


def test_append_registry_row_missing_file(tmp_path):
    result = append_registry_row(str(tmp_path / "nonexistent.md"), "| row |")
    assert result is False


def test_append_registry_row_no_table(tmp_path):
    md = tmp_path / "SCANNERS.md"
    md.write_text("# No table here\n")
    result = append_registry_row(str(md), "| row |")
    assert result is False
