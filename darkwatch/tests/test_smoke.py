"""Smoke tests — fast, no Docker, no network, no DB.
Confirms the modules import and load_config does the right thing.
Run: pytest darkwatch/tests/
"""

import json
import os
import sys
import tempfile

import pytest

# Make the source dir importable without needing an installable package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_imports_clean():
    import darkwatch  # noqa: F401
    import threat_intel  # noqa: F401


def test_load_config_substitutes_env(monkeypatch):
    """${VAR} placeholders in config.json must resolve from os.environ."""
    from darkwatch import load_config

    monkeypatch.setenv("FOO", "bar")
    monkeypatch.setenv("API_ID", "12345")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as fp:
        json.dump(
            {
                "telegram": {
                    "api_id": "${API_ID}",
                    "api_hash": "${MISSING_VAR}",
                    "session_path": "literal/path",
                },
                "alerts": {"slack_webhook_url": "${FOO}"},
            },
            fp,
        )
        path = fp.name

    try:
        cfg = load_config(path)
        assert cfg["telegram"]["api_id"] == "12345"
        # Missing env var resolves to empty string, not literal placeholder.
        assert cfg["telegram"]["api_hash"] == ""
        # Non-placeholder strings pass through unchanged.
        assert cfg["telegram"]["session_path"] == "literal/path"
        assert cfg["alerts"]["slack_webhook_url"] == "bar"
    finally:
        os.unlink(path)


def test_load_config_passes_through_non_placeholders():
    """A literal string that contains $ but isn't ${VAR} stays literal."""
    from darkwatch import load_config

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as fp:
        json.dump({"crawler": {"max_threads": 5}}, fp)
        path = fp.name

    try:
        cfg = load_config(path)
        assert cfg["crawler"]["max_threads"] == 5
    finally:
        os.unlink(path)


def test_yara_private_dir_compiles_each_yar_file(tmp_path):
    """Operator-private *.yar files mounted in via /app/yara-private are
    compiled into the scanner and contribute to scan() results."""
    yara = pytest.importorskip("yara")
    from darkwatch import YaraScanner

    # Curated rules path needs to exist for keywords/categories but content
    # is irrelevant for this test — point them at empty files.
    curated = tmp_path / "curated.yar"
    curated.write_text('rule curated_noop { strings: $a = "_____never_match_____" condition: $a }')

    priv = tmp_path / "priv"
    priv.mkdir()
    (priv / "ops_alpha.yar").write_text(
        'rule ops_alpha { meta: score = 42 strings: $s = "needle-alpha" condition: $s }'
    )
    (priv / "ops_beta.yar").write_text(
        'rule ops_beta { meta: score = 7 strings: $s = "needle-beta" condition: $s }'
    )

    scanner = YaraScanner(
        keywords_file=str(curated),
        categories_file=str(curated),
        user_file=None,
        private_dir=str(priv),
    )

    assert scanner.private_rules is not None, "private rules should compile"
    hits = scanner.scan("body contains needle-alpha and also needle-beta in passing")
    rule_names = {h["rule"] for h in hits["keywords"]}
    assert "ops_alpha" in rule_names
    assert "ops_beta" in rule_names


def test_yara_private_dir_missing_is_noop(tmp_path):
    """A missing or empty private_dir must not error — it's the default
    state on a fresh bootstrap before the operator drops files in."""
    pytest.importorskip("yara")
    from darkwatch import YaraScanner

    curated = tmp_path / "c.yar"
    curated.write_text('rule c { strings: $a = "_____never_____" condition: $a }')

    # Missing dir.
    s1 = YaraScanner(str(curated), str(curated), user_file=None,
                     private_dir=str(tmp_path / "does-not-exist"))
    assert s1.private_rules is None

    # Empty dir.
    empty = tmp_path / "empty"
    empty.mkdir()
    s2 = YaraScanner(str(curated), str(curated), user_file=None,
                     private_dir=str(empty))
    assert s2.private_rules is None


def test_save_custom_rule_compiles_and_lists(tmp_path):
    pytest.importorskip("yara")
    from darkwatch import YaraScanner

    curated = tmp_path / "c.yar"
    curated.write_text('rule c { strings: $a = "_____never_____" condition: $a }')
    priv = tmp_path / "priv"
    priv.mkdir()

    scanner = YaraScanner(str(curated), str(curated), user_file=None, private_dir=str(priv))
    fname = scanner.save_custom_rule(
        'rule corp_leak { meta: score = 90 strings: $x = "acme" nocase condition: $x }',
        "corp_leak",
    )
    assert fname == "corp_leak.yar"
    rules = scanner.list_rules()
    names = {r["name"] for r in rules}
    assert "corp_leak" in names
    custom = [r for r in rules if r.get("custom")]
    assert len(custom) == 1
    assert custom[0]["custom_file"] == "corp_leak.yar"
    removed = scanner.delete_custom_files(["corp_leak.yar"])
    assert removed == 1
    assert scanner.list_rules() == []


def test_save_custom_rule_rejects_duplicate_filename(tmp_path):
    pytest.importorskip("yara")
    from darkwatch import YaraScanner

    curated = tmp_path / "c.yar"
    curated.write_text('rule c { strings: $a = "x" condition: $a }')
    priv = tmp_path / "priv"
    priv.mkdir()
    scanner = YaraScanner(str(curated), str(curated), user_file=None, private_dir=str(priv))
    body = 'rule one { strings: $a = "a" condition: $a }'
    scanner.save_custom_rule(body, "dup")
    with pytest.raises(ValueError, match="already exists"):
        scanner.save_custom_rule(body, "dup")
    with pytest.raises(ValueError, match="already exists"):
        scanner.save_custom_rule(body, "dup.yar")


def test_save_custom_rule_rejects_duplicate_rule_name(tmp_path):
    pytest.importorskip("yara")
    from darkwatch import YaraScanner

    curated = tmp_path / "c.yar"
    curated.write_text('rule taken { strings: $a = "x" condition: $a }')
    priv = tmp_path / "priv"
    priv.mkdir()
    scanner = YaraScanner(str(curated), str(curated), user_file=None, private_dir=str(priv))
    with pytest.raises(ValueError, match="already in use"):
        scanner.save_custom_rule(
            'rule taken { strings: $a = "y" condition: $a }',
            "other",
        )


def test_save_custom_rule_accepts_dotted_filename(tmp_path):
    pytest.importorskip("yara")
    from darkwatch import YaraScanner

    curated = tmp_path / "c.yar"
    curated.write_text('rule c { strings: $a = "x" condition: $a }')
    priv = tmp_path / "priv"
    priv.mkdir()
    scanner = YaraScanner(str(curated), str(curated), user_file=None, private_dir=str(priv))
    fname = scanner.save_custom_rule(
        'rule dotted { strings: $a = "z" condition: $a }',
        "dotted.yar",
    )
    assert fname == "dotted.yar"


def test_save_custom_rule_rejects_invalid_syntax(tmp_path):
    pytest.importorskip("yara")
    from darkwatch import YaraScanner

    curated = tmp_path / "c.yar"
    curated.write_text('rule c { strings: $a = "x" condition: $a }')
    priv = tmp_path / "priv"
    priv.mkdir()
    scanner = YaraScanner(str(curated), str(curated), user_file=None, private_dir=str(priv))
    with pytest.raises(ValueError, match="YARA compile error"):
        scanner.save_custom_rule(
            "rule broken { strings: $a = \"unclosed condition: $a }",
            "broken",
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
