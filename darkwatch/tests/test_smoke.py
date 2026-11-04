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


def _write_json(path, data):
    path.write_text(json.dumps(data))
    return str(path)


def test_load_config_local_override_wins_and_keeps_other_keys(tmp_path, monkeypatch):
    """The local override file is merged last and recursively: the keys it
    names win, nested keys it doesn't name keep the config.json (or
    default) value, and its ${VAR} placeholders are substituted."""
    from darkwatch import load_config

    monkeypatch.setenv("LOCAL_WEBHOOK", "https://hooks.example/abc")
    base = _write_json(tmp_path / "config.json", {
        "crawler": {"max_threads": 5, "timeout": 30},
        "alerts": {"min_alert_score": 80, "allow_direct": False},
    })
    local = _write_json(tmp_path / "config.local.json", {
        "crawler": {"max_threads": 2},
        "alerts": {"allow_direct": True, "slack_webhook_url": "${LOCAL_WEBHOOK}"},
        "extra": {"k": [1, 2]},
    })
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", local)

    cfg = load_config(base)
    assert cfg["crawler"]["max_threads"] == 2         # override wins
    assert cfg["crawler"]["timeout"] == 30            # config.json kept
    assert cfg["crawler"]["max_depth"] == 2           # default kept
    assert cfg["alerts"]["allow_direct"] is True
    assert cfg["alerts"]["min_alert_score"] == 80
    assert cfg["alerts"]["slack_webhook_url"] == "https://hooks.example/abc"
    assert cfg["extra"] == {"k": [1, 2]}
    # An explicit path takes precedence over the environment.
    assert load_config(base, local_path="")["crawler"]["max_threads"] == 5


def test_load_config_local_override_is_optional(tmp_path, monkeypatch):
    from darkwatch import load_config

    base = _write_json(tmp_path / "config.json", {"crawler": {"max_threads": 5}})
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", str(tmp_path / "missing.json"))
    assert load_config(base)["crawler"]["max_threads"] == 5
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", "")
    assert load_config(base)["crawler"]["max_threads"] == 5


@pytest.mark.parametrize("body", ['{"crawler": {"max_threads": 2}', "[1, 2]", "",
                                  b'{"a": "\xff"}'])
def test_load_config_invalid_local_override_is_an_error(tmp_path, monkeypatch, body):
    """A broken override must stop startup, not silently run on the
    tracked config.json settings."""
    from darkwatch import load_config

    base = _write_json(tmp_path / "config.json", {"crawler": {"max_threads": 5}})
    local = tmp_path / "config.local.json"
    if isinstance(body, bytes):
        local.write_bytes(body)  # not valid UTF-8
    else:
        local.write_text(body)
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", str(local))
    with pytest.raises(ValueError, match="config.local.json"):
        load_config(base)


def test_load_config_unreadable_local_override_is_an_error(tmp_path, monkeypatch):
    from darkwatch import load_config

    # A directory exists but can't be opened as a file (works as root too).
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", str(tmp_path))
    with pytest.raises(ValueError, match="cannot read config file"):
        load_config(None)


def test_load_config_local_override_without_permission_is_an_error(tmp_path, monkeypatch):
    """A file darkwatch may not look up (os.path.exists says False on
    EACCES) must fail like an unreadable one, not count as missing."""
    import darkwatch

    local = str(tmp_path / "config.d" / "config.local.json")
    real_open = open

    def fake_open(path, *a, **kw):
        if path == local:
            raise PermissionError(13, "Permission denied", path)
        return real_open(path, *a, **kw)

    monkeypatch.setattr(darkwatch, "open", fake_open, raising=False)
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", local)
    with pytest.raises(ValueError, match="Permission denied"):
        darkwatch.load_config(None)


def test_cli_reports_an_invalid_config_without_a_traceback(tmp_path, monkeypatch):
    import darkwatch

    local = tmp_path / "config.local.json"
    local.write_text("{not json")
    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", str(local))
    monkeypatch.chdir(tmp_path)  # the default database path is relative
    monkeypatch.setattr(sys, "argv", ["darkwatch.py", "--config",
                                      str(tmp_path / "none.json"), "--stats"])
    with pytest.raises(SystemExit) as exc:
        darkwatch.main()
    assert "is not valid JSON" in str(exc.value.code)


def test_load_config_does_not_mutate_defaults_or_share_state(tmp_path, monkeypatch):
    """Each load starts from a fresh copy of DEFAULT_CONFIG: loading a file
    must not write into DEFAULT_CONFIG, and two loaded configs must not
    share nested dicts or lists."""
    import copy
    from darkwatch import DEFAULT_CONFIG, load_config

    monkeypatch.setenv("DARKWATCH_CONFIG_LOCAL", "")
    before = copy.deepcopy(DEFAULT_CONFIG)
    c1 = load_config(_write_json(tmp_path / "a.json", {"crawler": {"max_threads": 9}}))
    c2 = load_config(_write_json(tmp_path / "b.json", {"proxy": {"port": 1}}))
    assert DEFAULT_CONFIG == before
    assert c1["crawler"]["max_threads"] == 9
    assert c2["crawler"]["max_threads"] == before["crawler"]["max_threads"]
    assert c1["proxy"]["port"] == before["proxy"]["port"]
    assert c2["proxy"]["port"] == 1

    c1["crawler"]["max_depth"] = 99
    c1["crawler"]["user_agents"].append("c1-only")
    c1["security"]["allowed_content_types"].clear()
    assert c2["crawler"]["max_depth"] == before["crawler"]["max_depth"]
    assert c2["crawler"]["user_agents"] == before["crawler"]["user_agents"]
    assert c2["security"] == before["security"]
    assert DEFAULT_CONFIG == before


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
    # list_rules() also returns curated rules (here "c"); only the custom one
    # must be gone.
    remaining = scanner.list_rules()
    assert not [r for r in remaining if r.get("custom")]
    assert "corp_leak" not in {r["name"] for r in remaining}


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


def test_rescan_tg_channel_is_idempotent_and_releases_db_lock(tmp_path):
    """A repeated rescan adds nothing (it only adds findings, it no longer
    purges them), and the YARA pass, which takes the non-reentrant db.lock
    itself, runs without it held."""
    from types import SimpleNamespace
    from darkwatch import Database, DarkWebCrawler

    db = Database(str(tmp_path / "dw.db"))
    db.add_url("tg://leaks", source="telegram")
    url_id = db.conn.execute("SELECT id FROM urls").fetchone()[0]
    db.conn.execute("UPDATE urls SET tg_username = 'leaks' WHERE id = ?", (url_id,))
    for msg_id in (1, 2):
        db.add_page(url_id, f"https://t.me/leaks/{msg_id}", "t", f"hash{msg_id}",
                    page_type="telegram_message")
        page_id = db.conn.execute(
            "SELECT id FROM pages WHERE content_hash = ?", (f"hash{msg_id}",)).fetchone()[0]
        db.conn.execute(
            "INSERT INTO tg_messages (page_id, url_id, msg_id, text) VALUES (?, ?, ?, ?)",
            (page_id, url_id, msg_id, f"message {msg_id}"))
    db.conn.commit()

    def fake_match(url_id_, page_url, text, bump=True):
        # Would deadlock if rescan still held db.lock here.
        assert db.lock.acquire(timeout=1)
        db.lock.release()
        assert bump is False
        return int(db.add_finding(url_id_, page_url, "r", "keyword:text", 50,
                                  "m", "s", "medium", bump=bump))

    fake = SimpleNamespace(db=db, _yara_match_text=fake_match)
    assert DarkWebCrawler.rescan_tg_channel(fake, url_id) == \
        {"scanned": 2, "findings": 2}
    # The second run finds the same rows: nothing new, nothing doubled.
    assert DarkWebCrawler.rescan_tg_channel(fake, url_id) == \
        {"scanned": 2, "findings": 0}
    assert db.conn.execute(
        "SELECT COUNT(*), MAX(occurrence_count) FROM findings").fetchone() == (2, 1)


def test_utcnow_is_naive_utc():
    """utcnow() replaces datetime.utcnow() (deprecated in 3.12): it must
    stay naive, since stored timestamps are naive UTC ISO strings."""
    from datetime import datetime, timezone
    from darkwatch import utcnow

    now = utcnow()
    assert now.tzinfo is None
    ref = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((ref - now).total_seconds()) < 5


def test_no_deprecated_datetime_calls():
    """No datetime.utcnow()/utcfromtimestamp() left in the app modules:
    they warn on Python 3.12+ and are slated for removal."""
    import ast

    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    hits = []
    for name in sorted(os.listdir(src)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(src, name), encoding="utf-8") as fp:
            tree = ast.parse(fp.read(), filename=name)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and node.attr in ("utcnow", "utcfromtimestamp")
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "datetime"):
                hits.append(f"{name}:{node.lineno}")
    assert not hits, f"deprecated datetime calls: {hits}"
