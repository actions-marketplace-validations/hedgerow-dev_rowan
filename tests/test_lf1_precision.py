"""Focused regressions for the LF-1 precision cleanup."""

from pathlib import Path

import yaml

from rowan.core.findings import Category, Finding, Severity
from rowan.passes.enrichment import EnrichmentPass


def _finding(path: Path, rule_id: str, line: int, category: Category) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="test",
        severity=Severity.HIGH,
        category=category,
        file_path=str(path),
        start_line=line,
        engine="opengrep",
    )


def test_allowlisted_sql_identifier_is_not_reported(tmp_path):
    path = tmp_path / "queries.py"
    path.write_text(
        "ALLOWED = {'name', 'owner_id'}\n"
        "def query(question):\n"
        "    match = parse(question)\n"
        "    if not match or match.group(1) not in ALLOWED:\n"
        "        return []\n"
        "    column, value = match.group(1), match.group(2)\n"
        '    sql = f"SELECT * FROM items WHERE {column} = :value"\n'
        "    return execute(sql, {'value': value})\n",
        encoding="utf-8",
    )
    findings = [_finding(path, "NS-SQLI-005", 7, Category.INJECTION)]
    assert EnrichmentPass._suppress_contextual_false_positives(findings) == []


def test_unconstrained_sql_identifier_remains_reported(tmp_path):
    path = tmp_path / "queries.py"
    path.write_text(
        "def query(column):\n"
        "    if enabled:\n"
        "        return []\n"
        '    sql = f"SELECT * FROM items ORDER BY {column}"\n'
        "    return execute(sql)\n",
        encoding="utf-8",
    )
    finding = _finding(path, "NS-SQLI-005", 4, Category.INJECTION)
    assert EnrichmentPass._suppress_contextual_false_positives([finding]) == [finding]


def test_session_jwt_does_not_require_oauth_resource_audience(tmp_path):
    path = tmp_path / "session.py"
    path.write_text(
        "def decode_session(token):\n"
        "    return jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])\n",
        encoding="utf-8",
    )
    findings = [_finding(path, "ns-aiml-159", 2, Category.AUTH)]
    assert EnrichmentPass._suppress_contextual_false_positives(findings) == []


def test_oauth_bearer_jwt_without_audience_remains_reported(tmp_path):
    path = tmp_path / "resource_server.py"
    path.write_text(
        "def authorize_bearer_token(token):\n"
        "    # OAuth resource server validation\n"
        "    return jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])\n",
        encoding="utf-8",
    )
    finding = _finding(path, "ns-aiml-159", 3, Category.AUTH)
    assert EnrichmentPass._suppress_contextual_false_positives([finding]) == [finding]


def test_header_taint_rule_does_not_claim_redirect_sinks():
    rules_path = Path(__file__).parent.parent / "rules" / "python_taint.yaml"
    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["rules"]
    rule = next(rule for rule in rules if rule["id"] == "TNT-HEADER-001")
    sink_blob = yaml.safe_dump(rule["pattern-sinks"])
    assert "redirect(" not in sink_blob
    assert "HttpResponseRedirect(" not in sink_blob


def test_guarded_package_catalog_value_is_not_agent_shell_input(tmp_path):
    path = tmp_path / "tools.py"
    path.write_text(
        "def install(name):\n"
        "    pinned = ALLOWED_PACKAGES.get(name)\n"
        "    if pinned is None:\n"
        "        raise ValueError('not allowed')\n"
        "    return subprocess.run(['pip', 'install', pinned])\n",
        encoding="utf-8",
    )
    findings = [_finding(path, "ns-aiml-168", 5, Category.AI_ML)]
    assert EnrichmentPass._suppress_contextual_false_positives(findings) == []


def test_unrestricted_package_name_remains_agent_shell_input(tmp_path):
    path = tmp_path / "tools.py"
    path.write_text(
        "def install(name):\n"
        "    return subprocess.run(['pip', 'install', name])\n",
        encoding="utf-8",
    )
    finding = _finding(path, "ns-aiml-168", 2, Category.AI_ML)
    assert EnrichmentPass._suppress_contextual_false_positives([finding]) == [finding]
