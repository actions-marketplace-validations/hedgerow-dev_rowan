"""JG-15 regression tests for Java/Go application guard evidence."""

from pathlib import Path

from rowan.core.findings import Category, Finding, Severity
from rowan.passes.enrichment import EnrichmentPass


def _finding(path: Path, line: int, category: Category) -> Finding:
    return Finding(
        rule_id="JG-ORACLE-001",
        message="request value reaches dangerous sink",
        severity=Severity.HIGH,
        category=category,
        file_path=str(path),
        start_line=line,
        confidence=0.9,
        engine="opengrep",
    )


def _apply(finding: Finding) -> Finding:
    result = EnrichmentPass._demote_java_go_guarded_findings([finding])
    assert len(result) == 1  # guard evidence must never suppress the finding
    return result[0]


def test_go_app_named_path_guard_demotes_but_does_not_suppress(tmp_path):
    source = tmp_path / "handler.go"
    source.write_text(
        "package app\n\n"
        "func read(raw string) {\n"
        "    safePath := validateWorkspacePath(raw)\n"
        "    os.ReadFile(safePath)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 5, Category.PATH_TRAVERSAL))
    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.35
    assert finding.metadata["java_go_guard_evidence"] == "application_path_guard"
    assert finding.metadata["guard_effect"] == "demoted_not_suppressed"


def test_java_normalize_and_base_check_demotes(tmp_path):
    source = tmp_path / "Files.java"
    source.write_text(
        "class Files {\n"
        "  void read(Path base, String name) {\n"
        "    Path candidate = base.resolve(name).normalize();\n"
        "    if (!candidate.startsWith(base)) throw new SecurityException();\n"
        "    java.nio.file.Files.readString(candidate);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 5, Category.PATH_TRAVERSAL))
    assert finding.severity == Severity.LOW
    assert finding.metadata["java_go_guard_evidence"] == "compound_path_confinement"


def test_go_clean_and_prefix_check_demotes(tmp_path):
    source = tmp_path / "files.go"
    source.write_text(
        "package app\n\n"
        "func read(base, raw string) {\n"
        "    clean := filepath.Clean(raw)\n"
        "    if !strings.HasPrefix(clean, base) { return }\n"
        "    os.ReadFile(clean)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 6, Category.PATH_TRAVERSAL))
    assert finding.severity == Severity.LOW
    assert finding.metadata["java_go_guard_evidence"] == "compound_path_confinement"


def test_java_parsed_host_allowlist_demotes_ssrf(tmp_path):
    source = tmp_path / "Fetch.java"
    source.write_text(
        "class Fetch {\n"
        "  void fetch(String target) {\n"
        "    String host = URI.create(target).getHost();\n"
        "    if (!allowedHosts.contains(host)) throw new SecurityException();\n"
        "    httpClient.send(target);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 5, Category.SSRF))
    assert finding.severity == Severity.LOW
    assert finding.metadata["java_go_guard_evidence"] == "parsed_host_allowlist"


def test_go_parsed_host_allowlist_demotes_ssrf(tmp_path):
    source = tmp_path / "fetch.go"
    source.write_text(
        "package app\n\n"
        "func fetch(target string) {\n"
        "    parsed, err := url.Parse(target)\n"
        "    if err != nil || !slices.Contains(allowedHosts, parsed.Host) { return }\n"
        "    http.Get(target)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 6, Category.SSRF))
    assert finding.severity == Severity.LOW
    assert finding.metadata["java_go_guard_evidence"] == "parsed_host_allowlist"


def test_unrelated_guard_does_not_demote_real_path_finding(tmp_path):
    source = tmp_path / "handler.go"
    source.write_text(
        "package app\n\n"
        "func read(raw, cache string) {\n"
        "    safeCache := validateCachePath(cache)\n"
        "    _ = safeCache\n"
        "    os.ReadFile(raw)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 6, Category.PATH_TRAVERSAL))
    assert finding.severity == Severity.HIGH
    assert "java_go_guard_evidence" not in finding.metadata


def test_unguarded_go_oracle_sink_stays_high(tmp_path):
    source = tmp_path / "handler.go"
    source.write_text(
        "package app\n\n"
        "func read(raw string) {\n"
        "    os.ReadFile(raw)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _apply(_finding(source, 4, Category.PATH_TRAVERSAL))
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9
