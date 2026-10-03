"""Dedup must not move the surviving finding to another line (BACKLOG TE-04)."""

from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline


def test_placeholder_neighbour_does_not_hide_real_secret(tmp_path: Path):
    (tmp_path / "config.py").write_text(
        'password = "xxxxxxxxxxxxxxxxxxxx"\napi_key = "sk-9Xq2vB7mLp4RtY8wZc3nHd6kFj1sAe5g"\n',
        encoding="utf-8",
    )
    (tmp_path / "control.py").write_text(
        'api_key = "sk-9Xq2vB7mLp4RtY8wZc3nHd6kFj1sAe5g"\n', encoding="utf-8"
    )
    result = ScanPipeline(ScanConfig(target=tmp_path, enable_sca=False)).run()
    by_file = {}
    for f in result.findings:
        if f.category.value == "secrets":
            by_file.setdefault(Path(f.file_path).name, []).append(f)
    assert "control.py" in by_file, [f.rule_id for f in result.findings]
    assert by_file.get("config.py"), "the real key on line 2 must survive its placeholder neighbour"
    assert {f.start_line for f in by_file["config.py"]} == {2}
