"""SC-11: every manifest parser honours MAX_DEP_FILE_BYTES."""

from rowan.passes.sca import SCAPass


def test_requirements_and_package_json_respect_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(SCAPass, "MAX_DEP_FILE_BYTES", 1)
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}')
    scanner = SCAPass()
    assert scanner._extract_packages(tmp_path / "requirements.txt") == []
    assert scanner._extract_packages(tmp_path / "package.json") == []


def test_package_json_that_is_not_an_object_is_ignored(tmp_path):
    (tmp_path / "package.json").write_text("[]")
    assert SCAPass()._extract_packages(tmp_path / "package.json") == []
