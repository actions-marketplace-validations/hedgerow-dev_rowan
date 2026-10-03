"""RT-13: the GitHub Action installs a pinned Opengrep, not "latest"."""

import re
from pathlib import Path

import yaml

ACTION = yaml.safe_load((Path(__file__).parent.parent / "action.yml").read_text())


def test_opengrep_version_is_pinned_and_passed_as_data():
    version = ACTION["inputs"]["opengrep-version"]["default"]
    assert re.fullmatch(r"v\d+\.\d+\.\d+", version)
    step = next(s for s in ACTION["runs"]["steps"] if s.get("name") == "Install Opengrep")
    assert step["env"]["OPENGREP_VERSION"] == "${{ inputs.opengrep-version }}"
    assert '--version "$OPENGREP_VERSION"' in step["run"]
    assert "${{" not in step["run"]  # inputs reach bash through env only


def test_ref_defaults_to_the_actions_own_checkout():
    assert ACTION["inputs"]["ref"]["default"] == ""
