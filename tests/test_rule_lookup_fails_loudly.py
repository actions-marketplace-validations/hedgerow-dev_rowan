"""RT-08: a renamed or deleted rule must fail its tests, not skip them."""

import pytest
import test_ingest_surface_rules as ingest


def test_missing_rule_fails_instead_of_skipping(monkeypatch):
    monkeypatch.setattr(ingest, "load_neuroscan_rules", lambda path: [])
    with pytest.raises(pytest.fail.Exception, match="ns-aiml-130 not found"):
        ingest._rule("ns-aiml-130")
