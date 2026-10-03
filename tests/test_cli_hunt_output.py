"""Hunt terminal summary: leads must not be presented as confirmed chains."""

from rowan import cli


def _printed(chains: list[dict]) -> str:
    with cli.console.capture() as captured:
        cli._print_chains(chains)
    return captured.get()


def test_lead_chains_are_not_printed_as_confirmed() -> None:
    out = _printed([{
        "type": "sqli", "source": "app.py:3", "status": "lead",
        "lead_reason": "verify refuted", "evidence_state": "unresolved",
    }])
    assert "CONFIRMED CHAINS" not in out
    assert "EVIDENCE LEADS" in out
    assert "verify refuted" in out


def test_confirmed_chain_is_printed_as_confirmed() -> None:
    out = _printed([{"type": "rce", "source": "a.py:1", "status": "confirmed"}])
    assert "CONFIRMED CHAINS" in out
    assert "EVIDENCE LEADS" not in out
