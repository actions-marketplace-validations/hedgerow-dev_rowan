"""SIBLING-001: a dangerous primitive used where the repo's own wrapper is skipped.

Every negative case here corresponds to a false-positive cluster the detector
actually produced against the corpus before the constraint that kills it was
added. They are the specification, not decoration:

* guards after the call      -> llamaindex `get`, ragflow `make_request` (127 findings)
* methods as wrappers        -> llamaindex `load_data`, ragflow `load_credentials` (106)
* dunders as wrappers        -> llamaindex `__init__` (84)
* `self` as a guarded param  -> ragflow `check_installation` (28)
* single-file conventions    -> per-class helpers mistaken for repo-wide rules

After all of them the detector reports zero on nine corpus repositories and 23
on the tenth, where langflow ships `ssrf_safe_get` and 15 product-code call
sites fetch URLs without it.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.sibling_gate import SiblingGatePass


def _scan(tmp_path: Path, files: dict[str, str]):
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body), encoding="utf-8")
    ctx = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return SiblingGatePass().run(ctx).findings


_WRAPPER = """
    import requests
    from urllib.parse import urlparse

    ALLOWED = {"cdn.internal"}


    def fetch_media(url, timeout=10):
        host = urlparse(url).hostname
        if host not in ALLOWED:
            raise ValueError("host not allowed")
        return requests.get(url, timeout=timeout)
    """

_COMPLIANT = {
    f"backend_{i}.py": f"""
    from common import fetch_media


    def handle_{i}(request):
        return fetch_media(request["url_{i}"])
    """
    for i in range(3)
}


def test_flags_the_backend_that_skipped_the_wrapper(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {
        "common.py": _WRAPPER,
        **_COMPLIANT,
        "drifted.py": """
        import requests


        def handle(request):
            return requests.get(request["url"], timeout=10)
        """,
    })
    assert len(findings) == 1, [(f.file_path, f.start_line) for f in findings]
    f = findings[0]
    assert f.rule_id == "SIBLING-001"
    assert f.file_path.endswith("drifted.py")
    # The evidence is what makes this a claim rather than a guess: the wrapper
    # that exists, why it counts as a guard, and how established it is.
    assert f.metadata["wrapper_name"] == "fetch_media"
    assert f.metadata["sibling_use_count"] == 3
    assert "host" in f.metadata["wrapper_evidence"]
    assert "fetch_media" in f.message and "3 other call sites" in f.message


def test_compliant_siblings_and_the_wrapper_itself_are_silent(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"common.py": _WRAPPER, **_COMPLIANT})
    assert findings == []


def test_error_handling_after_the_call_is_not_a_guard(tmp_path: Path) -> None:
    """`response = requests.get(url)` then `if response.status_code != 200:
    raise` is error handling. Treating it as validation made every competent
    HTTP helper look like a security wrapper."""
    findings = _scan(tmp_path, {
        "util.py": """
        import requests


        def get(base_url, headers):
            response = requests.get(base_url, headers=headers)
            if response.status_code != 200:
                raise RuntimeError(response.text)
            return response.json()
        """,
        "a.py": "from util import get\n\n\ndef a():\n    return get('http://x', {})\n",
        "b.py": "from util import get\n\n\ndef b():\n    return get('http://y', {})\n",
        "c.py": "from util import get\n\n\ndef c():\n    return get('http://z', {})\n",
        "direct.py": "import requests\n\n\ndef d(u):\n    return requests.get(u)\n",
    })
    assert findings == []


def test_methods_are_not_conventions(tmp_path: Path) -> None:
    """Every reader class defines `load_data`; one class's method is not a
    repo-wide rule the others are violating."""
    findings = _scan(tmp_path, {
        "reader_a.py": """
        import requests
        from urllib.parse import urlparse


        class ReaderA:
            def load_data(self, url):
                if not urlparse(url).scheme:
                    raise ValueError("bad url")
                return requests.get(url)
        """,
        "reader_b.py": """
        import requests


        class ReaderB:
            def load_data(self, url):
                return requests.get(url)
        """,
        "reader_c.py": """
        import requests


        class ReaderC:
            def load_data(self, url):
                return requests.get(url)
        """,
    })
    assert findings == []


def test_self_is_not_a_guarded_parameter(tmp_path: Path) -> None:
    """A method guarding `self.token` wraps nothing its caller passed."""
    findings = _scan(tmp_path, {
        "svc.py": """
        import requests


        class Svc:
            def check_installation(self):
                if not self.access_token:
                    raise RuntimeError("not configured")
                return requests.get(self.base_url)
        """,
        "other.py": "import requests\n\n\ndef fetch(u):\n    return requests.get(u)\n",
    })
    assert findings == []


def test_a_wrapper_used_in_one_file_is_local_style(tmp_path: Path) -> None:
    """Three uses, all in the wrapper's own module: not a convention other
    modules are expected to follow."""
    findings = _scan(tmp_path, {
        "solo.py": _WRAPPER + """

    def one():
        return fetch_media("http://cdn.internal/a")


    def two():
        return fetch_media("http://cdn.internal/b")


    def three():
        return fetch_media("http://cdn.internal/c")
    """,
        "elsewhere.py": "import requests\n\n\ndef e(u):\n    return requests.get(u)\n",
    })
    assert findings == []


def test_no_wrapper_means_no_findings(tmp_path: Path) -> None:
    """The detector is silent on a repo that never centralised the primitive.
    It reports inconsistency, not danger."""
    findings = _scan(tmp_path, {
        "a.py": "import requests\n\n\ndef a(u):\n    return requests.get(u)\n",
        "b.py": "import requests\n\n\ndef b(u):\n    return requests.get(u)\n",
        "c.py": "import requests\n\n\ndef c(u):\n    return requests.get(u)\n",
    })
    assert findings == []


_NET = """
    import requests


    def get(url):
        if not url.startswith("https://api.example.com/"):
            raise ValueError("blocked host")
        return requests.get(url, timeout=5)
    """

_BYPASS = """
    import requests

    settings = {"token": "t"}


    def fetch_profile(user_url):
        token = settings.get("token")
        return requests.get(user_url, headers={"Authorization": token}, timeout=5)
    """


def test_dict_get_is_not_a_use_of_a_wrapper_named_get(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {
        "net.py": _NET,
        "config.py": 'cfg = {"a": 1}\n\ndef read():\n    return cfg.get("a"), cfg.get("b")\n',
        "other.py": _BYPASS,
    })
    assert findings == []


def test_imported_wrapper_named_get_still_counts(tmp_path: Path) -> None:
    users = {
        f"user_{i}.py": f"from net import get\n\ndef load_{i}(u):\n    return get(u)\n"
        for i in range(3)
    }
    findings = _scan(tmp_path, {"net.py": _NET, **users, "other.py": _BYPASS})
    assert len(findings) == 1
    assert "3 other call sites" in findings[0].message
