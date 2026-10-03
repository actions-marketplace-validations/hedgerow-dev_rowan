"""SC-13: curated reachability entries must match real import resolution."""

from rowan.core.reachability import collect_reachable_calls, is_package_reachable
from rowan.core.vuln_functions import get_vulnerable_functions

_APP = '''
import urllib3
from lxml import etree


def fetch(url):
    http = urllib3.PoolManager()
    return http.request("GET", url)


def parse(path):
    return etree.parse(path)
'''


def test_lxml_and_urllib3_entries_match(tmp_path):
    (tmp_path / "app.py").write_text(_APP)
    calls = collect_reachable_calls([tmp_path / "app.py"])
    for pkg in ("lxml", "urllib3"):
        reachable, _evidence = is_package_reachable(pkg, get_vulnerable_functions(pkg), calls)
        assert reachable, pkg


def test_unrelated_calls_do_not_make_them_reachable(tmp_path):
    (tmp_path / "app.py").write_text("import urllib3\nfrom lxml import html\nprint(urllib3.__version__, html)\n")
    calls = collect_reachable_calls([tmp_path / "app.py"])
    for pkg in ("lxml", "urllib3"):
        assert is_package_reachable(pkg, get_vulnerable_functions(pkg), calls)[0] is False, pkg
