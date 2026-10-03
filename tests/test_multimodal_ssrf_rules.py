"""Behavioral tests for the multimodal media-fetch SSRF rules (ns-aiml-135,
ns-aiml-136) and the fake exec-sandbox rule (ns-aiml-137) in
rules/ai_security.yaml.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id: str):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    if not matches:
        pytest.fail(f"{rule_id} not found")
    return matches[0]


class TestMediaUrlFetch:
    """ns-aiml-135."""

    def test_image_url_reaches_requests_get(self, tmp_path):
        """LMDeploy CVE-2026-33626 shape: vision-language loader fetches a
        caller-supplied image_url with no host check."""
        f = tmp_path / "vl_loader.py"
        f.write_text(
            "def load_image(image_url: str):\n"
            '    headers = {"User-Agent": "lmdeploy"}\n'
            "    response = requests.get(image_url, headers=headers, timeout=10)\n"
            "    return Image.open(BytesIO(response.content))\n"
        )
        assert len(_rule("ns-aiml-135").check(f)) >= 1

    def test_ref_audio_reaches_async_session_get(self, tmp_path):
        """NVIDIA Dynamo Omni TTS shape: ref_audio fetched through an aiohttp
        session that never revalidates the host."""
        f = tmp_path / "audio_handler.py"
        f.write_text(
            "async def fetch_ref_audio(ref_audio: str) -> bytes:\n"
            "    async with aiohttp.ClientSession() as session:\n"
            "        async with session.get(ref_audio) as resp:\n"
            "            return await resp.read()\n"
        )
        assert len(_rule("ns-aiml-135").check(f)) >= 1

    def test_openai_content_part_fetched_inline(self, tmp_path):
        f = tmp_path / "chat_parts.py"
        f.write_text(
            "def resolve_part(part: dict) -> bytes:\n"
            '    resp = httpx.get(part["image_url"]["url"], timeout=5)\n'
            "    return resp.content\n"
        )
        assert len(_rule("ns-aiml-135").check(f)) >= 1

    def test_urlopen_on_media_url_is_flagged(self, tmp_path):
        f = tmp_path / "media.py"
        f.write_text(
            "def read_media(media_url: str) -> bytes:\n"
            "    with urlopen(media_url) as fh:\n"
            "        return fh.read()\n"
        )
        assert len(_rule("ns-aiml-135").check(f)) >= 1

    def test_guarded_fetch_is_not_flagged(self, tmp_path):
        """The v0.12.3 fix: an _is_safe_url() check in the same window."""
        f = tmp_path / "safe_loader.py"
        f.write_text(
            "def load_image(image_url: str):\n"
            "    if not _is_safe_url(image_url):\n"
            '        raise ValueError("blocked destination")\n'
            "    response = requests.get(image_url, timeout=10)\n"
            "    return Image.open(BytesIO(response.content))\n"
        )
        assert _rule("ns-aiml-135").check(f) == []

    def test_fixed_destination_fetch_is_not_flagged(self, tmp_path):
        f = tmp_path / "health.py"
        f.write_text(
            "def probe_backend() -> int:\n"
            '    resp = requests.get("http://127.0.0.1:8000/health", timeout=2)\n'
            "    return resp.status_code\n"
        )
        assert _rule("ns-aiml-135").check(f) == []


class TestMediaUrlPayloadRead:
    """ns-aiml-136."""

    def test_openai_content_part_read_is_flagged(self, tmp_path):
        f = tmp_path / "parts.py"
        f.write_text(
            "def collect(part: dict) -> str:\n"
            '    url = part["image_url"]["url"]\n'
            "    return url\n"
        )
        assert len(_rule("ns-aiml-136").check(f)) >= 1

    def test_mapping_get_of_ref_audio_is_flagged(self, tmp_path):
        f = tmp_path / "tts.py"
        f.write_text(
            "def handle(payload: dict) -> str:\n"
            '    ref = payload.get("ref_audio")\n'
            "    return ref\n"
        )
        assert len(_rule("ns-aiml-136").check(f)) >= 1

    def test_pydantic_attribute_read_is_flagged(self, tmp_path):
        f = tmp_path / "schema_read.py"
        f.write_text(
            "def source_of(content) -> str:\n"
            "    return content.image_url.url\n"
        )
        assert len(_rule("ns-aiml-136").check(f)) >= 1

    def test_payload_construction_is_not_flagged(self, tmp_path):
        """Client-side code building a request is the opposite direction."""
        f = tmp_path / "client_build.py"
        f.write_text(
            "def build(url: str) -> dict:\n"
            "    payload = {}\n"
            '    payload["image_url"] = url\n'
            "    return payload\n"
        )
        assert _rule("ns-aiml-136").check(f) == []

    def test_guarded_read_is_not_flagged(self, tmp_path):
        f = tmp_path / "guarded_read.py"
        f.write_text(
            "def image_source(part: dict) -> str:\n"
            '    url = part["image_url"]["url"]\n'
            "    if not _is_safe_url(url):\n"
            '        raise ValueError("blocked destination")\n'
            "    return url\n"
        )
        assert _rule("ns-aiml-136").check(f) == []


class TestFakeExecSandbox:
    """ns-aiml-137."""

    def test_restricted_builtins_dict_is_flagged(self, tmp_path):
        """LMCache /run_script shape: a 'restricted' globals mapping."""
        f = tmp_path / "run_script.py"
        f.write_text(
            "def run(script_content: str):\n"
            "    restricted_globals = {\n"
            '        "__builtins__": {\n'
            '            "print": print,\n'
            '            "str": str,\n'
            '            "__import__": restricted_import,\n'
            "        }\n"
            "    }\n"
            "    restricted_locals = {}\n"
            "    exec(script_content, restricted_globals, restricted_locals)\n"
        )
        assert len(_rule("ns-aiml-137").check(f)) >= 1

    def test_inline_empty_builtins_dict_is_flagged(self, tmp_path):
        f = tmp_path / "inline_exec.py"
        f.write_text(
            "def evaluate(expr: str):\n"
            '    return eval(expr, {"__builtins__": {}})\n'
        )
        assert len(_rule("ns-aiml-137").check(f)) >= 1

    def test_builtins_assigned_into_globals_is_flagged(self, tmp_path):
        f = tmp_path / "assigned.py"
        f.write_text(
            "def make_globals(safe_builtins: dict) -> dict:\n"
            "    sandbox = {}\n"
            '    sandbox["__builtins__"] = safe_builtins\n'
            "    return sandbox\n"
        )
        assert len(_rule("ns-aiml-137").check(f)) >= 1

    def test_builtins_name_comparison_is_not_flagged(self, tmp_path):
        """Comparing a name against the string "__builtins__" is not a
        mapping (observed in _pytest/_code/code.py)."""
        f = tmp_path / "frame_repr.py"
        f.write_text(
            "def render(locals_: dict) -> list[str]:\n"
            "    lines = []\n"
            "    for name in sorted(locals_):\n"
            '        if name == "__builtins__":\n'
            '            lines.append("__builtins__ = <builtins>")\n'
            "    return lines\n"
        )
        assert _rule("ns-aiml-137").check(f) == []

    def test_exec_without_globals_dict_is_not_flagged(self, tmp_path):
        f = tmp_path / "plain_exec.py"
        f.write_text(
            "def apply_plugin(source: str, namespace: dict) -> None:\n"
            '    """Execute an operator-installed plugin in its own namespace."""\n'
            "    exec(source, namespace)\n"
        )
        assert _rule("ns-aiml-137").check(f) == []

    def test_real_os_level_sandbox_is_not_flagged(self, tmp_path):
        f = tmp_path / "real_sandbox.py"
        f.write_text(
            "def run_untrusted(script_path: str) -> str:\n"
            "    result = subprocess.run(\n"
            '        ["docker", "run", "--rm", "--network", "none",\n'
            '         "sandbox:latest", "python", script_path],\n'
            "        shell=False,\n"
            "        check=True,\n"
            "        capture_output=True,\n"
            "        timeout=30,\n"
            "    )\n"
            "    return result.stdout.decode()\n"
        )
        assert _rule("ns-aiml-137").check(f) == []
