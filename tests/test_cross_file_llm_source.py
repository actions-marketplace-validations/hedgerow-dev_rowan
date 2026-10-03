"""Cross-file taint from LLM output, loop propagation, and method overrides.

Three gaps found by auditing AI/ML frameworks against a real scan (flashrag's
`reasoning_pipeline.py` -> `ReaRAG_utils.py` `eval()` flow needed all three
fixed before it connected):

* model output was not a cross-file taint source at all -- `llm_output_taint.yaml`
  models it for Opengrep, but Opengrep is single-file;
* taint did not survive `for x in tainted:` / `zip(...)`, which is how batch
  pipelines consume generation results;
* a subclass overriding a base-class method was summarized against the base's
  AST, producing an empty `sink_params` that killed every edge into it.
"""

from __future__ import annotations

from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanConfig, ScanContext
from rowan.passes.cross_file import CrossFilePass


def _write(root: Path, rel: str, body: str) -> str:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return str(p.resolve())


def _eval_sink(file_str: str, line: int) -> Finding:
    return Finding(
        rule_id="NS-INJECT-001",
        message="eval() on tainted data",
        severity=Severity.HIGH,
        category=Category.INJECTION,
        file_path=file_str,
        start_line=line,
        engine="neuroscan",
    )


def _line_of(file_str: str, needle: str) -> int:
    for i, ln in enumerate(Path(file_str).read_text().splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(f"{needle!r} not in {file_str}")


def _run(root: Path, findings: list[Finding]) -> list[Finding]:
    ctx = ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(findings=list(findings)),
    )
    return [f for f in CrossFilePass().run(ctx).findings if f.engine == "crossfile"]


_UTILS = (
    "class Utils:\n"
    "    def extract(self, text):\n"
    "        return text.split('```')[1]\n"
    "\n"
    "    def postprocess(self, response):\n"
    "        return eval(self.extract(response))\n"
)


class TestLLMOutputIsCrossFileSource:
    def test_generate_on_model_receiver_is_a_source(self, tmp_path):
        utils = _write(tmp_path, "utils.py", _UTILS)
        _write(tmp_path, "pipe.py", (
            "from utils import Utils\n"
            "class P:\n"
            "    def __init__(self, generator):\n"
            "        self.generator = generator\n"
            "        self.utils = Utils()\n"
            "    def run(self, prompts):\n"
            "        out = self.generator.generate(prompts)\n"
            "        return self.utils.postprocess(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings, "LLM output must seed cross-file taint"

    def test_openai_completion_chain_is_a_source(self, tmp_path):
        utils = _write(tmp_path, "utils.py", _UTILS)
        _write(tmp_path, "pipe.py", (
            "from utils import Utils\n"
            "class P:\n"
            "    def __init__(self, client):\n"
            "        self.client = client\n"
            "        self.utils = Utils()\n"
            "    def run(self, msgs):\n"
            "        out = self.client.chat.completions.create(messages=msgs)\n"
            "        return self.utils.postprocess(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings, "provider call chain must seed cross-file taint"

    def test_generic_verb_on_unrelated_receiver_is_not_a_source(self, tmp_path):
        """`generate` alone is far too common -- without a model-ish receiver
        it must not taint, or every `report.generate()` becomes a source."""
        utils = _write(tmp_path, "utils.py", _UTILS)
        _write(tmp_path, "pipe.py", (
            "from utils import Utils\n"
            "class P:\n"
            "    def __init__(self, report):\n"
            "        self.report = report\n"
            "        self.utils = Utils()\n"
            "    def run(self):\n"
            "        out = self.report.generate()\n"
            "        return self.utils.postprocess(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings == []


class TestTaintSurvivesLoops:
    def test_for_over_tainted_iterable(self, tmp_path):
        utils = _write(tmp_path, "utils.py", _UTILS)
        _write(tmp_path, "pipe.py", (
            "from utils import Utils\n"
            "class P:\n"
            "    def __init__(self, llm):\n"
            "        self.llm = llm\n"
            "        self.utils = Utils()\n"
            "    def run(self, prompts):\n"
            "        outs = self.llm.generate(prompts)\n"
            "        for out in outs:\n"
            "            self.utils.postprocess(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings, "taint must survive `for x in tainted`"

    def test_for_over_zip_with_tainted_operand(self, tmp_path):
        utils = _write(tmp_path, "utils.py", _UTILS)
        _write(tmp_path, "pipe.py", (
            "from utils import Utils\n"
            "class P:\n"
            "    def __init__(self, llm):\n"
            "        self.llm = llm\n"
            "        self.utils = Utils()\n"
            "    def run(self, prompts, items):\n"
            "        outs = self.llm.generate(prompts)\n"
            "        for item, out in zip(items, outs):\n"
            "            self.utils.postprocess(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings, "taint must survive tuple-unpacking over zip()"

    def test_clean_loop_does_not_taint(self, tmp_path):
        utils = _write(tmp_path, "utils.py", _UTILS)
        _write(tmp_path, "pipe.py", (
            "from utils import Utils\n"
            "class P:\n"
            "    def __init__(self):\n"
            "        self.utils = Utils()\n"
            "    def run(self):\n"
            "        for out in ['a', 'b']:\n"
            "            self.utils.postprocess(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings == []


class TestOverriddenMethodSummary:
    """Two classes in one file defining the same method name: the override
    holds the sink, the base does not."""

    _OVERRIDE_UTILS = (
        "class Base:\n"
        "    def handle(self, response):\n"
        "        return response.strip()\n"
        "\n"
        "class Child(Base):\n"
        "    def parse(self, text):\n"
        "        return text.split('```')[1]\n"
        "\n"
        "    def handle(self, response):\n"
        "        parsed = self.parse(response)\n"
        "        for chunk in parsed:\n"
        "            return eval(chunk)\n"
        "        return None\n"
    )

    def test_override_sink_is_reachable(self, tmp_path):
        utils = _write(tmp_path, "u.py", self._OVERRIDE_UTILS)
        _write(tmp_path, "pipe.py", (
            "from u import Child\n"
            "class P:\n"
            "    def __init__(self, llm):\n"
            "        self.llm = llm\n"
            "        self.child = Child()\n"
            "    def run(self, prompts):\n"
            "        out = self.llm.generate(prompts)\n"
            "        return self.child.handle(out)\n"
        ))
        findings = _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])
        assert findings, (
            "the subclass override holds the sink; summarizing it against the "
            "base class's AST yields an empty sink_params and kills the edge"
        )


class TestTestAnchoredFindingsDropped:
    """A cross-file finding anchors at the caller, and a test function is not a
    reachable entry point. Adding LLM output as a source made this acute: 88% of
    new findings across a 17-repo corpus landed in test files (100% in
    langchain), because test suites call `llm.invoke()` constantly."""

    def test_caller_in_tests_dir_is_not_reported(self, tmp_path):
        utils = _write(tmp_path, "pkg/utils.py", _UTILS)
        _write(tmp_path, "tests/test_pipeline.py", (
            "from pkg.utils import Utils\n"
            "class P:\n"
            "    def __init__(self, llm):\n"
            "        self.llm = llm\n"
            "        self.utils = Utils()\n"
            "    def run(self, prompts):\n"
            "        out = self.llm.generate(prompts)\n"
            "        return self.utils.postprocess(out)\n"
        ))
        assert _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))]) == []

    def test_identical_caller_outside_tests_is_reported(self, tmp_path):
        """Control: the same code in application code must still fire, so the
        filter is discriminating on path and not silently disabling the pass."""
        utils = _write(tmp_path, "pkg/utils.py", _UTILS)
        _write(tmp_path, "pkg/pipeline.py", (
            "from pkg.utils import Utils\n"
            "class P:\n"
            "    def __init__(self, llm):\n"
            "        self.llm = llm\n"
            "        self.utils = Utils()\n"
            "    def run(self, prompts):\n"
            "        out = self.llm.generate(prompts)\n"
            "        return self.utils.postprocess(out)\n"
        ))
        assert _run(tmp_path, [_eval_sink(utils, _line_of(utils, "eval("))])

    def test_scan_root_under_a_test_named_directory_still_reports(self, tmp_path):
        """The path is judged RELATIVE to the scan root. Judging the absolute
        path would silently drop every finding for anyone whose checkout lives
        under a directory named `test`/`examples`/... -- which is exactly how
        this bug was caught, via pytest's own tmp_path."""
        root = tmp_path / "testing" / "myrepo"
        utils = _write(root, "pkg/utils.py", _UTILS)
        _write(root, "pkg/pipeline.py", (
            "from pkg.utils import Utils\n"
            "class P:\n"
            "    def __init__(self, llm):\n"
            "        self.llm = llm\n"
            "        self.utils = Utils()\n"
            "    def run(self, prompts):\n"
            "        out = self.llm.generate(prompts)\n"
            "        return self.utils.postprocess(out)\n"
        ))
        assert _run(root, [_eval_sink(utils, _line_of(utils, "eval("))])
