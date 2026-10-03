"""Tests for AST-based sanitizer detection and enrichment pass."""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

from rowan.analysis.ast_sanitizers import (
    collect_pydantic_validated_classes,
    collect_safe_dicts,
    collect_string_constants,
)
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.ast_enrichment import ASTEnrichmentPass
from rowan.passes.base import ScanContext


def _parse(source: str) -> ast.AST:
    return ast.parse(source)


class TestCollectSafeDicts:
    def test_collect_safe_dicts(self):
        tree = _parse('COMMANDS = {"ls": "/bin/ls", "cat": "/bin/cat"}\n')
        assert collect_safe_dicts(tree) == {"COMMANDS"}

    def test_safe_dict_non_constant_values(self):
        tree = _parse('DYNAMIC = {"key": func()}\n')
        assert collect_safe_dicts(tree) == set()

    def test_empty_dict_is_not_safe(self):
        # TE-02: `all()` over no values is True; an empty registry is filled
        # at runtime and is not a constant lookup table.
        tree = _parse('EMPTY = {}\nX = {"a": 1}\n')
        assert collect_safe_dicts(tree) == {"X"}

    def test_nested_inside_function_not_detected(self):
        tree = _parse("def f():\n    X = {'a': 1}\n")
        assert collect_safe_dicts(tree) == set()


class TestCollectPydanticValidated:
    def test_collect_pydantic_validated(self):
        src = (
            "from pydantic import BaseModel, model_validator\n"
            "class UserInput(BaseModel):\n"
            "    name: str\n"
            "    @model_validator(mode='before')\n"
            "    def check(cls, v):\n"
            "        return v\n"
        )
        tree = _parse(src)
        assert collect_pydantic_validated_classes(tree) == {"UserInput"}

    def test_pydantic_no_validator(self):
        src = (
            "from pydantic import BaseModel\n"
            "class SimpleModel(BaseModel):\n"
            "    name: str\n"
        )
        tree = _parse(src)
        assert collect_pydantic_validated_classes(tree) == set()

    def test_field_validator_detected(self):
        src = (
            "from pydantic import BaseModel, field_validator\n"
            "class Config(BaseModel):\n"
            "    url: str\n"
            "    @field_validator('url')\n"
            "    def validate_url(cls, v):\n"
            "        return v\n"
        )
        tree = _parse(src)
        assert collect_pydantic_validated_classes(tree) == {"Config"}

    def test_sqlmodel_with_validator(self):
        src = (
            "from sqlmodel import SQLModel\n"
            "from pydantic import validator\n"
            "class Item(SQLModel):\n"
            "    price: float\n"
            "    @validator('price')\n"
            "    def check_price(cls, v):\n"
            "        return v\n"
        )
        tree = _parse(src)
        assert collect_pydantic_validated_classes(tree) == {"Item"}

    def test_non_pydantic_base_ignored(self):
        src = (
            "class Foo(SomeOtherBase):\n"
            "    @model_validator(mode='before')\n"
            "    def check(cls, v):\n"
            "        return v\n"
        )
        tree = _parse(src)
        assert collect_pydantic_validated_classes(tree) == set()


class TestCollectStringConstants:
    def test_collect_string_constants(self):
        tree = _parse('API_URL = "https://example.com"\n')
        result = collect_string_constants(tree)
        assert result == {"API_URL": "https://example.com"}

    def test_non_upper_not_constant(self):
        tree = _parse('api_url = "https://example.com"\n')
        assert collect_string_constants(tree) == {}

    def test_int_constant_excluded(self):
        tree = _parse("MAX_RETRIES = 3\n")
        assert collect_string_constants(tree) == {}

    def test_multiple_constants(self):
        src = 'HOST = "localhost"\nPORT = "8080"\nname = "skip"\n'
        tree = _parse(src)
        result = collect_string_constants(tree)
        assert result == {"HOST": "localhost", "PORT": "8080"}


class TestASTEnrichmentIntegration:
    def test_safe_dict_lookup_suppressed(self):
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                'COMMANDS = {"ls": "/bin/ls", "cat": "/bin/cat"}\n'
                "def run(user_input):\n"
                "    cmd = COMMANDS[user_input]\n"
                "    os.system(cmd)\n"
            )
            f.flush()
            file_path = f.name

        finding = Finding(
            rule_id="NS-CMDI-001",
            message="Command injection via os.system",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=file_path,
            start_line=3,
            engine="neuroscan",
        )

        result = ScanResult()
        result.add_finding(finding)
        config = ScanConfig(target=Path(file_path).parent)
        context = ScanContext(
            target_path=Path(file_path).parent,
            config=config,
            result=result,
        )

        pass_ = ASTEnrichmentPass()
        pass_.run(context)

        assert len(context.result.findings) == 0

    def test_pydantic_class_constructor_suppressed(self):
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "from pydantic import BaseModel, field_validator\n"
                "class SafeInput(BaseModel):\n"
                "    cmd: str\n"
                "    @field_validator('cmd')\n"
                "    def check(cls, v):\n"
                "        assert v in ('ls', 'cat')\n"
                "        return v\n"
                "def run(raw):\n"
                "    validated = SafeInput(cmd=raw)\n"
                "    os.system(validated.cmd)\n"
            )
            f.flush()
            file_path = f.name

        finding = Finding(
            rule_id="NS-CMDI-001",
            message="Command injection",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=file_path,
            start_line=9,
            engine="neuroscan",
        )

        result = ScanResult()
        result.add_finding(finding)
        config = ScanConfig(target=Path(file_path).parent)
        context = ScanContext(
            target_path=Path(file_path).parent,
            config=config,
            result=result,
        )

        pass_ = ASTEnrichmentPass()
        pass_.run(context)

        assert len(context.result.findings) == 0

    def test_upper_case_constant_downgraded(self):
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                'DEFAULT_CMD = "echo hello"\n'
                "def run():\n"
                "    os.system(DEFAULT_CMD)\n"
            )
            f.flush()
            file_path = f.name

        finding = Finding(
            rule_id="NS-CMDI-001",
            message="Command injection via os.system",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=file_path,
            start_line=3,
            engine="neuroscan",
        )

        result = ScanResult()
        result.add_finding(finding)
        config = ScanConfig(target=Path(file_path).parent)
        context = ScanContext(
            target_path=Path(file_path).parent,
            config=config,
            result=result,
        )

        pass_ = ASTEnrichmentPass()
        pass_.run(context)

        assert len(context.result.findings) == 1
        assert context.result.findings[0].severity == Severity.LOW
        assert context.result.findings[0].metadata.get("ast_downgraded") == "upper_case_constant"

    def test_upper_case_constant_with_tainted_argument_not_downgraded(self):
        # TE-03: the constant is only part of the sink argument; the other
        # part is request input, so the finding must keep its severity.
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                'TOOL = "ls"\n'
                "def run(request):\n"
                "    name = request.args['name']\n"
                '    subprocess.run(f"{TOOL} {name}", shell=True)\n'
            )
            f.flush()
            file_path = f.name

        finding = Finding(
            rule_id="NS-CMDI-002",
            message="subprocess with shell=True",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=file_path,
            start_line=4,
            engine="neuroscan",
        )
        result = ScanResult()
        result.add_finding(finding)
        context = ScanContext(
            target_path=Path(file_path).parent,
            config=ScanConfig(target=Path(file_path).parent),
            result=result,
        )
        ASTEnrichmentPass().run(context)
        assert context.result.findings[0].severity == Severity.HIGH
        assert "ast_downgraded" not in context.result.findings[0].metadata

    def test_secret_assignment_not_downgraded_by_its_own_name(self):
        # TE-03: the assignment target of a constant is itself a Name on the
        # line, so every one-line secret was demoted to LOW.
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write('LANGSMITH_API_KEY = "lsv2_pt_9Xq2vB7mLp4RtY8wZc3nHd6kFj1sAe5g"\n')
            f.flush()
            file_path = f.name

        finding = Finding(
            rule_id="ns-sec-003",
            message="LangSmith API key",
            severity=Severity.HIGH,
            category=Category.SECRETS,
            file_path=file_path,
            start_line=1,
            engine="neuroscan",
        )
        result = ScanResult()
        result.add_finding(finding)
        context = ScanContext(
            target_path=Path(file_path).parent,
            config=ScanConfig(target=Path(file_path).parent),
            result=result,
        )
        ASTEnrichmentPass().run(context)
        assert context.result.findings[0].severity == Severity.HIGH

    def test_unmatched_finding_preserved(self):
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "def run(user_input):\n"
                "    os.system(user_input)\n"
            )
            f.flush()
            file_path = f.name

        finding = Finding(
            rule_id="NS-CMDI-001",
            message="Command injection",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=file_path,
            start_line=2,
            engine="neuroscan",
        )

        result = ScanResult()
        result.add_finding(finding)
        config = ScanConfig(target=Path(file_path).parent)
        context = ScanContext(
            target_path=Path(file_path).parent,
            config=config,
            result=result,
        )

        pass_ = ASTEnrichmentPass()
        pass_.run(context)

        assert len(context.result.findings) == 1
        assert context.result.findings[0].severity == Severity.HIGH


class TestStringLiteralCallSuppression:
    """#304: a code-execution regex rule (eval/exec/os.system/pickle/yaml.load)
    fires on the call syntax whether it is a real call or the same text inside
    a string literal / comment / bare name. A genuine finding always has a
    matching ast.Call on its line; when the AST shows none, the match is
    spurious and is suppressed. Real calls must survive."""

    @staticmethod
    def _run(source: str, rule_id: str, line: int) -> int:
        import tempfile as _tf
        with _tf.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as f:
            f.write(source)
            f.flush()
            path = f.name
        finding = Finding(
            rule_id=rule_id, message="x", severity=Severity.HIGH,
            category=Category.INJECTION, file_path=path, start_line=line,
            engine="opengrep",
        )
        result = ScanResult()
        result.add_finding(finding)
        ctx = ScanContext(
            target_path=Path(path).parent,
            config=ScanConfig(target=Path(path).parent),
            result=result,
        )
        ASTEnrichmentPass().run(ctx)
        return len(ctx.result.findings)

    def test_denylist_string_is_suppressed(self):
        src = 'DANGEROUS = [\n    "eval(",\n    "os.system(",\n]\n'
        assert self._run(src, "NS-INJECT-001", 2) == 0   # "eval(" string
        assert self._run(src, "NS-INJECT-004", 3) == 0   # "os.system(" string

    def test_description_string_is_suppressed(self):
        src = 'def d():\n    return "call eval() or exec() on input"\n'
        assert self._run(src, "NS-INJECT-001", 2) == 0
        assert self._run(src, "NS-INJECT-002", 2) == 0

    def test_yaml_and_pickle_strings_suppressed(self):
        src = 'PATTERNS = {\n    "yaml.load(": 1,\n    "pickle.loads(": 2,\n}\n'
        assert self._run(src, "NS-DESER-003", 2) == 0
        assert self._run(src, "NS-DESER-001", 3) == 0

    def test_real_calls_are_not_suppressed(self):
        src = (
            "import os, yaml, pickle\n"
            "def run(u):\n"
            "    eval(u)\n"
            "    os.system(u)\n"
            "    yaml.load(u)\n"
            "    pickle.loads(u)\n"
        )
        assert self._run(src, "NS-INJECT-001", 3) == 1
        assert self._run(src, "NS-INJECT-004", 4) == 1
        assert self._run(src, "NS-DESER-003", 5) == 1
        assert self._run(src, "NS-DESER-001", 6) == 1

    def test_unmapped_rule_is_untouched(self):
        # A rule not in the map (e.g. an SQL f-string rule) must not be
        # affected by this suppressor at all.
        src = 'q = "SELECT * FROM t"\n'
        assert self._run(src, "NS-SQLI-005", 1) == 1


class TestSqlFstringLogSuppression:
    """#304: NS-SQLI-005 matches an SQL-keyword f-string. When that f-string is
    a logging/print argument it is a log message, not a query, and is
    suppressed. An f-string ASSIGNED to a variable (the real SQL-construction
    shape the rule targets) must survive."""

    @staticmethod
    def _run(source: str, line: int) -> int:
        import tempfile as _tf
        with _tf.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as f:
            f.write(source)
            f.flush()
            path = f.name
        finding = Finding(
            rule_id="NS-SQLI-005", message="x", severity=Severity.HIGH,
            category=Category.INJECTION, file_path=path, start_line=line,
            engine="opengrep",
        )
        result = ScanResult()
        result.add_finding(finding)
        ctx = ScanContext(
            target_path=Path(path).parent,
            config=ScanConfig(target=Path(path).parent),
            result=result,
        )
        ASTEnrichmentPass().run(ctx)
        return len(ctx.result.findings)

    def test_logger_fstring_is_suppressed(self):
        src = 'import logging\ndef f(q):\n    logging.warning(f"ran SELECT ... where id = {q}")\n'
        assert self._run(src, 3) == 0

    def test_print_fstring_is_suppressed(self):
        src = 'def f(q):\n    print(f"about to run SELECT ... where id = {q}")\n'
        assert self._run(src, 2) == 0

    def test_multiline_logger_call_is_suppressed(self):
        src = 'import logging\ndef f(x):\n    logging.info(\n        f"built SELECT ... WHERE k = {x}"\n    )\n'
        assert self._run(src, 4) == 0

    def test_real_sql_assignment_is_not_suppressed(self):
        src = 'def f(name):\n    query = f"SELECT * FROM users WHERE name = \'{name}\'"\n    return query\n'
        assert self._run(src, 2) == 1

    def test_assignment_guard_wins_when_a_line_both_assigns_and_looks_loggy(self):
        # A line that assigns an f-string is never treated as a pure log line.
        src = 'def f(name):\n    query = f"SELECT * FROM t WHERE n = {name}"  # print(f"...SELECT {x}")\n    return query\n'
        assert self._run(src, 2) == 1
