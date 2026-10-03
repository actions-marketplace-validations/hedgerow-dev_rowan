"""Tool-privilege recognition for multi-agent handoff detection (issue #188).

`MultiAgentPass` (`rowan/passes/multiagent.py`) asks a question none of
this project's existing multi-agent coverage does: not "does an agent have a
dangerous tool at all" (`NS-AIML-010`/`011`/`NS-AIML-025` already cover that
as presence signals), but "does an untrusted value produced by one agent
reach a DIFFERENT, more-privileged agent." Answering that needs a notion of
relative privilege -- this module is the recognizer half of that; the pass
drives resolution and the handoff-edge check.

Two axes, each answered independently for a `tools=[...]` list:

* **Privileged** -- a tool that can affect or read outside the sandboxed
  conversation: shell, arbitrary code execution, filesystem write. This is
  the receiving/higher-privilege side of a handoff.
* **Web-sourced** -- a tool that pulls content from the open web (scraping,
  search). Output produced using one of these is attacker-influenceable --
  this is the emitting/lower-trust side of a handoff.

A tool can be neither, one, or (rare, e.g. a "browse and execute" tool)
both. The two axes are independent on purpose: a search tool is not
privileged, and a privileged tool is not automatically a web source.
"""

from __future__ import annotations

import ast
import re

from rowan.analysis.request_sources import dotted_name

#: Known crewai_tools / common custom-tool class names that grant shell,
#: arbitrary code execution, or filesystem write. Curated first (exact
#: names from the real package), heuristic second (`_PRIVILEGED_NAME_RE`
#: below) for house-named custom tools this list can't anticipate.
_PRIVILEGED_TOOL_NAMES: frozenset[str] = frozenset({
    "CodeInterpreterTool", "CodeExecutionTool", "FileWriteTool",
    "FileWriterTool", "DirectoryWriteTool", "ShellTool", "BashTool",
    "PythonREPLTool", "ExecuteCodeTool", "PythonAstREPLTool",
})

#: Heuristic fallback for a custom tool class/function name this project has
#: never seen: "does the NAME itself claim shell/exec/write capability."
#: Matched on the tail component only (see `_name_tail`), not a substring of
#: the whole dotted path, so `WriteUpGeneratorTool` doesn't qualify merely
#: for containing "write" followed by other text -- the tail must END in one
#: of these tokens (`\w*` before, not after).
_PRIVILEGED_NAME_RE = re.compile(
    r"(?i)(?:\w*(?:shell|bash|exec(?:ute)?|interpreter|code_?run|write_?file"
    r"|file_?write|filewriter)\w*tool$|^(?:run_?shell|execute_?code|"
    r"run_?command|write_?file)$)"
)

#: Same idea for the emitting side: tool names that pull content from the
#: open web. Search results are included deliberately -- a search snippet is
#: exactly as attacker-shaped as a scraped page for this purpose (both are
#: text an external party controls the content of).
_WEB_SOURCE_TOOL_NAMES: frozenset[str] = frozenset({
    "ScrapeWebsiteTool", "FirecrawlScrapeWebsiteTool", "SeleniumScrapingTool",
    "ScrapeElementFromWebsiteTool", "SerperDevTool", "WebsiteSearchTool",
    "EXASearchTool", "BraveSearchTool", "GithubSearchTool",
    "YoutubeVideoSearchTool", "ScrapflyScrapeWebsiteTool",
})
_WEB_SOURCE_NAME_RE = re.compile(
    r"(?i)\w*(?:scrape|scraper|crawl|browse|browser)\w*$"
)

#: Shell/exec/subprocess vocabulary reused from NS-AIML-010/011's own
#: presence patterns, for resolving a LOCALLY-DEFINED custom tool
#: (`@tool`-decorated function or `BaseTool` subclass) referenced by name in
#: a `tools=[...]` list, e.g. `tools=[run_shell]` where `run_shell` is
#: defined earlier in the same file.
_SHELL_EXEC_BODY_RE = re.compile(
    r"os\.system\(|subprocess\.(?:run|Popen|call|check_output)\(|"
    r"\bexec\(|\beval\(|os\.popen\("
)


def _name_tail(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1] if dotted else ""


def _call_class_name(call: ast.expr) -> str | None:
    if not isinstance(call, ast.Call):
        return None
    dotted = dotted_name(call.func)
    return _name_tail(dotted) if dotted else None


def is_privileged_tool_expr(expr: ast.expr) -> bool:
    """True if `expr` is a call to (or bare reference naming) a tool class
    recognized as privileged -- `ShellTool()`, `CodeInterpreterTool()`, or a
    bare name whose OWN naming convention claims the same (`run_shell`,
    `execute_code`). Does not resolve a bare name to its definition -- see
    `resolve_custom_tool_privilege` for that."""
    name = _call_class_name(expr)
    if name is None and isinstance(expr, ast.Name):
        name = expr.id
    if not name:
        return False
    return name in _PRIVILEGED_TOOL_NAMES or bool(_PRIVILEGED_NAME_RE.match(name))


def is_web_source_tool_expr(expr: ast.expr) -> bool:
    """True if `expr` is a call to (or bare reference naming) a tool class
    recognized as pulling content from the open web."""
    name = _call_class_name(expr)
    if name is None and isinstance(expr, ast.Name):
        name = expr.id
    if not name:
        return False
    return name in _WEB_SOURCE_TOOL_NAMES or bool(_WEB_SOURCE_NAME_RE.match(name))


def resolve_custom_tool_privilege(tree: ast.AST) -> frozenset[str]:
    """Names of module-level functions/classes defined in `tree` whose OWN
    body contains a shell/exec/subprocess call -- so a `tools=[run_shell]`
    reference to a locally-defined custom tool resolves to "privileged" via
    its actual implementation, not just its declared name.

    Deliberately module-level and by-name only (matches
    `passes/authz.py::_module_helper_guards`'s own "same-module, bare-name
    callee" scope limit) -- a tool imported from another file, or referenced
    through an attribute/instance method, is not resolved and is judged by
    name heuristic alone (`is_privileged_tool_expr`).
    """
    privileged: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        source = ast.unparse(node)
        if _SHELL_EXEC_BODY_RE.search(source):
            privileged.add(node.name)
    return frozenset(privileged)
