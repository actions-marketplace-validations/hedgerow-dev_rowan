"""Constrained Python evaluation for the data-analysis assistant."""

ALLOWED_GLOBALS = {"__builtins__": {"len": len, "range": range, "sum": sum}}


def evaluate_snippet(code):
    scope = dict(ALLOWED_GLOBALS)
    exec(compile(code, "<assistant>", "exec"), scope)
    return scope.get("result")
