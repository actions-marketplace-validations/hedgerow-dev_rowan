import re

from mcp.server.fastmcp import FastMCP
from sympy import diff, symbols
from sympy.parsing.sympy_parser import parse_expr

mcp = FastMCP("math")
x = symbols("x")
_ARITHMETIC = re.compile(r"[0-9x+\-*/^(). ]{1,200}")


@mcp.tool()
def derivative(expression: str) -> str:
    """Differentiate an expression in x."""
    if not _ARITHMETIC.fullmatch(expression):
        raise ValueError("only arithmetic in x is accepted")
    expr = parse_expr(expression.replace("^", "**"), local_dict={"x": x})
    return str(diff(expr, x))
