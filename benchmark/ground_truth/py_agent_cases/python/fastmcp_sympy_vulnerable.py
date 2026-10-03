from mcp.server.fastmcp import FastMCP
from sympy import diff, symbols
from sympy.parsing.sympy_parser import parse_expr

mcp = FastMCP("math")
x = symbols("x")


@mcp.tool()
def derivative(expression: str) -> str:
    """Differentiate an expression in x."""
    expr = parse_expr(expression.replace("^", "**"), local_dict={"x": x})
    return str(diff(expr, x))
