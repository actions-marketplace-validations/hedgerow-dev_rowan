"""is_http_route: HTTP route decorators, not every decorator ending in a verb."""

import ast

import pytest

from rowan.analysis.request_sources import is_http_route


def _func(decorator: str) -> ast.FunctionDef:
    node = ast.parse(f"{decorator}\ndef handler():\n    pass\n").body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


@pytest.mark.parametrize(
    "decorator",
    [
        "@app.get('/predict')",
        "@router.post(path='/predict')",
        "@app.route('/predict', methods=['POST'])",
        "@bp.route",
        "@api_view(['GET'])",
    ],
)
def test_http_routes_are_detected(decorator):
    assert is_http_route(_func(decorator))


@pytest.mark.parametrize(
    "decorator",
    [
        "@mock.patch('os.path.exists')",
        "@patch('module.fn')",
        "@torch._inductor.config.patch(max_autotune=True)",
        "@config.patch('flag', True)",
        "@cache.get",
        "@app.get(PREDICT_PATH)",
    ],
)
def test_non_routes_are_rejected(decorator):
    assert not is_http_route(_func(decorator))
