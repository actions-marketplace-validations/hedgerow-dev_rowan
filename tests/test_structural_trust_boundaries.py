"""Regression tests for GitHub issue #122: structural taint sources for
trust boundaries beyond HTTP requests and agent tools.

The agent-tool insight (any boundary where a function's own arguments are
attacker-influenced is a structural source, even when nothing reads a bare
request.* attribute) generalizes to Celery/RQ task bodies, gRPC servicer
methods, GraphQL resolvers, and webhook handlers -- same recognition
mechanism (_collect_boundary_nodes), same relaxed same-file sink detection
(_structural_path_sink's is_agent_tool mode), different standalone rule_id
per boundary kind.
"""

from __future__ import annotations

import ast

from rowan.config import ScanConfig
from rowan.core.findings import Category, ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import (
    CrossFilePass,
    _collect_boundary_nodes,
    _collect_graphql_resolver_nodes,
    _collect_grpc_servicer_nodes,
    _collect_http_route_nodes,
    _collect_task_queue_nodes,
    _collect_webhook_handler_nodes,
)


def _node_names(tree: ast.AST, ids: set[int]) -> set[str]:
    return {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(node) in ids
    }


class TestTaskQueueDetection:
    def test_shared_task_decorator_recognized(self):
        src = (
            "from celery import shared_task\n"
            "@shared_task\n"
            "def process_upload(filename):\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_task_queue_nodes(tree)) == {"process_upload"}

    def test_app_task_decorator_recognized(self):
        src = (
            "@app.task\n"
            "def run_job(payload):\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_task_queue_nodes(tree)) == {"run_job"}

    def test_plain_function_not_recognized(self):
        src = "def helper(x):\n    pass\n"
        tree = ast.parse(src)
        assert _collect_task_queue_nodes(tree) == set()


class TestGrpcServicerDetection:
    def test_public_methods_on_servicer_subclass_recognized(self):
        src = (
            "class MyServiceServicer(my_pb2_grpc.MyServiceServicer):\n"
            "    def DoThing(self, request, context):\n"
            "        pass\n"
            "    def _private(self, request, context):\n"
            "        pass\n"
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_grpc_servicer_nodes(tree)) == {"DoThing"}

    def test_unrelated_base_class_not_recognized(self):
        src = (
            "class MyHandler(BaseHandler):\n"
            "    def DoThing(self, request, context):\n"
            "        pass\n"
        )
        tree = ast.parse(src)
        assert _collect_grpc_servicer_nodes(tree) == set()


class TestGraphqlResolverDetection:
    def test_resolve_prefix_method_recognized(self):
        src = (
            "class Query(graphene.ObjectType):\n"
            "    def resolve_user(self, info, user_id):\n"
            "        pass\n"
            "    def helper(self):\n"
            "        pass\n"
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_graphql_resolver_nodes(tree)) == {"resolve_user"}

    def test_field_decorator_recognized(self):
        src = (
            "@strawberry.field\n"
            "def get_widget(self, widget_id):\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_graphql_resolver_nodes(tree)) == {"get_widget"}

    def test_bare_resolve_prefixed_function_not_recognized(self):
        """A module-level (or unrelated-class) resolve_-prefixed function is
        NOT a GraphQL resolver just because of the name -- confirmed
        empirically against llama-index's own resolve_binary(), an
        unrelated HTTP-fetch helper that would have been misflagged without
        gating the prefix match on GraphQL-looking class context."""
        src = (
            "def resolve_binary(source, as_base64=False):\n"
            "    return requests.get(source).content\n"
        )
        tree = ast.parse(src)
        assert _collect_graphql_resolver_nodes(tree) == set()

    def test_resolve_prefixed_method_on_unrelated_class_not_recognized(self):
        src = (
            "class UrlHelper:\n"
            "    def resolve_url(self, source):\n"
            "        pass\n"
        )
        tree = ast.parse(src)
        assert _collect_graphql_resolver_nodes(tree) == set()

    def test_field_decorator_with_unrelated_qualifier_not_recognized(self):
        """A bare '.field' attribute decorator from an unrelated library
        (e.g. a dataclass-ish builder) must not be treated as a GraphQL
        resolver just because the attribute name matches."""
        src = (
            "@builder.field\n"
            "def some_prop(self):\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        assert _collect_graphql_resolver_nodes(tree) == set()


class TestWebhookHandlerDetection:
    def test_webhook_in_route_path_recognized(self):
        src = (
            '@app.route("/webhook/stripe", methods=["POST"])\n'
            "def stripe_handler():\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_webhook_handler_nodes(tree)) == {"stripe_handler"}

    def test_webhook_name_without_route_is_not_recognized(self):
        src = "def github_webhook(payload):\n    pass\n"
        tree = ast.parse(src)
        assert _collect_webhook_handler_nodes(tree) == set()

    def test_webhook_name_on_route_is_recognized(self):
        src = '@app.post("/events")\ndef github_webhook(payload):\n    pass\n'
        tree = ast.parse(src)
        assert _node_names(tree, _collect_webhook_handler_nodes(tree)) == {"github_webhook"}

    def test_named_webhook_route_registration_is_recognized(self):
        src = (
            "def github_handler(payload):\n"
            "    pass\n"
            'app.add_url_rule("/webhook/github", view_func=github_handler)\n'
        )
        tree = ast.parse(src)
        assert _node_names(tree, _collect_webhook_handler_nodes(tree)) == {"github_handler"}

    def test_internal_callback_registry_methods_are_not_recognized(self):
        src = (
            "class CompilationCallbackHandler:\n"
            "    def remove_start_callback(self, callback):\n"
            "        self.start_callbacks.remove(callback)\n"
            "    def remove_end_callback(self, callback):\n"
            "        self.end_callbacks.remove(callback)\n"
        )
        tree = ast.parse(src)
        assert _collect_webhook_handler_nodes(tree) == set()

    def test_unrelated_route_not_recognized(self):
        src = (
            '@app.route("/users", methods=["GET"])\n'
            "def list_users():\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        assert _collect_webhook_handler_nodes(tree) == set()


class TestHttpRouteDetection:
    def test_route_decorator_recognized_without_global_request_read(self):
        tree = ast.parse('@app.get("/run/<cmd>")\ndef run(**kwargs):\n    pass\n')
        assert _node_names(tree, _collect_http_route_nodes(tree)) == {"run"}

    def test_unrelated_decorator_not_recognized(self):
        tree = ast.parse('@cache.get("key")\ndef load(**kwargs):\n    pass\n')
        # Method-name recognition alone cannot distinguish cache.get from an
        # HTTP router, so only route-like functions with a path parameter are
        # accepted by the collector.
        assert _collect_http_route_nodes(tree) == set()


class TestCollectBoundaryNodesUnion:
    def test_combines_all_kinds_with_correct_tags(self):
        src = (
            "from celery import shared_task\n"
            "\n"
            "@shared_task\n"
            "def do_task(x):\n"
            "    pass\n"
            "\n"
            "class SvcServicer(pb2_grpc.SvcServicer):\n"
            "    def Call(self, request, context):\n"
            "        pass\n"
            "\n"
            "class Query(graphene.ObjectType):\n"
            "    def resolve_thing(self, info, x):\n"
            "        pass\n"
            "\n"
            '@app.route("/webhook", methods=["POST"])\n'
            "def hook():\n"
            "    pass\n"
        )
        tree = ast.parse(src)
        kind_by_id = _collect_boundary_nodes(tree)
        by_name = {
            node.name: kind_by_id[id(node)]
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(node) in kind_by_id
        }
        assert by_name == {
            "do_task": "task_queue",
            "Call": "grpc",
            "resolve_thing": "graphql",
            "hook": "webhook",
        }


class TestCrossFilePassEmitsBoundaryFindings:
    def test_http_route_kwargs_direct_sink_emits_finding(self, tmp_path):
        root = tmp_path / "app"
        root.mkdir()
        (root / "views.py").write_text(
            "import os\n"
            "@app.get('/run/<cmd>')\n"
            "def run(**kwargs):\n"
            "    os.system(kwargs.get('cmd'))\n",
            encoding="utf-8",
        )
        (root / "other.py").write_text("x = 1\n", encoding="utf-8")
        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
        result = CrossFilePass().run(ctx)
        hits = [f for f in result.findings if f.rule_id == "HTTP-ROUTE-001"]
        assert hits and hits[0].category == Category.COMMAND_INJECTION
    def test_celery_task_direct_sink_emits_task_queue_finding(self, tmp_path):
        """A Celery task body passing its own (queue-controlled) argument
        straight to os.system -- no request.* read anywhere, so ordinary
        source detection alone would never catch this."""
        root = tmp_path / "app"
        root.mkdir()
        (root / "tasks.py").write_text(
            "from celery import shared_task\n"
            "import os\n"
            "\n"
            "@shared_task\n"
            "def process_upload(filename):\n"
            "    os.system(filename)\n",
            encoding="utf-8",
        )
        (root / "other.py").write_text("x = 1\n", encoding="utf-8")

        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
        pass_result = CrossFilePass().run(ctx)

        hits = [f for f in pass_result.findings if f.rule_id == "TASK-QUEUE-001"]
        assert hits, "expected a standalone TASK-QUEUE-001 finding on process_upload"
        assert hits[0].category == Category.COMMAND_INJECTION
        assert "process_upload" in hits[0].message

    def test_grpc_servicer_direct_sink_emits_grpc_finding(self, tmp_path):
        root = tmp_path / "app"
        root.mkdir()
        (root / "servicer.py").write_text(
            "class MyServiceServicer(my_pb2_grpc.MyServiceServicer):\n"
            "    def Eval(self, request, context):\n"
            "        return eval(request.expr)\n",
            encoding="utf-8",
        )
        (root / "other.py").write_text("x = 1\n", encoding="utf-8")

        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
        pass_result = CrossFilePass().run(ctx)

        hits = [f for f in pass_result.findings if f.rule_id == "GRPC-001"]
        assert hits, "expected a standalone GRPC-001 finding on Eval"

    def test_webhook_handler_direct_sink_emits_webhook_finding(self, tmp_path):
        root = tmp_path / "app"
        root.mkdir()
        (root / "views.py").write_text(
            "import subprocess\n"
            "\n"
            '@app.post("/webhook/stripe")\n'
            "def stripe_webhook(cmd):\n"
            "    subprocess.run(cmd)\n",
            encoding="utf-8",
        )
        (root / "other.py").write_text("x = 1\n", encoding="utf-8")

        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
        pass_result = CrossFilePass().run(ctx)

        hits = [f for f in pass_result.findings if f.rule_id == "WEBHOOK-001"]
        assert hits, "expected a standalone WEBHOOK-001 finding on stripe_webhook"
