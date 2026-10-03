from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.agent_flow import AgentFlowPass
from rowan.passes.base import ScanContext


def _scan(tmp_path, files):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return (
        AgentFlowPass()
        .run(
            ScanContext(
                target_path=tmp_path,
                config=ScanConfig(target=tmp_path),
                result=ScanResult(),
            )
        )
        .findings
    )


def test_request_budget_reaching_cross_file_llm_loop_is_flagged(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "agent.py": "def run_agent(message, rounds):\n    for _ in range(rounds):\n        client.chat(messages=[message])\n",
            "api.py": "@app.post('/ask')\ndef ask():\n    data = request.get_json()\n    return run_agent(data.get('message'), int(data.get('rounds')))\n",
        },
    )
    assert [hit.rule_id for hit in hits] == ["AGENT-UNBOUNDED-BUDGET-001"]


def test_keyword_and_route_parameter_budgets_are_flagged(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "agent.py": "def run_agent(message, rounds):\n    for _ in range(rounds):\n        client.chat(messages=[message])\n",
            "api.py": "@app.api_route('/ask')\ndef ask(rounds: int):\n    return run_agent('hello', rounds=rounds)\n",
        },
    )
    assert [hit.rule_id for hit in hits] == ["AGENT-UNBOUNDED-BUDGET-001"]


def test_bound_method_budget_ignores_self_parameter(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "agent.py": "class Agent:\n    def run(self, message, rounds):\n        for _ in range(rounds):\n            client.chat(messages=[message])\n",
            "api.py": "@app.post('/ask')\ndef ask():\n    data = request.get_json()\n    return agent.run('hello', data.get('rounds'))\n",
        },
    )
    assert [hit.rule_id for hit in hits] == ["AGENT-UNBOUNDED-BUDGET-001"]


def test_clamped_budget_is_not_flagged(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "agent.py": "def run_agent(message, rounds):\n    for _ in range(rounds):\n        client.chat(messages=[message])\n",
            "api.py": "@app.post('/ask')\ndef ask():\n    data = request.get_json()\n    rounds = min(int(data.get('rounds')), 8)\n    return run_agent(data.get('message'), rounds)\n",
        },
    )
    assert hits == []


def test_unrelated_same_named_helper_does_not_lend_a_budget_sink(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "agent.py": "def run_agent(message, rounds):\n    for _ in range(rounds):\n        client.chat(messages=[message])\n",
            "other.py": "def run_agent(message, rounds):\n    return {'message': message}\n",
            "api.py": "@app.post('/ask')\ndef ask():\n    data = request.get_json()\n    return run_agent(data.get('message'), data.get('rounds'))\n",
        },
    )
    assert hits == []


def test_custom_markdown_image_renderer_without_allowlist_is_flagged(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "markdown.py": "import re\ndef render_markdown(text):\n    return re.sub(r'!\\[([^]]*)\\]\\(([^)]+)\\)', r'<img alt=\"\\1\" src=\"\\2\">', text)\n",
        },
    )
    assert [hit.rule_id for hit in hits] == ["MARKDOWN-IMAGE-EGRESS-001"]


def test_custom_markdown_image_renderer_with_allowlist_is_not_flagged(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "markdown.py": "def render_markdown(text):\n    allowed_image_hosts = ('/static/',)\n    src = '/static/a.png'\n    if not src.startswith(allowed_image_hosts):\n        return ''\n    return text\n",
        },
    )
    assert hits == []


def test_allowlist_name_without_enforcement_does_not_suppress_renderer(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "markdown.py": "import re\ndef render_markdown(text):\n    allowed_image_hosts = {'cdn.example'}\n    return re.sub(r'!\\[([^]]*)\\]\\(([^)]+)\\)', r'<img src=\"\\2\">', text)\n",
        },
    )
    assert [hit.rule_id for hit in hits] == ["MARKDOWN-IMAGE-EGRESS-001"]


def test_concatenated_custom_image_renderer_is_flagged(tmp_path):
    hits = _scan(
        tmp_path,
        {
            "markdown.py": "def render_markdown(text):\n    url = parse_image_url(text)\n    return '<img src=\"' + url + '\">'\n",
        },
    )
    assert [hit.rule_id for hit in hits] == ["MARKDOWN-IMAGE-EGRESS-001"]


def test_orm_create_loop_is_not_a_budget_sink(tmp_path):
    """AZ-18: `Item.objects.create` is not an LLM call."""
    findings = _scan(
        tmp_path,
        {
            "app.py": (
                "from flask import request\n"
                "from seed import seed_items\n"
                "@app.route('/seed', methods=['POST'])\n"
                "def seed():\n"
                "    seed_items(request.user, int(request.json.get('count')))\n"
            ),
            "seed.py": (
                "def seed_items(owner, count):\n"
                "    for _ in range(count):\n"
                "        Item.objects.create(owner=owner)\n"
            ),
        },
    )
    assert findings == []


def test_llm_create_loop_is_still_a_budget_sink(tmp_path):
    findings = _scan(
        tmp_path,
        {
            "app.py": (
                "from flask import request\n"
                "from seed import ask\n"
                "@app.route('/ask', methods=['POST'])\n"
                "def route():\n"
                "    ask(request.json['q'], int(request.json.get('count')))\n"
            ),
            "seed.py": (
                "def ask(q, count):\n"
                "    for _ in range(count):\n"
                "        client.chat.completions.create(messages=[q])\n"
            ),
        },
    )
    assert [f.rule_id for f in findings] == ["AGENT-UNBOUNDED-BUDGET-001"]


def test_django_widget_render_is_not_a_markdown_renderer(tmp_path):
    findings = _scan(
        tmp_path,
        {
            "widgets.py": (
                "class ImagePreviewWidget(Widget):\n"
                "    def render(self, name, value, attrs=None):\n"
                "        return '<img src=\"' + value + '\">'\n"
            ),
        },
    )
    assert findings == []
