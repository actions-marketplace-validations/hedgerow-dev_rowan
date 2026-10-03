"""Test fixtures for Rowan: intentionally vulnerable code snippets."""

import tempfile
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--require-corpus",
        action="store_true",
        help="fail, instead of skip, `corpus` tests whose external corpus is missing",
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """A `corpus` test that skips for a missing checkout reads as green on
    any machine without it; under --require-corpus it fails instead (RT-10)."""
    outcome = yield
    report = outcome.get_result()
    if (
        report.skipped
        and item.get_closest_marker("corpus") is not None
        and item.config.getoption("--require-corpus")
    ):
        report.outcome = "failed"
        report.longrepr = f"corpus required (--require-corpus) but test skipped: {call.excinfo.value if call.excinfo else ''}"


@pytest.fixture
def test_project_dir():
    """Create a temporary project directory with vulnerable and safe test files."""
    with tempfile.TemporaryDirectory(prefix="rowan_test_") as tmpdir:
        root = Path(tmpdir)
        src = root / "src"
        src.mkdir()

        # Vulnerable: direct pickle.loads
        (src / "vuln_pickle.py").write_text("""\
import pickle
from flask import request

@app.route('/load')
def load_data():
    data = request.args.get('payload')
    return pickle.loads(data.encode())
""")

        # Safe: torch.load with weights_only
        (src / "safe_torch.py").write_text("""\
import torch

def load_model():
    torch.load("model.pt", weights_only=True)
""")

        # Vulnerable: eval() on user input
        (src / "vuln_eval.py").write_text("""\
from flask import request

@app.route('/calc')
def calculate():
    expr = request.args.get('expr')
    return str(eval(expr))
""")

        # Vulnerable: command injection
        (src / "vuln_cmd.py").write_text("""\
import subprocess
from flask import request

@app.route('/ping')
def ping():
    host = request.args.get('host')
    subprocess.run(f"ping -c 1 {host}", shell=True)
""")

        # Vulnerable: SSRF
        (src / "vuln_ssrf.py").write_text("""\
import requests
from flask import request

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    return requests.get(url).text
""")

        # Vulnerable: SSTI
        (src / "vuln_ssti.py").write_text("""\
from flask import request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string(f"<h1>Hello {name}!</h1>")
""")

        # Safe: parameterized SQL
        (src / "safe_sql.py").write_text("""\
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
""")

        # Vulnerable: SQL injection
        (src / "vuln_sqli.py").write_text("""\
import sqlite3
from flask import request

@app.route('/user')
def get_user():
    name = request.args.get('name')
    conn = sqlite3.connect("db.sqlite")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchone()
""")

        # Vulnerable: torch.load without weights_only
        (src / "vuln_torch.py").write_text("""\
import torch
from flask import request

@app.route('/load-model')
def load_model():
    path = request.args.get('path')
    return torch.load(path)
""")

        # Safe: validation
        (src / "safe_validation.py").write_text("""\
from flask import request

def safe_square():
    x = request.args.get('x')
    if not x.isdigit():
        return "Invalid"
    return str(int(x) * int(x))
""")

        # Vulnerable: subprocess with shell=True
        (src / "vuln_subprocess.py").write_text("""\
import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
""")

        yield root
