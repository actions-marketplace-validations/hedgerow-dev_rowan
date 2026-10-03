"""Shared ORM-read (data-access-layer) inference, extracted from `cross_file.py`.

Recognizes the common "read a model instance out of the database" idioms for
Django and SQLAlchemy, and maps local variables to the model class they were
read from. This is the automatic DAL inference that `CrossFilePass`'s
second-order ORM taint (#155/#156) is built on, and that `AuthzPass` (the
BOLA/IDOR detector, issue #171) reuses to decide "this handler fetches an object
of model M keyed by a user-controlled id." Extracting it here keeps a single
definition shared by both passes instead of two copies.
"""

from __future__ import annotations

import ast

from rowan.analysis.stmt_walk import iter_body_statements

#: Django manager read methods that return (or lazily resolve to) model rows.
DJANGO_MANAGER_READ_METHODS = frozenset({"get", "filter", "first", "all", "get_or_create"})


def is_pascal_case(name: str) -> bool:
    return bool(name) and name[0].isupper()


def orm_read_class(value: ast.expr) -> str | None:
    """Infer the ORM model class a value was read from, for three common
    idioms: SQLAlchemy's `db.session.get(Model, pk)`, `Model.query....()`,
    and session queries rooted at `db.query(Model)` / `db.session.query(Model)`;
    and Django's `Model.objects.get/filter/first/all/get_or_create(...)`
    manager pattern (including lazy chains like
    `Model.objects.filter(...).first()`)."""
    if not isinstance(value, ast.Call):
        return None
    func = value.func
    if isinstance(func, ast.Attribute) and func.attr == "get" and value.args:
        arg0 = value.args[0]
        if isinstance(arg0, ast.Name) and is_pascal_case(arg0.id):
            return arg0.id

    if isinstance(func, ast.Attribute) and func.attr in DJANGO_MANAGER_READ_METHODS:
        node: ast.expr = func.value
        while isinstance(node, (ast.Call, ast.Attribute)):
            if isinstance(node, ast.Call):
                node = node.func
                continue
            if (
                node.attr == "objects"
                and isinstance(node.value, ast.Name)
                and is_pascal_case(node.value.id)
            ):
                return node.value.id
            node = node.value

    # Walk down an arbitrarily long `.foo().bar(...).query` chain -- Calls
    # and Attributes alternate (`.filter_by(...)` between `.query` and
    # `.first()`), so both node kinds must be unwrapped at every step.
    node = func
    while isinstance(node, (ast.Call, ast.Attribute)):
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "query"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and is_pascal_case(node.args[0].id)
            ):
                return node.args[0].id
            node = node.func
            continue
        if (
            node.attr == "query"
            and isinstance(node.value, ast.Name)
            and is_pascal_case(node.value.id)
        ):
            return node.value.id
        node = node.value
    return None


def orm_classes_by_var(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    """Map local variable names assigned from a recognized ORM read idiom
    (`orm_read_class`) to the ORM model class they were read from -- e.g.
    `u = User.query.filter_by(id=1).first()` -> {"u": "User"}."""
    classes_by_var: dict[str, str] = {}
    for stmt in iter_body_statements(func_node.body):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            cls = orm_read_class(stmt.value)
            if cls:
                classes_by_var[stmt.targets[0].id] = cls
    return classes_by_var
