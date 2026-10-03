"""Reduced source snapshot: langchain-core==1.2.4, dump.py, 10087ac0248a.

The control-flow and serializer calls below are copied from the upstream
implementation. Imports and unrelated Pydantic conversion are omitted.
"""

# ruff: noqa: F821 -- unrelated upstream helpers are omitted from this static fixture

import json


def default(obj):
    if isinstance(obj, Serializable):
        return obj.to_json()
    return to_json_not_implemented(obj)


def dumps(obj, *, pretty=False, **kwargs):
    if "default" in kwargs:
        raise ValueError("`default` should not be passed to dumps")
    try:
        obj = _dump_pydantic_models(obj)
        if pretty:
            indent = kwargs.pop("indent", 2)
            return json.dumps(obj, default=default, indent=indent, **kwargs)
        return json.dumps(obj, default=default, **kwargs)
    except TypeError:
        if pretty:
            indent = kwargs.pop("indent", 2)
            return json.dumps(to_json_not_implemented(obj), indent=indent, **kwargs)
        return json.dumps(to_json_not_implemented(obj), **kwargs)
