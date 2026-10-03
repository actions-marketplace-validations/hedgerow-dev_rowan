"""Reduced source snapshot: langchain-core==1.2.5, dump.py, 5ec0fa69de31.

The key fix is preprocessing all values with _serialize_value before JSON
encoding. That function escapes plain dictionaries with an ``lc`` marker.
"""

# ruff: noqa: F821 -- unrelated upstream helpers are omitted from this static fixture

import json


def default(obj):
    if isinstance(obj, Serializable):
        return obj.to_json()
    return to_json_not_implemented(obj)


def _needs_escaping(obj):
    return "lc" in obj or (len(obj) == 1 and "__lc_escaped__" in obj)


def _serialize_value(obj):
    if isinstance(obj, Serializable):
        return _serialize_lc_object(obj)
    if isinstance(obj, dict):
        if _needs_escaping(obj):
            return {"__lc_escaped__": obj}
        return {key: _serialize_value(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_value(item) for item in obj]
    return obj


def dumps(obj, *, pretty=False, **kwargs):
    if "default" in kwargs:
        raise ValueError("`default` should not be passed to dumps")
    obj = _dump_pydantic_models(obj)
    serialized = _serialize_value(obj)
    if pretty:
        indent = kwargs.pop("indent", 2)
        return json.dumps(serialized, indent=indent, **kwargs)
    return json.dumps(serialized, **kwargs)
