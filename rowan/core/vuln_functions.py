"""Maps known CVE-affected packages to their specific vulnerable functions.

This hand-curated map is the *highest-precision* source of vulnerable-function
names for SCA reachability, but no longer the only one: for packages absent
here, `SCAPass._apply_reachability` falls back to
`core.advisory_functions.extract_vulnerable_symbols`, which mines the symbols
per-CVE from the OSV advisory text. Keep this map for the cases where the
advisory doesn't name the API in code, or where a hand-verified entry is worth
the extra confidence (bare method names like `from_pretrained` that the
qualified-only extractor deliberately won't derive).
"""

from __future__ import annotations

VULN_FUNCTION_MAP: dict[str, list[str]] = {
    # Bare (no-dot) entries are matched via a *scoped* suffix check: any call
    # resolved into this package's own import namespace whose final segment
    # is that name (see core.reachability.is_package_reachable). Qualified
    # entries (containing a dot) must be the exact resolved dotted call.
    #
    # IMPORTANT: qualified entries must use the real *import* name, not the
    # PyPI distribution name or a conventional alias -- e.g. Pillow ships as
    # `import PIL`, not `import pillow`; bare entries' package key is also
    # matched against the import name via this same rule.
    "torch": ["torch.load", "load"],
    "pyyaml": ["yaml.load", "yaml.unsafe_load", "yaml.full_load"],
    "pickle": ["pickle.load", "pickle.loads"],
    "joblib": ["joblib.load"],
    "dill": ["dill.load", "dill.loads"],
    "jinja2": ["Template", "from_string", "render_template_string"],
    "langchain": ["loads", "load", "deserialize"],
    "numpy": ["numpy.load"],
    "pillow": ["PIL.Image.open"],
    "requests": ["requests.get", "requests.post"],
    "transformers": ["from_pretrained", "pipeline"],
    "huggingface_hub": ["hf_hub_download", "snapshot_download", "from_pretrained"],
    "mlflow": [
        "mlflow.pyfunc.load_model", "mlflow.pytorch.load_model",
        "mlflow.sklearn.load_model", "mlflow.tensorflow.load_model",
    ],
    "gradio": ["gradio.Interface", "gradio.Blocks", "launch"],
    "streamlit": ["streamlit.cache_data", "streamlit.cache_resource"],
    "lxml": ["lxml.etree.parse", "lxml.etree.fromstring"],
    "paramiko": ["SSHClient", "exec_command"],
    "flask": ["render_template_string"],
    "django": ["render_to_string"],
    "pypdf": ["PdfReader"],
    "pyjwt": ["jwt.decode"],
    "gitpython": ["git.Repo.clone_from"],
    "nltk": ["nltk.data.load"],
    "msgpack": ["msgpack.unpackb"],
    "diffusers": ["from_pretrained"],
    # `urlopen` is on pool instances, which import resolution does not follow;
    # constructing a PoolManager or calling the v2 top-level request() does resolve.
    "urllib3": ["PoolManager", "request"],
}


def _normalize(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")


_NORMALIZED_VULN_FUNCTION_MAP: dict[str, list[str]] = {
    _normalize(key): value for key, value in VULN_FUNCTION_MAP.items()
}


def get_vulnerable_functions(package_name: str) -> list[str]:
    return _NORMALIZED_VULN_FUNCTION_MAP.get(_normalize(package_name), [])
