"""Manifest parsing.

Manifests may reference custom Python tag handlers registered by the plugin
system, so the full loader is used rather than the safe one.
"""

import yaml


def parse_manifest(document):
    manifest = yaml.load(document, Loader=yaml.Loader)
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a mapping")
    return manifest
