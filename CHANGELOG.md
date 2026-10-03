# Changelog

## v0.3.1 (alpha)

Documentation and packaging only; scanning behaviour is unchanged.

- Install docs use pipx or `uv tool`; a bare `pip install` fails on
  Homebrew and other externally managed Pythons.
- Getting started explains how to add an LLM for `rowan hunt` (Ollama,
  DeepSeek or OpenRouter), and the usage guide lists every backend env var.
- The GitHub Action has a fuller description for its Marketplace listing,
  and its docs show the `security-events: write` permission it needs.

## v0.3.0 (alpha)

First public release.

- `rowan scan`: static analysis of source code and model files, with text,
  JSON, HTML and SARIF reports.
- Opengrep within-file dataflow, plus cross-file analysis for Python and JS/TS
  and limited cross-file analysis for Go.
- Model-file scanning by [Hayward](https://github.com/hedgerow-dev/hayward)
  (pickle, PyTorch, GGUF, SafeTensors, Keras, ONNX, TensorFlow and more).
- AI/ML checks: model loading, agent tools, LLM output handling, prompt and
  instruction files, MCP configuration.
- Dependency CVE lookup with reachability hints, CycloneDX SBOM and OpenVEX output.
- Baselines, CI exit codes, a GitHub Action and a pre-commit hook.
- An MCP server (`rowan-mcp`) for coding agents.
- Experimental `rowan hunt` for LLM-assisted review.

Findings are review leads. See the README for coverage limits.
