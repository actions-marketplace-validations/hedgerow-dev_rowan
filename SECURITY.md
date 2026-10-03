# Security Policy

## Reporting a vulnerability

Email **hello@hedgerow.dev** with a description of the issue, the affected version or commit, and
steps to reproduce. Please do not open a public GitHub issue for a security report.

You should get an acknowledgement within 5 business days. This project is maintained by one person,
so fix timelines vary with severity and complexity, but we'll keep you updated as we work on it.

If you'd like to encrypt your report, ask for a key in your first email.

## Scope

In scope:

- Vulnerabilities in Rowan itself: the scanner, its pipeline passes, the MCP server, and the
  supporting scripts (`rowan/`, `scripts/`). Examples: unsafe deserialization of a scan target's
  own files, command injection via a crafted repository, path traversal in report output, or a way
  for a scanned codebase to execute code during a scan.
- Vulnerabilities in how Rowan installs or verifies its Opengrep dependency
  (`rowan/install_opengrep.py`).

Out of scope:

- False negatives or false positives in the rule corpus (`rules/`). These are quality issues, not
  security vulnerabilities. Please open a normal GitHub issue instead.
- Vulnerabilities in Opengrep itself: report those upstream at
  [opengrep/opengrep](https://github.com/opengrep/opengrep).
- Vulnerabilities in a project that Rowan's own rules or benchmarks reference. Report those to
  that project directly.

## Disclosure

We ask for a reasonable window to investigate and ship a fix before any public disclosure. We'll credit
reporters who want credit once a fix is out, unless you'd rather stay anonymous.
