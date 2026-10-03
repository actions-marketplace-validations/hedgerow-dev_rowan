# Real-CVE recall corpus (issue #105)

This corpus measures recall on **real vulnerabilities in real projects**, not
synthetic snippets (`vuln_cases/`) or a purpose-built app (`vuln_app/`). Each
case pins a project at a **pre-fix** commit (the vulnerability is genuinely
present) and records where it lives and what class it is.

## Layout

- `manifest.json`: the case list (committed). See its `schema` block.
- `cache/<id>/`: fetched checkouts (git-ignored, **not committed**).

## Adding a case

1. Find a CVE with a public fix commit. The commit **before** the fix is the
   pinned `commit` (the code must still be vulnerable there).
2. Identify the sink: the file and approximate line of the dangerous call, and
   the CWE id (used for class-consistency grading, see
   `_CWE_CLASS_KEYWORDS` in `scripts/benchmark.py`; add a mapping there if the
   CWE isn't covered yet).
3. Add an entry to `manifest.json` following `schema`. Put it in the
   `regression` pool only if you intend to tune rules against it; otherwise use
   `holdout` so it stays an honest generalization number (issue #106).
4. Fetch and run:
   ```
   python scripts/fetch_cve_cases.py
   python scripts/benchmark.py --corpus cve_cases
   ```

## Scoring

A case is a **hit** if a scan of the checkout produces a finding in `sink_file`
within `VULN_APP_SINK_WINDOW` lines of `sink_line` **and** the finding's
identity is consistent with the case's CWE class. Recall is computed over
**fetched** cases only; unfetched cases are skipped (like `clean_models/`), so a
missing checkout never fails the run: only a fetched case we fail to detect
does (regression pool).
