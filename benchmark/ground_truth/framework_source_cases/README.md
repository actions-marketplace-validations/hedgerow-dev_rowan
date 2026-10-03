# Framework implementation pairs

This corpus tests detection in library source, separately from application
call-path cases. Each pair is pinned to upstream release tags and commits in
`manifest.json`. The Python files are reduced static snapshots: they preserve
the relevant upstream serializer control flow but omit unrelated imports,
docstrings, and Pydantic conversion details. For CVE-2025-68664, the vulnerable
side matches the `default`/`dumps` logic in `langchain-core==1.2.4`; the fixed
side models the `_serialize_value` preprocessing added by the patch in
`langchain-core==1.2.5`. The 34070 pair captures three config-derived path
reads in the legacy prompt loader: template text, examples, and nested prompt
files, before and after default-on path validation in 1.2.22. The 65106 and
40087 pairs capture distinct f-string validation defects: top-level field
traversal in 1.0.6, then nested format
specifiers left unchecked in 1.2.27. The 1.0.7 control for 65106 can still
trigger the 40087 rule; scoring deliberately requires only the *same* CVE's
rule to be absent from its patched pair.

Run the focused gate with:

```bash
uv run python scripts/benchmark.py --corpus framework_source_cases
```

These are candidate source-level signals, not proof that an attacker can reach
each code path. Analysts should verify the relevant input boundary and, for
68664, that marker-shaped user dictionaries can be reinterpreted by a matching
object loader.
