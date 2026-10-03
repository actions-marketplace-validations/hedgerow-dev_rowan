# Framework vulnerability pairs

This corpus converts real framework advisories into package-independent security
contracts. Every case contains a vulnerable call path and a fixed control. The
benchmark requires 100% vulnerable recall and zero same-rule findings on fixed
files.

Run it with:

```bash
python scripts/benchmark.py --corpus framework_cases
```

The fixtures intentionally model application trust boundaries. Separate
structural rules cover library implementations where a dangerous configuration
or validation/fetch split is visible without assuming every library parameter is
attacker-controlled.
