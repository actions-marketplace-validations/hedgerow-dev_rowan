# Model-file scanning: quickset, 2026-10-02

Rowan v0.3.0 against five open-source model-file scanners on
[quickset](https://github.com/hedgerow-dev/quickset), Hedgerow's public
benchmark for model-file scanners. Rowan scans model files with
[Hayward](https://github.com/hedgerow-dev/hayward) 1.2.4.

## Result

26 inert malicious test files (pickle, skops, SafeTensors, GGUF, ONNX, joblib)
and 225 benign files, 213 of them real Hugging Face models pinned by hash.
"Strict" counts only each tool's top, actionable tier. "+unknown" also counts
the tier the tool itself declines to stand behind.

| Scanner | Detected (strict) | False positives (strict) | False positives (+unknown) | Files read |
|---|---|---|---|---|
| **Rowan 0.3.0** | **26/26** | **0/225** | 6/225 | **251/251** |
| Hayward 1.0.1 | 26/26 | 0/225 | 7/225 | 251/251 |
| ModelAudit 0.2.52 | 18/26 | 14/225 | 93/225 | 251/251 |
| fickling 0.1.12 | 16/26 | 88/92 | | 109/251 |
| picklescan 1.0.5 | 12/26 | 1/192 | 38/192 | 216/251 |
| ModelScan 0.8.8 | 5/26 | 0/80 | | 93/251 |

A false-positive rate only means something next to the number of files the
tool actually read: ModelScan's 0 false positives come from reading 93 of 251
files. Files a scanner could not read count as misses in the detection column.

**Externally written corpora** (detection, strict / +unknown):

| Corpus | Rowan | Hayward 1.0.1 |
|---|---|---|
| picklescan's own test suite (35 malicious, 3 benign) | 35/35, 0 FP | 35/35, 0 FP |
| PickleCloak gadget exploits (57) | 50/57 / 57/57 | 49/57 / 57/57 |
| PickleCloak AEG chains (97) | 91/97 / 97/97 | 91/97 / 97/97 |

Full per-file verdicts for every scanner: [`report.txt`](report.txt),
[`results.json`](results.json).

## Read these numbers carefully

- **Hedgerow wrote quickset, Hayward and Rowan.** The test cases are public and
  every scanner runs through the same subprocess contract, but the authors are
  not independent.
- **The malicious cases are what Hayward was built to catch.** Several come from
  published scanner bypasses; quickset keeps cases no scanner catches marked as
  known misses, but this table still favours the tool written alongside it.
- **Rowan and Hayward share an engine,** so their rows agree by design. Rowan's
  row shows Rowan adds no losses on top of Hayward. The Hayward row is an older
  release (1.0.1) installed in the benchmark environment.
- **PickleCloak declares no license.** Only counts are published here, not files.

## Setup

| | |
|---|---|
| quickset | commit `a51d9f8`, benign manifest `b4fe2992e8a85a77` |
| Rowan | v0.3.0 with Hayward 1.2.4 (re-run after the 1.2.4 release: identical results), `rowan scan <dir> --audit -f json --no-sca --no-taint --no-cross-file --no-project-config`, one file per directory |
| Machine | macOS, Apple Silicon, Python 3.12 |

## Reproduce

```bash
git clone https://github.com/hedgerow-dev/quickset && cd quickset
git checkout a51d9f8
pip install -e . picklescan modelscan fickling modelaudit hayward
python -m quickset.realmodels        # fetch the benign models
python -m quickset.external          # fetch the external corpora
ROWAN=/path/to/rowan python /path/to/rowan/benchmark/results/quickset-2026-10-02/rowan_adapter.py --jobs 2
```

[`rowan_adapter.py`](rowan_adapter.py) adds Rowan to quickset's scanners
without changing quickset.
