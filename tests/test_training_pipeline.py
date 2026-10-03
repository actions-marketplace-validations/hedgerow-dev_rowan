"""Training-side supply chain (issue #190, epic #183).

The corpus covers model LOADING thoroughly (deserialization,
trust_remote_code, MFV, ns-aiml-047/060 for unpinned revisions and
unverified downloads) but covered the TRAINING side not at all before this.

  TNT-ML-030   user data reaching a training/fine-tuning dataset with no
               schema validation (rules/ml_taint.yaml, Opengrep taint only --
               taint-mode rules have no legacy NeuroScan equivalent).
  ns-aiml-146  adapter/LoRA loaded without a pinned revision or local path.
  ns-aiml-147  model merging / weight arithmetic without provenance checks.
  ns-aiml-148  Airflow DAG run parameter interpolated into a shell/container
               command. Scoped to Airflow; Kubeflow/Dagster/Prefect/DVC
               orchestrator coverage is a follow-up (see the epic tracking).
  ns-aiml-149  MLOps artifact-store download without integrity verification.

ns-aiml-150 (repo-level "no model signing anywhere" signal) is out of scope
here -- it needs a whole-repo absence check, a different mechanism than a
per-file regex/taint rule. Filed as a follow-up (see the epic tracking).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULES_PATH = RULES_DIR / "ai_security.yaml"
CONVERTED_RULES_PATH = RULES_DIR / "converted" / "ai_security.yaml"
ML_TAINT_PATH = RULES_DIR / "ml_taint.yaml"
_RULES = load_neuroscan_rules(RULES_PATH)

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    """LEGACY engine (`ScanConfig.legacy_neuroscan=True`): NeuroScan's own
    per-line matcher with the windowed `sanitizers:` field."""
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _scan_converted(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    """CONVERTED engine (`ScanConfig.legacy_neuroscan=False`, the DEFAULT):
    the same rule compiled to Opengrep pattern-regex/pattern-not-regex and
    run through the real Opengrep binary."""
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [CONVERTED_RULES_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


def _scan_taint(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [ML_TAINT_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id]


class TestTntMl027TrainingSetPoisoning:
    """Item 1: user data reaching a training set with no schema validation."""

    def test_request_json_into_dataset_from_list_flagged(self, tmp_path):
        src = (
            "def upload():\n"
            "    record = request.json.get('example')\n"
            "    ds = Dataset.from_list([record])\n"
        )
        assert _scan_taint(tmp_path, "train.py", src, "TNT-ML-030")

    def test_request_json_into_trainer_train_dataset_flagged(self, tmp_path):
        src = (
            "def fine_tune():\n"
            "    record = request.json.get('example')\n"
            "    trainer = Trainer(model=model, train_dataset=record)\n"
        )
        assert _scan_taint(tmp_path, "trainer.py", src, "TNT-ML-030")

    def test_openai_fine_tune_upload_flagged(self, tmp_path):
        src = (
            "def upload():\n"
            "    upload = request.files.get('file')\n"
            "    openai.files.create(file=upload, purpose='fine-tune')\n"
        )
        assert _scan_taint(tmp_path, "openai_upload.py", src, "TNT-ML-030")

    def test_schema_validated_record_not_flagged(self, tmp_path):
        src = (
            "def upload():\n"
            "    record = request.json.get('example')\n"
            "    record = TrainingRecordSchema.model_validate(record)\n"
            "    ds = Dataset.from_list([record])\n"
        )
        assert _scan_taint(tmp_path, "train_safe.py", src, "TNT-ML-030") == []

    def test_hardcoded_dataset_not_flagged(self, tmp_path):
        src = (
            "def build():\n"
            "    ds = Dataset.from_list([{'text': 'a fixed example'}])\n"
        )
        assert _scan_taint(tmp_path, "static_train.py", src, "TNT-ML-030") == []


class TestNsAiml146AdapterUnpinnedSource:
    """Item 2 (explicitly called out as the highest-yield item in the issue)."""

    def test_peft_from_pretrained_no_revision_flagged(self, tmp_path):
        src = "adapter = PeftModel.from_pretrained(base_model, 'community/lora-adapter')\n"
        assert _scan(tmp_path, "adapter.py", src, "ns-aiml-146")
        assert _scan_converted(tmp_path, "adapter.py", src, "ns-aiml-146")

    def test_load_adapter_no_revision_flagged(self, tmp_path):
        src = "model.load_adapter('community/lora-adapter')\n"
        assert _scan(tmp_path, "load_adapter.py", src, "ns-aiml-146")
        assert _scan_converted(tmp_path, "load_adapter.py", src, "ns-aiml-146")

    def test_load_lora_weights_no_revision_flagged(self, tmp_path):
        src = "pipe.load_lora_weights('community/sd-lora')\n"
        assert _scan(tmp_path, "load_lora.py", src, "ns-aiml-146")
        assert _scan_converted(tmp_path, "load_lora.py", src, "ns-aiml-146")

    def test_pinned_revision_not_flagged(self, tmp_path):
        src = (
            "adapter = PeftModel.from_pretrained(\n"
            "    base_model, 'community/lora-adapter', revision='a1b2c3d4'\n"
            ")\n"
        )
        assert _scan(tmp_path, "adapter_pinned.py", src, "ns-aiml-146") == []
        assert _scan_converted(tmp_path, "adapter_pinned.py", src, "ns-aiml-146") == []

    def test_local_path_not_flagged(self, tmp_path):
        src = (
            "adapter = PeftModel.from_pretrained(\n"
            "    base_model, './local-adapters/reviewed-lora', local_files_only=True\n"
            ")\n"
        )
        assert _scan(tmp_path, "adapter_local.py", src, "ns-aiml-146") == []
        assert _scan_converted(tmp_path, "adapter_local.py", src, "ns-aiml-146") == []


class TestNsAiml147ModelMerging:
    """Item 3: merging launders provenance."""

    def test_add_weighted_adapter_flagged(self, tmp_path):
        src = "model.add_weighted_adapter(['a', 'b'], [0.5, 0.5], 'merged')\n"
        assert _scan(tmp_path, "merge.py", src, "ns-aiml-147")
        assert _scan_converted(tmp_path, "merge.py", src, "ns-aiml-147")

    def test_mergekit_run_merge_flagged(self, tmp_path):
        src = "from mergekit.merge import run_merge\nrun_merge(merge_config, out_path)\n"
        assert _scan(tmp_path, "mergekit_run.py", src, "ns-aiml-147")
        assert _scan_converted(tmp_path, "mergekit_run.py", src, "ns-aiml-147")

    def test_unrelated_dict_merge_not_flagged(self, tmp_path):
        src = "config = {**base_config, **overrides}\n"
        assert _scan(tmp_path, "config_merge.py", src, "ns-aiml-147") == []
        assert _scan_converted(tmp_path, "config_merge.py", src, "ns-aiml-147") == []


class TestNsAiml148AirflowParamInjection:
    """Item 4: same class as ns-cicd-003, applied to the ML orchestrator layer."""

    def test_dag_run_conf_into_bash_command_flagged(self, tmp_path):
        src = (
            "BashOperator(\n"
            "    task_id='train',\n"
            "    bash_command=\"python train.py --dataset {{ dag_run.conf['dataset_uri'] }}\",\n"
            ")\n"
        )
        assert _scan(tmp_path, "dag.py", src, "ns-aiml-148")
        assert _scan_converted(tmp_path, "dag.py", src, "ns-aiml-148")

    def test_xcom_pull_into_docker_command_flagged(self, tmp_path):
        src = (
            "DockerOperator(\n"
            "    task_id='train',\n"
            "    command=\"{{ ti.xcom_pull(task_ids='prep') }}\",\n"
            ")\n"
        )
        assert _scan(tmp_path, "docker_dag.py", src, "ns-aiml-148")
        assert _scan_converted(tmp_path, "docker_dag.py", src, "ns-aiml-148")

    def test_static_bash_command_not_flagged(self, tmp_path):
        src = "BashOperator(task_id='train', bash_command='python train.py --dataset /data/fixed.csv')\n"
        assert _scan(tmp_path, "dag_static.py", src, "ns-aiml-148") == []
        assert _scan_converted(tmp_path, "dag_static.py", src, "ns-aiml-148") == []

    def test_param_passed_via_env_not_flagged(self, tmp_path):
        """Passed through env: rather than interpolated into the script text
        -- the ns-cicd-003 fix guidance this rule mirrors."""
        src = (
            "BashOperator(\n"
            "    task_id='train',\n"
            "    bash_command='python train.py --dataset $DATASET_URI',\n"
            "    env={'DATASET_URI': \"{{ dag_run.conf['dataset_uri'] }}\"},\n"
            ")\n"
        )
        assert _scan(tmp_path, "dag_env.py", src, "ns-aiml-148") == []
        assert _scan_converted(tmp_path, "dag_env.py", src, "ns-aiml-148") == []


class TestNsAiml149ArtifactIntegrity:
    """Item 5: same fetch-without-verification shape as ns-aiml-060 (HF Hub)."""

    def test_wandb_use_artifact_no_hash_check_flagged(self, tmp_path):
        src = (
            "def load():\n"
            "    artifact = run.use_artifact('team/project/model:latest')\n"
            "    path = artifact.download()\n"
            "    model = torch.load(path)\n"
        )
        assert _scan(tmp_path, "wandb_load.py", src, "ns-aiml-149")
        assert _scan_converted(tmp_path, "wandb_load.py", src, "ns-aiml-149")

    def test_mlflow_download_artifacts_no_hash_check_flagged(self, tmp_path):
        src = "path = mlflow.artifacts.download_artifacts('runs:/abc123/model')\n"
        assert _scan(tmp_path, "mlflow_load.py", src, "ns-aiml-149")
        assert _scan_converted(tmp_path, "mlflow_load.py", src, "ns-aiml-149")

    def test_dvc_api_read_no_hash_check_flagged(self, tmp_path):
        src = "data = dvc.api.read('model.pkl', repo='https://example.com/repo')\n"
        assert _scan(tmp_path, "dvc_load.py", src, "ns-aiml-149")
        assert _scan_converted(tmp_path, "dvc_load.py", src, "ns-aiml-149")

    def test_download_with_verified_hash_compare_not_flagged(self, tmp_path):
        src = (
            "def load():\n"
            "    artifact = run.use_artifact('team/project/model:latest')\n"
            "    path = artifact.download()\n"
            "    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()\n"
            "    if digest != EXPECTED_DIGEST:\n"
            "        raise ValueError('artifact hash mismatch')\n"
            "    model = torch.load(path)\n"
        )
        assert _scan(tmp_path, "wandb_load_verified.py", src, "ns-aiml-149") == []
        assert _scan_converted(tmp_path, "wandb_load_verified.py", src, "ns-aiml-149") == []
