"""Document/media ingestion channel (issue #191, epic #183).

Indirect prompt injection through documents is the dominant real-world
delivery vector, and none of OCR/PDF/EXIF/transcript/office-loader output
was previously a taint source. This closes that gap:

  TNT-ML-033   document_ingest content reaching a completion/agent call
               with no delimiter-fencing/moderation/schema/classifier.
  TNT-ML-034   document_ingest content reaching a vector-store WRITE
               (poisoning-at-rest, as opposed to NS-AIML-015's raw-insert
               presence signal).
  TNT-ML-035   a request-controlled URL assembled into a multimodal
               image_url/input_audio message part -- SSRF + injection in
               one shape. (ID chosen to match the corpus's own mode:taint
               convention rather than the issue's suggested "ns-aiml-151",
               same call this project made for ns-aiml-149 in #190.)
  ns-aiml-107  extended to text/json (fixture/corpus files) -- the
               Unicode-Tags-block detector has no legitimate-use false
               positive risk in any file type, unlike ns-aiml-108
               (zero-width/bidi), deliberately NOT extended for the same
               CJK/RTL prose reason its own comment already documents.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.rules import load_neuroscan_rules
from rowan.passes.file_scan import LANGUAGE_EXTENSIONS
from rowan.pipeline import ScanPipeline
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
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _scan_converted(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [CONVERTED_RULES_PATH],
        languages=["python", "javascript", "typescript", "ai_instructions", "markdown", "text", "json"],
    )
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


def _scan_taint(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [ML_TAINT_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id]


class TestTntMl028DocumentToPromptInjection:
    """TP per ingestion shape (OCR, PDF, EXIF, transcript, HTML loader)."""

    def test_ocr_output_into_chat_completion_flagged(self, tmp_path):
        src = (
            "def handle_upload(image_path):\n"
            "    text = pytesseract.image_to_string(image_path)\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4', messages=[{'role': 'user', 'content': text}],\n"
            "    )\n"
        )
        assert _scan_taint(tmp_path, "ocr.py", src, "TNT-ML-033")

    def test_pdf_text_layer_into_agent_run_flagged(self, tmp_path):
        src = (
            "def handle_upload(pdf_path):\n"
            "    reader = PdfReader(pdf_path)\n"
            "    text = reader.pages[0].extract_text()\n"
            "    return agent.run(text)\n"
        )
        assert _scan_taint(tmp_path, "pdf_ingest.py", src, "TNT-ML-033")

    def test_exif_metadata_into_completion_flagged(self, tmp_path):
        src = (
            "def caption(image_path):\n"
            "    img = Image.open(image_path)\n"
            "    meta = img._getexif()\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4', messages=[{'role': 'user', 'content': str(meta)}],\n"
            "    )\n"
        )
        assert _scan_taint(tmp_path, "exif.py", src, "TNT-ML-033")

    def test_audio_transcript_into_completion_flagged(self, tmp_path):
        src = (
            "def handle_voice_note(audio_path):\n"
            "    transcript = client.audio.transcriptions.create(file=audio_path, model='whisper-1')\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4', messages=[{'role': 'user', 'content': transcript}],\n"
            "    )\n"
        )
        assert _scan_taint(tmp_path, "transcript.py", src, "TNT-ML-033")

    def test_html_loader_into_chain_invoke_flagged(self, tmp_path):
        src = (
            "def summarize(url):\n"
            "    docs = BSHTMLLoader(url).load()\n"
            "    return chain.invoke(docs)\n"
        )
        assert _scan_taint(tmp_path, "html_loader.py", src, "TNT-ML-033")

    def test_structured_extraction_schema_not_flagged(self, tmp_path):
        src = (
            "def handle_upload(image_path):\n"
            "    text = pytesseract.image_to_string(image_path)\n"
            "    text = InvoiceSchema.model_validate_json(text)\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4', messages=[{'role': 'user', 'content': str(text)}],\n"
            "    )\n"
        )
        assert _scan_taint(tmp_path, "ocr_safe_schema.py", src, "TNT-ML-033") == []

    def test_delimiter_fenced_not_flagged(self, tmp_path):
        src = (
            "def handle_upload(image_path):\n"
            "    text = pytesseract.image_to_string(image_path)\n"
            "    text = f\"<document>{text}</document>\"\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4', messages=[{'role': 'user', 'content': text}],\n"
            "    )\n"
        )
        assert _scan_taint(tmp_path, "ocr_safe_fenced.py", src, "TNT-ML-033") == []

    def test_moderation_gate_not_flagged(self, tmp_path):
        src = (
            "def handle_upload(pdf_path):\n"
            "    reader = PdfReader(pdf_path)\n"
            "    text = reader.pages[0].extract_text()\n"
            "    text = moderation(text)\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4', messages=[{'role': 'user', 'content': text}],\n"
            "    )\n"
        )
        assert _scan_taint(tmp_path, "pdf_safe_moderated.py", src, "TNT-ML-033") == []


class TestTntMl029DocumentToVectorStoreWrite:
    """Poisoning-at-rest: pairs with TNT-ML-016's memory read-back."""

    def test_ocr_output_into_add_texts_flagged(self, tmp_path):
        src = (
            "def ingest(image_path):\n"
            "    text = pytesseract.image_to_string(image_path)\n"
            "    vectorstore.add_texts([text])\n"
        )
        assert _scan_taint(tmp_path, "ocr_ingest.py", src, "TNT-ML-034")

    def test_pdf_text_into_chroma_collection_add_flagged(self, tmp_path):
        src = (
            "def ingest(pdf_path):\n"
            "    reader = PdfReader(pdf_path)\n"
            "    text = reader.pages[0].extract_text()\n"
            "    collection.add(documents=[text], ids=['doc1'])\n"
        )
        assert _scan_taint(tmp_path, "pdf_chroma_ingest.py", src, "TNT-ML-034")

    def test_pinecone_index_upsert_flagged(self, tmp_path):
        src = (
            "def ingest(pdf_path):\n"
            "    reader = PdfReader(pdf_path)\n"
            "    text = reader.pages[0].extract_text()\n"
            "    index.upsert(vectors=[(text, embed(text))])\n"
        )
        assert _scan_taint(tmp_path, "pinecone_ingest.py", src, "TNT-ML-034")

    def test_moderated_before_write_not_flagged(self, tmp_path):
        src = (
            "def ingest(image_path):\n"
            "    text = pytesseract.image_to_string(image_path)\n"
            "    text = moderation(text)\n"
            "    vectorstore.add_texts([text])\n"
        )
        assert _scan_taint(tmp_path, "ocr_ingest_safe.py", src, "TNT-ML-034") == []

    def test_document_text_never_reaching_a_model_not_flagged(self, tmp_path):
        """Written to a database and never reaching a model or vector store."""
        src = (
            "def archive(pdf_path):\n"
            "    reader = PdfReader(pdf_path)\n"
            "    text = reader.pages[0].extract_text()\n"
            "    db.session.add(ArchivedDocument(body=text))\n"
            "    db.session.commit()\n"
        )
        assert _scan_taint(tmp_path, "archive_only.py", src, "TNT-ML-034") == []


class TestTntMl030MultimodalRemoteUrl:
    """SSRF + injection in one shape -- the model provider is the fetching agent."""

    def test_request_controlled_image_url_into_vision_message_flagged(self, tmp_path):
        src = (
            "def handle_upload():\n"
            "    url = request.json.get('image_url')\n"
            "    part = {'type': 'image_url', 'image_url': {'url': url}}\n"
        )
        assert _scan_taint(tmp_path, "vision_msg.py", src, "TNT-ML-035")

    def test_allowlisted_url_not_flagged(self, tmp_path):
        src = (
            "def handle_upload():\n"
            "    url = request.json.get('image_url')\n"
            "    url = validate_url(url)\n"
            "    part = {'type': 'image_url', 'image_url': {'url': url}}\n"
        )
        assert _scan_taint(tmp_path, "vision_msg_safe.py", src, "TNT-ML-035") == []

    def test_hardcoded_url_not_flagged(self, tmp_path):
        src = (
            "def build():\n"
            "    part = {'type': 'image_url', 'image_url': {'url': 'https://cdn.example.com/logo.png'}}\n"
        )
        assert _scan_taint(tmp_path, "vision_msg_static.py", src, "TNT-ML-035") == []


class TestNsAiml107ExtendedToFixtureFiles:
    """Item 5: text/json fixture/corpus coverage. json/text carried no legitimate
    Tags-block use before -- same reasoning as the existing markdown wiring."""

    def test_text_and_json_now_real_discovery_keys(self):
        assert "text" in LANGUAGE_EXTENSIONS
        assert ".txt" in LANGUAGE_EXTENSIONS["text"]
        assert "json" in LANGUAGE_EXTENSIONS
        assert ".json" in LANGUAGE_EXTENSIONS["json"]

    def test_txt_fixture_with_tags_block_flagged_via_check(self, tmp_path):
        src = "innocuous corpus line\U000E0041\U000E0042 hidden instruction\n"
        assert _scan(tmp_path, "corpus.txt", src, "ns-aiml-107")
        assert _scan_converted(tmp_path, "corpus.txt", src, "ns-aiml-107")

    def test_json_fixture_with_tags_block_flagged_via_check(self, tmp_path):
        src = '{"text": "innocuous\U000E0041\U000E0042 hidden instruction"}\n'
        assert _scan(tmp_path, "corpus.json", src, "ns-aiml-107")
        assert _scan_converted(tmp_path, "corpus.json", src, "ns-aiml-107")

    def test_end_to_end_pipeline_discovers_txt_corpus_file(self, tmp_path):
        """Full ScanPipeline discovery, not just NeuroScanRule.check() directly
        -- proves the file-discovery layer actually walks .txt files now,
        not merely that the regex matches when handed a file manually."""
        (tmp_path / "seeded_corpus.txt").write_text(
            "innocuous corpus line\U000E0041\U000E0042 hidden instruction\n",
            encoding="utf-8",
        )
        result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, no_taint=True)).run()
        assert any(f.rule_id == "ns-aiml-107" for f in result.findings)

    def test_clean_txt_corpus_file_not_flagged(self, tmp_path):
        (tmp_path / "seeded_corpus.txt").write_text(
            "ordinary corpus line with no smuggled characters\n", encoding="utf-8",
        )
        result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, no_taint=True)).run()
        assert not any(f.rule_id == "ns-aiml-107" for f in result.findings)
