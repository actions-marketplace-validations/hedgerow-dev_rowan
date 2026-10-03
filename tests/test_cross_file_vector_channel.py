"""Second-order taint through a vector store / RAG index (#156, Phase D).

The vector channel generalizes the ORM second-order channel: a handler
ingests attacker-controlled documents into a vector store in one function,
and a *different* function retrieves them (no call edge between the two) and
feeds the retrieved text into a sink. The channel is coarse but gated on a
genuinely-tainted write ("armed"): framework code that only ever writes its
own parameters never arms it.
"""

from __future__ import annotations

import ast

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanConfig, ScanContext
from rowan.passes.cross_file import (
    CrossFilePass,
    _collect_vector_write_channels,
    _extract_functions,
    _is_vector_read_call,
    _is_vector_write_call,
)

# ---- unit: write arming -------------------------------------------------- #

def test_tainted_write_arms_channel():
    src = (
        "from flask import request\n"
        "def ingest():\n"
        "    doc = request.args.get('doc')\n"
        "    collection.add_documents([doc])\n"
    )
    assert _collect_vector_write_channels(ast.parse(src)) == {("__vector__", "collection")}


def test_tainted_document_metadata_and_content_both_arm_channel():
    metadata_src = (
        "from flask import request\n"
        "def ingest():\n"
        "    source = request.form.get('source')\n"
        "    docs = [Document(page_content='trusted', metadata={'source': source})]\n"
        "    vector_store.add_documents(docs)\n"
    )
    content_src = (
        "from flask import request\n"
        "def ingest():\n"
        "    content = request.form.get('content')\n"
        "    docs = [Document(page_content=content, metadata={'source': 'manual'})]\n"
        "    vector_store.add_documents(docs)\n"
    )
    expected = {("__vector__", "vector_store")}
    assert _collect_vector_write_channels(ast.parse(metadata_src)) == expected
    assert _collect_vector_write_channels(ast.parse(content_src)) == expected


def test_untainted_param_write_does_not_arm_channel():
    # Framework-style: writes a plain parameter, no known taint source -> the
    # channel must stay disarmed (this is what keeps langchain/llamaindex
    # internals from lighting it up project-wide).
    src = "def ingest(doc):\n    collection.add_documents([doc])\n"
    assert _collect_vector_write_channels(ast.parse(src)) == set()


def test_non_vector_write_method_does_not_arm():
    src = (
        "from flask import request\n"
        "def ingest():\n"
        "    doc = request.args.get('doc')\n"
        "    some_list.append(doc)\n"  # .append is not a vector write
    )
    assert _collect_vector_write_channels(ast.parse(src)) == set()


# ---- unit: read recognition ---------------------------------------------- #

def test_specific_read_methods_recognized():
    for expr in (
        "store.similarity_search(q)",
        "retriever.get_relevant_documents(q)",
        "vs.max_marginal_relevance_search(q)",
    ):
        assert _is_vector_read_call(ast.parse(expr, mode="eval").body), expr


def test_generic_read_requires_vector_receiver_hint():
    # `query`/`search` only count on a vector-hinted receiver.
    assert _is_vector_read_call(ast.parse("index.query(v)", mode="eval").body)
    assert _is_vector_read_call(ast.parse("vector_store.search(q)", mode="eval").body)
    assert not _is_vector_read_call(ast.parse("foo.query(v)", mode="eval").body)
    assert not _is_vector_read_call(ast.parse("d.search(q)", mode="eval").body)


# ---- unit: generic write recognition (STaint-motivated widening) --------- #

def test_specific_write_methods_recognized():
    for expr in (
        "collection.add_documents([doc])",
        "store.upsert(doc)",
        "vs.add_texts([doc])",
    ):
        assert _is_vector_write_call(ast.parse(expr, mode="eval").body), expr


def test_generic_write_requires_vector_receiver_hint():
    # A custom wrapper's .save()/.persist()/.ingest() -- not one of the
    # hardcoded LangChain-style method names -- only counts on a
    # vector-hinted receiver, same gating as the generic reads above.
    assert _is_vector_write_call(ast.parse("vector_store.save(doc)", mode="eval").body)
    assert _is_vector_write_call(ast.parse("my_collection.persist(doc)", mode="eval").body)
    assert _is_vector_write_call(ast.parse("index.ingest(doc)", mode="eval").body)
    assert not _is_vector_write_call(ast.parse("obj.save(doc)", mode="eval").body)
    assert not _is_vector_write_call(ast.parse("user.persist()", mode="eval").body)


def test_custom_wrapper_write_arms_channel():
    """End-to-end version of the unit check above: a custom wrapper class's
    .save() call, not one of the hardcoded SDK method names, still arms the
    channel when the receiver name hints at a vector store."""
    src = (
        "from flask import request\n"
        "def ingest():\n"
        "    doc = request.args.get('doc')\n"
        "    vector_store.save(doc)\n"
    )
    assert _collect_vector_write_channels(ast.parse(src)) == {("__vector__", "vector_store")}


# ---- end-to-end ---------------------------------------------------------- #

def _sink_finding(file_str: str, line: int) -> Finding:
    return Finding(
        rule_id="NS-CMDI-001", message="command injection", severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION, file_path=file_str, start_line=line,
        engine="neuroscan",
    )


def _line_with(root, rel, needle):
    for i, ln in enumerate((root / rel).read_text().splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(needle)


def _rag_project(tmp_path, *, poison: bool):
    """Three-file RAG app. `poison` toggles whether the ingest handler feeds a
    known taint source into the vector write (arming the channel) or writes an
    untainted constant (leaving it disarmed) -- the ONLY difference between the
    two, so any finding delta is attributable to the second-order channel."""
    write_val = "request.args.get('doc')" if poison else "'static seed doc'"
    (tmp_path / "ingest.py").write_text(
        "from flask import request\n"
        "def ingest():\n"
        f"    doc = {write_val}\n"
        "    collection.add_documents([doc])\n"
    )
    # retriever.py: retrieves from the store and forwards the retrieved text
    # to a sink helper in a THIRD file -- no call edge to ingest() at all.
    (tmp_path / "retriever.py").write_text(
        "from sink import run_cmd\n"
        "def answer(q):\n"
        "    docs = collection.similarity_search(q)\n"
        "    run_cmd(docs)\n"
    )
    (tmp_path / "sink.py").write_text(
        "import os\n"
        "def run_cmd(payload):\n"
        "    os.system(payload)\n"
    )
    sink = str((tmp_path / "sink.py").resolve())
    sink_line = _line_with(tmp_path, "sink.py", "os.system(")
    ctx = ScanContext(
        target_path=tmp_path, config=ScanConfig(target=tmp_path),
        result=ScanResult(findings=[_sink_finding(sink, sink_line)]),
    )
    return CrossFilePass().run(ctx).findings


def test_rag_poisoning_chain_emits_cross_file_finding(tmp_path):
    findings = _rag_project(tmp_path, poison=True)
    cf = [
        f for f in findings
        if f.engine == "crossfile" and f.metadata.get("callee_name") == "run_cmd"
    ]
    assert cf, "armed vector channel: retrieved text -> run_cmd() must be flagged"


def test_untainted_ingest_leaves_channel_disarmed_no_finding(tmp_path):
    """Control: identical app but the ingest writes a constant, so the channel
    never arms and the retrieval is not treated as a source -- no finding."""
    findings = _rag_project(tmp_path, poison=False)
    cf = [
        f for f in findings
        if f.engine == "crossfile" and f.metadata.get("callee_name") == "run_cmd"
    ]
    assert cf == [], "disarmed vector channel must not fabricate a finding"


def test_reader_becomes_source_only_when_armed(tmp_path):
    reader = "def load(q):\n    docs = store.similarity_search(q)\n    return docs\n"
    tree = ast.parse(reader)
    disarmed = _extract_functions("r.py", tree, vector_channels=set())
    armed = _extract_functions(
        "r.py", tree, vector_channels={("__vector__", "store")}
    )
    assert disarmed[0].has_source is False
    assert armed[0].has_source is True


def test_different_vector_receiver_does_not_cross_contaminate():
    reader = "def load(q):\n    docs = other_store.similarity_search(q)\n    return docs\n"
    funcs = _extract_functions(
        "r.py", ast.parse(reader), vector_channels={("__vector__", "store")}
    )
    assert funcs[0].has_source is False


def test_same_chroma_resource_pairs_across_different_receiver_names():
    writer = ast.parse(
        "import chromadb\n"
        "from flask import request\n"
        "from langchain_chroma import Chroma\n"
        "client = chromadb.PersistentClient(path='/srv/chroma')\n"
        "collection = Chroma(client=client, collection_name='handbook')\n"
        "def ingest():\n"
        "    collection.add_documents([request.form.get('doc')])\n"
    )
    reader = ast.parse(
        "import chromadb\n"
        "from langchain_chroma import Chroma\n"
        "client = chromadb.PersistentClient(path='/srv/chroma')\n"
        "vector_store = Chroma(client=client, collection_name='handbook')\n"
        "def load(q):\n"
        "    docs = vector_store.similarity_search(q)\n"
        "    return docs\n"
    )
    channels = _collect_vector_write_channels(writer)
    funcs = _extract_functions("reader.py", reader, vector_channels=channels)
    assert channels == {("__vector__", "chroma", "/srv/chroma", "handbook")}
    assert funcs[0].has_source is True


def test_same_receiver_name_does_not_pair_different_chroma_resources():
    writer = ast.parse(
        "import chromadb\n"
        "from flask import request\n"
        "from langchain_chroma import Chroma\n"
        "client = chromadb.PersistentClient(path='/srv/chroma')\n"
        "vector_store = Chroma(client=client, collection_name='poisoned')\n"
        "def ingest():\n"
        "    vector_store.add_documents([request.form.get('doc')])\n"
    )
    reader = ast.parse(
        "import chromadb\n"
        "from langchain_chroma import Chroma\n"
        "client = chromadb.PersistentClient(path='/srv/chroma')\n"
        "vector_store = Chroma(client=client, collection_name='trusted')\n"
        "def load(q):\n"
        "    docs = vector_store.similarity_search(q)\n"
        "    return docs\n"
    )
    funcs = _extract_functions(
        "reader.py", reader, vector_channels=_collect_vector_write_channels(writer)
    )
    assert funcs[0].has_source is False
