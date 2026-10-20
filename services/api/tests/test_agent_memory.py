"""Episodic memory (pure half): deterministic embeddings, recall, prioritisation."""
from __future__ import annotations

from app.agent.memory import (
    EMBED_DIM,
    cosine,
    embed,
    host_of,
    prior_productive_tools,
    recall,
    record_from_finding,
)


def test_host_of_drops_path_and_lowercases() -> None:
    assert host_of("http://Target:9000/a/b?x=1") == "http://target:9000"
    assert host_of("https://api.example.com/v1") == "https://api.example.com"


def test_embed_is_deterministic_and_normalised() -> None:
    a = embed("bola on /widgets/{id}")
    b = embed("bola on /widgets/{id}")
    assert a == b
    assert len(a) == EMBED_DIM
    assert abs(sum(v * v for v in a) - 1.0) < 1e-9
    assert embed("") == [0.0] * EMBED_DIM


def test_cosine_ranks_similar_text_higher() -> None:
    q = embed("sql injection on search query parameter")
    near = embed("sql injection on the search parameter")
    far = embed("missing content security policy header")
    assert cosine(q, near) > cosine(q, far)
    assert cosine([], q) == 0.0


def test_record_needs_a_fingerprint() -> None:
    assert record_from_finding(
        fingerprint="", check="bola", severity="high", confidence="verified", title="x"
    ) is None
    rec = record_from_finding(
        fingerprint="fp1",
        check="bola",
        severity="high",
        confidence="verified",
        title="BOLA on /widgets/{id}",
        evidence={"route": "/widgets/{id}", "param": "id"},
    )
    assert rec is not None and rec.fingerprint == "fp1"
    assert len(rec.embedding) == EMBED_DIM
    assert rec.to_dict()["check"] == "bola"


def test_recall_ranks_by_similarity_and_respects_min_score() -> None:
    rows = [
        {"fingerprint": "f1", "check": "sqlmap_confirm", "hits": 1,
         "embedding": embed("sql injection search query")},
        {"fingerprint": "f2", "check": "security_headers", "hits": 1,
         "embedding": embed("missing hsts header")},
    ]
    got = recall(rows, "sql injection on the search parameter", min_score=0.1)
    assert got and got[0]["fingerprint"] == "f1"
    assert "embedding" not in got[0] and "score" in got[0]


def test_recall_without_query_falls_back_to_hits() -> None:
    rows = [
        {"fingerprint": "f1", "check": "bola", "hits": 5, "embedding": []},
        {"fingerprint": "f2", "check": "bfla", "hits": 2, "embedding": []},
    ]
    got = recall(rows, "")
    assert [r["fingerprint"] for r in got] == ["f1", "f2"]


def test_prior_productive_tools_maps_checks() -> None:
    recalls = [
        {"check": "reflected_injection"},
        {"check": "kali_nuclei"},
        {"check": "security_headers"},
    ]
    assert prior_productive_tools(recalls) == {"sqlmap", "nuclei"}
