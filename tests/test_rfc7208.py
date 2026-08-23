"""The official openspf.org RFC 7208 corpus, one pytest case per test.

This is the release gate. All EXPECTED_CASES must pass.
"""
from __future__ import annotations

import asyncio

import pytest

from spftrace import Evaluator, Limits, ZoneResolver

from . import corpus

try:
    CASES = corpus.load_cases()
    LOAD_ERROR: Exception | None = None
except Exception as exc:  # unavailable, bad hash, or missing pyyaml
    CASES = []
    LOAD_ERROR = exc


def test_corpus_loaded(rfc_strict):
    if LOAD_ERROR is not None:
        msg = f"RFC 7208 corpus unavailable: {LOAD_ERROR}"
        if rfc_strict or not isinstance(LOAD_ERROR, corpus.CorpusUnavailable):
            pytest.fail(msg)
        pytest.skip(msg)
    assert len(CASES) == corpus.EXPECTED_CASES, (
        f"expected {corpus.EXPECTED_CASES} cases, found {len(CASES)}. "
        "The pinned corpus changed shape."
    )


@pytest.mark.parametrize(
    "description,name,body,zone",
    CASES,
    ids=[f"{d}-{n}" for d, n, _, _ in CASES],
)
def test_rfc_case(description, name, body, zone):
    expected = body["result"]
    expected = expected if isinstance(expected, list) else [expected]

    evaluator = Evaluator(ZoneResolver(zone), Limits())
    result = asyncio.run(
        evaluator.evaluate(body["host"], body.get("mailfrom", ""), body.get("helo", ""))
    )

    assert result.result in expected, (
        f"[{description}] {name}: want {expected}, got {result.result} "
        f"(spec {body.get('spec')})"
    )
    if "explanation" in body and result.explanation is not None:
        assert result.explanation == body["explanation"], (
            f"[{description}] {name}: explanation mismatch (spec {body.get('spec')})"
        )
