"""Fetch and verify the official RFC 7208 test corpus.

The corpus is not vendored. It is fetched from an immutable commit URL and its
sha256 is verified, so the gate cannot shift under us the way a `master` URL
can, and we do not inherit the upstream file's licensing into this repo.

To refresh: change PINNED_COMMIT, run the suite, and update EXPECTED_SHA256 and
EXPECTED_CASES to whatever the new corpus actually produces. Never update the
hash without re-reading the diff.
"""
from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path

PINNED_COMMIT = "1042e9e15dd29047dc9b0a1bb77437e2fd81e775"
CORPUS_URL = (
    "https://raw.githubusercontent.com/sdgathman/pyspf/"
    f"{PINNED_COMMIT}/test/rfc7208-tests.yml"
)
EXPECTED_SHA256 = "901f561a6e2b1c1590a40a61b1ac7601226fd7045a7aae591a4d25421358d6f9"
EXPECTED_CASES = 203

CACHE = Path(__file__).parent / ".corpus-cache" / f"rfc7208-{PINNED_COMMIT[:12]}.yml"


class CorpusUnavailable(Exception):
    """Corpus could not be fetched. Distinct from a corpus that fails its hash."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def corpus_bytes() -> bytes:
    """Return the corpus, from cache or the network, hash-checked either way.

    SPFTRACE_RFC_CORPUS overrides the source with a local path, for offline or
    air-gapped runs. It is still hash-checked.
    """
    override = os.environ.get("SPFTRACE_RFC_CORPUS")
    if override:
        data = Path(override).read_bytes()
        _verify(data, f"local file {override}")
        return data

    if CACHE.exists():
        data = CACHE.read_bytes()
        if _digest(data) == EXPECTED_SHA256:
            return data
        CACHE.unlink()  # poisoned cache, refetch rather than trust it

    try:
        with urllib.request.urlopen(CORPUS_URL, timeout=30) as resp:
            data = resp.read()
    except Exception as exc:  # network, DNS, proxy, 404
        raise CorpusUnavailable(f"{CORPUS_URL}: {exc}") from exc

    _verify(data, CORPUS_URL)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_bytes(data)
    return data


def _verify(data: bytes, source: str) -> None:
    got = _digest(data)
    if got != EXPECTED_SHA256:
        raise AssertionError(
            f"RFC 7208 corpus from {source} does not match the pinned hash.\n"
            f"  expected {EXPECTED_SHA256}\n  got      {got}\n"
            "Refusing to run: the gate must not change silently."
        )


def build_zone(zonedata: dict) -> dict:
    """Translate the suite's zonedata into our resolver's zone format.

    Driver conventions in the suite:
      "TIMEOUT" as a bare list item  -> any type not otherwise present times out
      value "NONE"                   -> that type exists but returns no data
      type SPF (RR 99)               -> obsolete; duplicated to TXT only when the
                                        name has no TXT key at all
    """
    zone: dict = {}
    for name, recs in zonedata.items():
        if recs == "TIMEOUT" or recs == ["TIMEOUT"]:
            zone[name] = "TIMEOUT"
            continue
        out = []
        txt_key_seen = False
        for r in recs:
            if r == "TIMEOUT":
                out.append(("*", "TIMEOUT"))
                continue
            for rtype, val in r.items():
                if rtype == "TXT":
                    txt_key_seen = True
                if val == "NONE":
                    continue
                if rtype in ("TXT", "SPF"):
                    if isinstance(val, list):
                        val = "".join(str(v) for v in val)
                    out.append((rtype, str(val)))
                elif rtype == "MX":
                    out.append(("MX", str(val[1])))
                else:
                    out.append((rtype, str(val)))
        has_txt = any(t == "TXT" for t, _ in out)
        wildcard = any(t == "*" for t, _ in out)
        if not has_txt and not wildcard and not txt_key_seen:
            out += [("TXT", v) for t, v in out if t == "SPF"]
        zone[name] = out
    return zone


def load_cases() -> list[tuple[str, str, dict, dict]]:
    """Return (description, test_name, test_body, zone) for every case."""
    import yaml

    docs = list(yaml.safe_load_all(corpus_bytes().decode("utf-8")))
    cases = []
    for doc in docs:
        zone = build_zone(doc["zonedata"])
        for tname, body in doc["tests"].items():
            cases.append((doc["description"], tname, body, zone))
    return cases
