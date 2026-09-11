"""Prefetch changes wall time and nothing else.

The prefetcher speculates DNS lookups in parallel while evaluation proceeds
sequentially. These tests hold the promise that matters: with prefetch on,
verdict, term count, void count and evaluation order are identical to a
sequential run, and a speculation failure can cost speed but never the answer.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time

import pytest

from spftrace import Evaluator, Limits, ZoneResolver

from . import corpus

try:
    CASES = corpus.load_cases()
except Exception:  # unavailable; test_rfc7208 reports the reason
    CASES = []


# The events that describe *what the evaluator decided*, as opposed to
# timing or provenance. These must match between the two modes exactly.
DECISION_KINDS = {
    "check_start", "txt_lookup", "policy_parsed", "parse_error", "mech_start",
    "mech_match", "mech_nomatch", "recurse_in", "recurse_out", "eval_done",
    "exit", "limit_exceeded", "void_lookup", "family_skip", "exists_miss",
    "mx_match", "ptr_validated", "target_invalid", "domain_invalid",
    "audit_override", "exp", "macro_expand", "dns_lookup",
}
TIMING_FIELDS = {"at_ms", "ms", "source"}


def _decisions(result):
    return [
        {k: v for k, v in ev.items() if k not in TIMING_FIELDS}
        for ev in result.trace.to_list()
        if ev["kind"] in DECISION_KINDS
    ]


def _run(zone, ip, sender, helo="", *, resolver=None, **limit_kw):
    async def go():
        ev = Evaluator(resolver or ZoneResolver(zone), Limits(**limit_kw))
        return await ev.evaluate(ip, sender, helo)

    return asyncio.run(go())


def _both(zone, ip, sender, helo="", **limit_kw):
    return (
        _run(zone, ip, sender, helo, prefetch=False, **limit_kw),
        _run(zone, ip, sender, helo, prefetch=True, **limit_kw),
    )


class SlowZoneResolver(ZoneResolver):
    """A zone with a fixed per-lookup latency, so parallelism is measurable."""

    def __init__(self, zone, delay: float) -> None:
        super().__init__(zone)
        self.delay = delay
        self.calls = 0

    async def _lookup(self, name, rtype):
        self.calls += 1
        await asyncio.sleep(self.delay)
        return await super()._lookup(name, rtype)


# --- the decisive test: the whole RFC corpus, both ways -----------------------


@pytest.mark.parametrize(
    "description,name,body,zone",
    CASES,
    ids=[f"{d}-{n}" for d, n, _, _ in CASES],
)
def test_prefetch_matches_sequential_on_the_rfc_corpus(description, name, body, zone):
    """Every conformance case, evaluated with and without prefetch, must
    agree on the verdict, the explanation, both counters and the full
    sequence of evaluation decisions."""
    seq, pre = _both(zone, body["host"], body.get("mailfrom", ""), body.get("helo", ""))

    assert pre.result == seq.result, f"[{description}] {name}: verdict diverged"
    assert pre.explanation == seq.explanation, f"[{description}] {name}: explanation"
    assert pre.dns_terms_used == seq.dns_terms_used, f"[{description}] {name}: terms"
    assert pre.void_lookups_used == seq.void_lookups_used, f"[{description}] {name}: voids"
    assert _decisions(pre) == _decisions(seq), (
        f"[{description}] {name}: evaluation order or decisions diverged"
    )
    assert pre.prefetch is not None and seq.prefetch is None


# --- the two accounting rules -------------------------------------------------


def test_void_lookups_served_from_prefetch_still_count():
    """The trap. A prefetched answer served as a cache hit would stop voids
    counting and turn this permerror into a fail."""
    zone = {
        "d.test": [("TXT", "v=spf1 exists:gone-a.test exists:gone-b.test "
                           "exists:gone-c.test -all")],
    }
    seq, pre = _both(zone, "1.2.3.4", "u@d.test")

    assert seq.result == "permerror"
    assert pre.result == "permerror", "prefetch hid the third void"
    assert pre.void_lookups_used == seq.void_lookups_used == 3
    served = [q for q in pre.queries if q.source == "prefetch"]
    assert served, "nothing was actually served from prefetch, test is vacuous"
    assert all(q.void for q in served if q.rtype == "A")


def test_speculative_traffic_never_touches_the_evaluation_budget():
    """A record that matches at its first term needs one lookup. The tree
    behind it may be far larger than the budget. Speculating it must neither
    trip the budget nor change the verdict."""
    wide = " ".join(f"a:h{i}.test" for i in range(30))
    zone = {
        "d.test": [("TXT", "v=spf1 ip4:1.2.3.4 include:wide.test -all")],
        "wide.test": [("TXT", f"v=spf1 {wide} -all")],
        **{f"h{i}.test": [("A", f"10.0.0.{i}")] for i in range(30)},
    }
    seq, pre = _both(zone, "1.2.3.4", "u@d.test", max_queries=5)

    assert seq.result == pre.result == "pass"
    for r in (seq, pre):
        assert len([q for q in r.queries if q.source != "cache"]) == 1
    assert pre.prefetch.issued <= 5, "the prefetcher must honour its own cap"


# --- the point of it -----------------------------------------------------------


def test_a_wide_include_is_taken_in_parallel():
    """Five sibling includes: sequential is six round trips deep, prefetch is
    two. The verdict is the same either way."""
    delay = 0.03
    zone = {
        "d.test": [("TXT", "v=spf1 " + " ".join(
            f"include:r{i}.test" for i in range(5)) + " -all")],
        **{f"r{i}.test": [("TXT", f"v=spf1 ip4:10.0.0.{i} -all")] for i in range(5)},
    }

    def timed(prefetch):
        resolver = SlowZoneResolver(zone, delay)
        t0 = time.monotonic()
        result = _run(zone, "9.9.9.9", "u@d.test", resolver=resolver, prefetch=prefetch)
        return result, time.monotonic() - t0, resolver.calls

    seq, seq_wall, seq_calls = timed(False)
    pre, pre_wall, pre_calls = timed(True)

    assert seq.result == pre.result == "fail"
    assert seq_calls == 6
    assert seq_wall >= 6 * delay * 0.9
    # Root TXT, then five in parallel: two round trips, with slack for the loop.
    assert pre_wall < 6 * delay * 0.6, (
        f"prefetch took {pre_wall*1000:.0f} ms against sequential "
        f"{seq_wall*1000:.0f} ms; no parallelism happened"
    )
    # Best-effort: the five deep TXTs are what the parallelism is for, and they
    # are served from prefetch. Whether the root TXT itself is claimed from
    # prefetch or raced to a live lookup is a wash on wall time; don't pin it.
    assert pre.prefetch.served >= 5
    assert pre.prefetch.unused <= 1


def test_prefetched_answers_are_marked_as_such():
    zone = {
        "d.test": [("TXT", "v=spf1 a:h.test include:i.test -all")],
        "h.test": [("A", "10.0.0.1")],
        "i.test": [("TXT", "v=spf1 ip4:10.0.0.2 -all")],
    }
    pre = _run(zone, "9.9.9.9", "u@d.test", prefetch=True)

    sources = {(q.name, q.rtype): q.source for q in pre.queries}
    # The root TXT is claimed before the prefetcher's task has run, so it is
    # served from prefetch too: the session found a task in flight.
    assert sources[("d.test", "TXT")] == "prefetch"
    assert sources[("h.test", "A")] == "prefetch"
    assert sources[("i.test", "TXT")] == "prefetch"
    kinds = [e["kind"] for e in pre.trace.to_list()]
    assert kinds.index("prefetch_start") < kinds.index("check_start")
    assert "prefetch_done" in kinds
    assert pre.to_dict()["prefetch"]["served"] == 3


# --- failure is only ever slow, never wrong -----------------------------------


class FlakyOnceResolver(ZoneResolver):
    """Raises a non-DNS exception the first time a given name is looked up —
    the shape a speculation bug would take. The retry (the evaluator's live
    lookup) succeeds, so a correct fallback yields the right verdict."""

    def __init__(self, zone, poison: str) -> None:
        super().__init__(zone)
        self.poison = poison
        self.tripped = False

    async def _lookup(self, name, rtype):
        if name.rstrip(".") == self.poison and not self.tripped:
            self.tripped = True
            raise RuntimeError("simulated defect in speculative lookup")
        return await super()._lookup(name, rtype)


def test_a_speculation_defect_falls_back_to_a_live_lookup():
    """A prefetch task that dies of something other than DNS must not decide
    the verdict. The evaluator claims it, the failure surfaces, and it does
    the lookup live instead — costing latency, never correctness."""
    zone = {
        "d.test": [("TXT", "v=spf1 include:i.test -all")],
        "i.test": [("TXT", "v=spf1 ip4:1.2.3.4 -all")],
    }
    resolver = FlakyOnceResolver(zone, poison="i.test")
    pre = _run(zone, "1.2.3.4", "u@d.test", resolver=resolver, prefetch=True)

    assert resolver.tripped, "the poisoned lookup was never speculated"
    assert pre.result == "pass", "a prefetch failure changed the verdict"


def test_a_dns_failure_in_prefetch_is_the_same_temperror_as_live():
    zone = {
        "d.test": [("TXT", "v=spf1 include:i.test -all")],
        "i.test": "TIMEOUT",
    }
    seq, pre = _both(zone, "1.2.3.4", "u@d.test")
    assert seq.result == pre.result == "temperror"


def test_policy_override_is_speculated_without_a_root_txt_lookup():
    zone = {"i.test": [("TXT", "v=spf1 ip4:1.2.3.4 -all")]}

    async def go():
        ev = Evaluator(
            ZoneResolver(zone), Limits(prefetch=True),
            policy_override="v=spf1 include:i.test -all",
        )
        return await ev.evaluate("1.2.3.4", "u@d.test")

    pre = asyncio.run(go())
    assert pre.result == "pass"
    assert ("d.test", "TXT") not in {(q.name, q.rtype) for q in pre.queries}
    assert pre.prefetch.issued == 1, "only the include should have been speculated"


def test_nothing_is_left_running_after_the_verdict():
    """The prefetcher is cancelled the moment evaluation ends. A verdict must
    not leave DNS traffic trailing behind it. An `ip4` at the root matches the
    instant the root TXT lands — before any of the ten includes it also names
    can resolve — so those ten are in flight and get cut off."""
    zone = {
        "d.test": [("TXT", "v=spf1 ip4:1.2.3.4 " + " ".join(
            f"include:r{i}.test" for i in range(10)) + " -all")],
        **{f"r{i}.test": [("TXT", f"v=spf1 ip4:9.9.9.{i} -all")] for i in range(10)},
    }

    async def go():
        resolver = SlowZoneResolver(zone, 0.05)
        result = await Evaluator(resolver, Limits(prefetch=True)).evaluate(
            "1.2.3.4", "u@d.test"
        )
        others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        return result, others

    result, others = asyncio.run(go())
    assert result.result == "pass"  # ip4:1.2.3.4 matches at the root
    assert not others, f"{len(others)} prefetch task(s) still alive after evaluate()"
    # The ten include TXTs were issued and in flight when the verdict landed.
    assert result.prefetch.cancelled >= 1, "expected in-flight speculation to be cut"


def test_prefetch_is_off_by_default():
    zone = {"d.test": [("TXT", "v=spf1 ip4:1.2.3.4 -all")]}
    result = _run(zone, "1.2.3.4", "u@d.test")
    assert result.prefetch is None
    assert all(q.source != "prefetch" for q in result.queries)
    assert result.to_dict()["prefetch"] is None
