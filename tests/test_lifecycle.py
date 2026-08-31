"""State-lifetime and isolation tests.

The RFC 7208 corpus validates SPF language semantics and final verdicts. It
constructs fresh state per case, so it cannot see state leaking between two
independent evaluations. These tests cover that gap: what one check does must
never change what an unrelated later check decides.

Written against 0.1.1 to demonstrate the defects before 0.2.0 fixes them.
"""
from __future__ import annotations

import asyncio
from importlib.metadata import version

import pytest

import spftrace
from spftrace import Evaluator, Limits, ZoneResolver

# A domain whose record needs two void lookups, and an unrelated domain that
# passes cleanly on its own. Evaluating the first must not poison the second.
VOID_ZONE: dict[str, object] = {
    "noisy.test": [("TXT", "v=spf1 exists:gone-a.test exists:gone-b.test ?all")],
    "quiet.test": [("TXT", "v=spf1 exists:gone-c.test ip4:1.2.3.4 -all")],
    # gone-a/b/c deliberately absent: each lookup is NXDOMAIN, i.e. a void.
}

BUDGET_ZONE: dict[str, object] = {
    "wide.test": [("TXT", "v=spf1 a:h1.test a:h2.test a:h3.test ?all")],
    "narrow.test": [("TXT", "v=spf1 ip4:9.9.9.9 -all")],
    "h1.test": [("A", "10.0.0.1")],
    "h2.test": [("A", "10.0.0.2")],
    "h3.test": [("A", "10.0.0.3")],
}


async def _check(resolver, sender, ip="1.2.3.4", **limit_kw):
    return await Evaluator(resolver, Limits(**limit_kw)).evaluate(ip, sender)


# --- 1-3: void budget is per evaluation ------------------------------------


def test_void_budget_is_not_inherited_from_a_previous_check():
    """Review finding 1. A prior check's voids must not permerror a later one."""

    async def run():
        baseline = await _check(ZoneResolver(VOID_ZONE), "u@quiet.test")
        shared = ZoneResolver(VOID_ZONE)
        await _check(shared, "u@noisy.test")
        reused = await _check(shared, "u@quiet.test")
        return baseline.result, reused.result

    baseline, reused = asyncio.run(run())
    assert baseline == "pass", "sanity: quiet.test passes in isolation"
    assert reused == baseline, (
        "quiet.test changed verdict because noisy.test's void count leaked "
        "through the shared resolver"
    )


def test_void_counter_starts_at_zero_for_each_evaluation():
    """Review finding 3 (state half). The reported void count must be per check."""

    async def run():
        shared = ZoneResolver(VOID_ZONE)
        await _check(shared, "u@noisy.test")
        return await _check(shared, "u@quiet.test")

    result = asyncio.run(run())
    assert result.void_lookups_used == 1, (
        f"quiet.test performs exactly one void lookup, reported "
        f"{result.void_lookups_used}"
    )


# --- 4: network query budget is per evaluation -----------------------------


def test_network_query_budget_is_not_consumed_by_a_previous_check():
    """Review finding 1. max_queries is a per-message cap, not a lifetime cap."""

    async def run():
        # wide.test costs exactly four network queries (TXT + three A records),
        # so a budget of four is spent precisely by the first check.
        shared = ZoneResolver(BUDGET_ZONE)
        await _check(shared, "u@wide.test", max_queries=4)
        return await _check(shared, "u@narrow.test", max_queries=4)

    result = asyncio.run(run())
    assert result.result == "fail", (
        "narrow.test needs one lookup against a budget of five, but the "
        "earlier check had already spent the budget"
    )


# --- 5: returned results are stable ----------------------------------------


def test_returned_result_queries_do_not_change_afterwards():
    """Review finding 4. A returned Result is a record, not a live view."""

    async def run():
        shared = ZoneResolver(BUDGET_ZONE)
        first = await _check(shared, "u@narrow.test")
        before = len(first.queries)
        await _check(shared, "u@wide.test")
        return before, len(first.queries)

    before, after = asyncio.run(run())
    assert after == before, (
        f"first result's query list grew from {before} to {after} because of "
        "an unrelated later evaluation"
    )


# --- 6: concurrency --------------------------------------------------------


def test_concurrent_evaluations_on_one_resolver_do_not_interfere():
    """Review finding 1. A shared resolver in a FastAPI app sees concurrency."""

    async def run():
        shared = ZoneResolver(VOID_ZONE)
        solo = await _check(ZoneResolver(VOID_ZONE), "u@quiet.test")
        together = await asyncio.gather(
            *[_check(shared, "u@noisy.test") for _ in range(4)],
            _check(shared, "u@quiet.test"),
        )
        return solo.result, together[-1].result

    solo, concurrent = asyncio.run(run())
    assert concurrent == solo, (
        "quiet.test decided differently when evaluated alongside other checks "
        "sharing one resolver"
    )


# --- 7: evaluator reuse ----------------------------------------------------


def test_evaluator_reuse_keeps_the_policy_override():
    """Review finding 5. Reuse must be either correct or refused, never silent."""

    async def run():
        zone = {"d.test": [("TXT", "v=spf1 -all")]}
        ev = Evaluator(ZoneResolver(zone), Limits(), policy_override="v=spf1 +all")
        first = await ev.evaluate("1.2.3.4", "u@d.test")
        try:
            second = await ev.evaluate("1.2.3.4", "u@d.test")
        except spftrace.SpfUsageError:
            return first.result, "refused"
        return first.result, second.result

    first, second = asyncio.run(run())
    assert first == "pass", "sanity: the override is applied on first use"
    assert second in ("pass", "refused"), (
        "second evaluate() silently dropped the policy override and fell back "
        "to DNS; reuse must either work or raise SpfUsageError"
    )


def test_evaluator_reuse_does_not_accumulate_trace_events():
    """Review finding 5. Leftover trace state would corrupt the debug output."""

    async def run():
        zone = {"d.test": [("TXT", "v=spf1 ip4:1.2.3.4 -all")]}
        ev = Evaluator(ZoneResolver(zone), Limits())
        first = await ev.evaluate("1.2.3.4", "u@d.test")
        n_first = len(first.trace.to_list())
        try:
            second = await ev.evaluate("1.2.3.4", "u@d.test")
        except spftrace.SpfUsageError:
            pytest.skip("Evaluator reuse is refused, which is an acceptable contract")
        return n_first, len(second.trace.to_list())

    n_first, n_second = asyncio.run(run())
    assert n_second == n_first, (
        f"second evaluation's trace carried {n_second - n_first} stale events "
        "from the first"
    )


# --- 8: cache lifetime -----------------------------------------------------


def test_cached_answers_do_not_outlive_the_evaluation():
    """Review finding 2. Stale SPF policy is an authentication error, not a
    performance detail. Evaluation-local caching is the 0.2.0 contract."""

    async def run():
        zone: dict[str, object] = {"c.test": [("TXT", "v=spf1 ip4:1.2.3.4 -all")]}
        shared = ZoneResolver(zone)
        before = await _check(shared, "u@c.test")
        shared.zone["c.test"] = [("TXT", "v=spf1 -all")]
        after = await _check(shared, "u@c.test")
        return before.result, after.result

    before, after = asyncio.run(run())
    assert before == "pass", "sanity: the original record passes"
    assert after == "fail", (
        "the record changed between checks but the second evaluation served a "
        "cached answer from the first"
    )


def test_cache_still_deduplicates_within_one_evaluation():
    """The cache must keep earning its place inside a single check."""

    async def run():
        zone = {
            "dup.test": [("TXT", "v=spf1 a:host.test a:host.test a:host.test -all")],
            "host.test": [("A", "10.0.0.9")],
        }
        return await _check(ZoneResolver(zone), "u@dup.test")

    result = asyncio.run(run())
    cached = [q for q in result.queries if q.source == "cache"]
    assert cached, "repeated lookups within one evaluation should hit the cache"


# --- 9: void limit enforced at the earliest point --------------------------


def test_no_dns_queries_are_issued_after_the_void_limit_is_reached():
    """Review finding 3. The void limit is resource-exhaustion protection, so
    the third void must be the last packet that leaves the host."""

    async def run():
        zone = {
            "mx.test": [
                ("TXT", "v=spf1 mx -all"),
                ("MX", "e1.test"),
                ("MX", "e2.test"),
                ("MX", "e3.test"),
                ("MX", "e4.test"),
                ("MX", "e5.test"),
                ("MX", "e6.test"),
            ],
            # e1..e6 absent: every A lookup is a void.
        }
        return await _check(ZoneResolver(zone), "u@mx.test")

    result = asyncio.run(run())
    assert result.result == "permerror"
    network = [q for q in result.queries if q.source == "dns"]
    void_positions = [i for i, q in enumerate(network) if q.void]
    assert len(void_positions) >= 3, "sanity: the zone produces at least three voids"
    trailing = len(network) - (void_positions[2] + 1)
    assert trailing == 0, (
        f"{trailing} DNS queries were issued after the third void lookup"
    )


def test_audit_mode_still_counts_voids_past_the_limit():
    """Early enforcement must not cost the debug tool its visibility."""

    async def run():
        zone = {
            "mx.test": [
                ("TXT", "v=spf1 mx -all"),
                ("MX", "e1.test"),
                ("MX", "e2.test"),
                ("MX", "e3.test"),
                ("MX", "e4.test"),
                ("MX", "e5.test"),
                ("MX", "e6.test"),
            ],
        }
        return await _check(ZoneResolver(zone), "u@mx.test", audit=True)

    result = asyncio.run(run())
    assert result.result == "permerror", "audit changes visibility, never the verdict"
    assert result.void_lookups_used > 3, (
        "audit mode should report the record's true void count, got "
        f"{result.void_lookups_used}"
    )


# --- 10: version single source of truth ------------------------------------


def test_runtime_version_matches_package_metadata():
    """Review finding 7."""
    assert spftrace.__version__ == version("spftrace")


# --- 11: CLI reports the limit it actually used ----------------------------


def test_cli_displays_the_configured_time_limit():
    """Review finding 8."""
    from spftrace.cli import render_text

    zone = {"d.test": [("TXT", "v=spf1 ip4:1.2.3.4 -all")]}

    async def run():
        return await Evaluator(ZoneResolver(zone), Limits(time_limit=60.0)).evaluate(
            "1.2.3.4", "u@d.test"
        )

    result = asyncio.run(run())
    text = render_text(result, dns_server="192.0.2.53", time_limit=60.0)
    assert "60 seconds" in text, "CLI printed the default limit, not the configured one"


# --- 12: deadline semantics ------------------------------------------------


def test_deadline_bounds_a_slow_multi_lookup_mechanism():
    """Review finding 6. One `mx` can issue a dozen lookups. A slow zone must
    not be able to run far past the caller's deadline before anyone notices."""

    class SlowResolver(ZoneResolver):
        async def _lookup(self, name, rtype):
            await asyncio.sleep(0.05)
            return await super()._lookup(name, rtype)

    zone: dict[str, object] = {
        "slow.test": [
            ("TXT", "v=spf1 mx -all"),
            *[("MX", f"e{i}.test") for i in range(1, 9)],
        ],
        **{f"e{i}.test": [("A", "10.0.0.99")] for i in range(1, 9)},
    }

    async def run():
        start = asyncio.get_running_loop().time()
        result = await _check(SlowResolver(zone), "u@slow.test", time_limit=0.12)
        return result, asyncio.get_running_loop().time() - start

    result, elapsed = asyncio.run(run())
    assert result.result == "temperror", (
        "a mechanism that runs past the deadline should temperror, got "
        f"{result.result}"
    )
    assert elapsed < 0.5, (
        f"evaluation ran {elapsed:.2f}s against a 0.12s limit; the deadline is "
        "not being checked inside the mechanism"
    )


# --- config validation -----------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_queries": -1},
        {"time_limit": 0},
        {"time_limit": -5},
        {"timeout": 0},
        {"nameservers": []},
    ],
)
def test_invalid_configuration_raises_usage_error(kwargs):
    """Review finding 9."""
    with pytest.raises(spftrace.SpfUsageError):
        spftrace.check("1.2.3.4", "u@example.com", **kwargs)
