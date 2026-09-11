"""What the trace shows, not what it decides.

Every DNS query was recorded in `Result.queries`, but only TXT lookups produced
a trace event. A non-matching `mx` therefore rendered as "Evaluating mechanism
mx" followed by "The mechanism did not match", with the MX query and the
per-exchange address lookups entirely invisible. That is precisely the detail
someone debugging a legitimate sender is looking for. These tests hold the
address lookups visible.
"""
from __future__ import annotations

import asyncio

import pytest

from spftrace import Evaluator, Limits, ZoneResolver
from spftrace.cli import render_text

MX_ZONE: dict[str, object] = {
    "d.test": [
        ("TXT", "v=spf1 mx -all"),
        ("MX", "mxa.d.test"),
        ("MX", "mxb.d.test"),
    ],
    "mxa.d.test": [("A", "10.0.0.1"), ("AAAA", "2001:db8::1")],
    "mxb.d.test": [("A", "10.0.0.2"), ("AAAA", "2001:db8::2")],
}


def _run(zone, ip, sender, **limit_kw):
    async def go():
        return await Evaluator(ZoneResolver(zone), Limits(**limit_kw)).evaluate(
            ip, sender
        )

    return asyncio.run(go())


def _lookups(result):
    return [e for e in result.trace.to_list() if e["kind"] == "dns_lookup"]


def test_mx_enumeration_is_visible_when_nothing_matches():
    """The whole point. A failing `mx` must name the hosts it checked."""
    result = _run(MX_ZONE, "198.51.100.7", "u@d.test")
    assert result.verdict == "fail"

    looked_up = [(e["rtype"], e["name"]) for e in _lookups(result)]
    assert looked_up == [
        ("MX", "d.test"),
        ("A", "mxa.d.test"),
        ("A", "mxb.d.test"),
    ], "the MX query and both exchange lookups must each appear in the trace"

    text = render_text(result)
    assert "mxa.d.test" in text and "mxb.d.test" in text
    assert "10.0.0.1" in text, "the addresses compared against the client IP"


def test_mx_short_circuits_at_the_first_matching_exchange():
    """Only the exchanges actually queried may appear. The trace must not
    imply work that never happened."""
    result = _run(MX_ZONE, "10.0.0.1", "u@d.test")
    assert result.verdict == "pass"

    names = [e["name"] for e in _lookups(result) if e["rtype"] == "A"]
    assert names == ["mxa.d.test"], "mxb was never queried, so it must not be traced"


@pytest.mark.parametrize(
    "ip, wanted, unwanted",
    [("10.0.0.1", "A", "AAAA"), ("2001:db8::1", "AAAA", "A")],
)
def test_address_family_follows_the_connecting_ip(ip, wanted, unwanted):
    """RFC 7208 section 5.3: one family per check, chosen by the client IP.
    An IPv4 connection never triggers an AAAA lookup, and vice versa."""
    result = _run(MX_ZONE, ip, "u@d.test")
    assert result.verdict == "pass"

    types = {e["rtype"] for e in _lookups(result)}
    assert wanted in types
    assert unwanted not in types


def test_txt_is_not_traced_twice():
    """The evaluator already emits `txt_lookup`, which carries the records and
    knows they are a policy. A second generic event would duplicate it."""
    result = _run(MX_ZONE, "10.0.0.1", "u@d.test")
    assert all(e["rtype"] != "TXT" for e in _lookups(result))
    kinds = [e["kind"] for e in result.trace.to_list()]
    assert kinds.count("txt_lookup") == 1


def test_a_lookup_served_from_cache_says_so():
    """A repeated name costs nothing. Rendering it identically to a real query
    would make the elapsed times look wrong."""
    zone = {
        "d.test": [("TXT", "v=spf1 a:h.test a:h.test -all")],
        "h.test": [("A", "10.0.0.9")],
    }
    result = _run(zone, "198.51.100.7", "u@d.test")

    sources = [e["source"] for e in _lookups(result)]
    assert sources == ["dns", "cache"]
    assert "from cache, no query sent" in render_text(result)


def test_a_void_lookup_shows_the_empty_answer():
    """An `a` against a name with no address records is the quiet failure mode
    that used to render as nothing at all."""
    zone = {
        "d.test": [("TXT", "v=spf1 a:nowhere.test -all")],
        "nowhere.test": [("TXT", "not an address")],
    }
    result = _run(zone, "198.51.100.7", "u@d.test")

    events = _lookups(result)
    assert [e["answers"] for e in events] == [[]]
    assert "No A records (NOERROR)." in render_text(result)
