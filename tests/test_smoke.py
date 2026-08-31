"""Tricky cases and regressions for bugs actually hit in production.

Offline by design: ZoneResolver only, so these run with no network at all.
"""
from __future__ import annotations

import asyncio

import pytest

from spftrace import Evaluator, Limits, ZoneResolver

ZONE = {
    "e.com": [("TXT", "v=spf1 ip4:1.2.3.0/24 -all")],
    "mx.e.com": [("TXT", "v=spf1 mx -all"), ("MX", "mail.e.com")],
    "mail.e.com": [("A", "1.2.3.4")],
    "inc.e.com": [("TXT", "v=spf1 include:e.com ~all")],
    "incnone.e.com": [("TXT", "v=spf1 include:nothing.e.com -all")],
    "red.e.com": [("TXT", "v=spf1 redirect=e.com")],
    "macro.e.com": [("TXT", "v=spf1 exists:%{ir}._d.e.com -all")],
    "4.3.2.1._d.e.com": [("A", "127.0.0.1")],
    "dbl.e.com": [("TXT", "v=spf1 -all"), ("TXT", "v=spf1 +all")],
    "cidr.e.com": [("TXT", "v=spf1 a:foo/bar.e.com -all")],
    "foo/bar.e.com": [("A", "1.2.3.4")],
    "badmod.e.com": [("TXT", "v=spf1 -all foo=%abc")],
    "exponly.e.com": [("TXT", "v=spf1 -all exp=%{r}.e.com")],
    "v6.e.com": [("TXT", "v=spf1 ip6:2001:db8::/32 -all")],
    "void.e.com": [("TXT", "v=spf1 a:x1.e.com a:x2.e.com a:x3.e.com -all")],
    "loop.e.com": [("TXT", "v=spf1 include:loop.e.com -all")],
    "helo.e.com": [("TXT", "v=spf1 a:%{H} -all")],
    # one void lookup, three includes deep: must count once, not once per level
    "nest1.e.com": [("TXT", "v=spf1 include:nest2.e.com -all")],
    "nest2.e.com": [("TXT", "v=spf1 include:nest3.e.com -all")],
    "nest3.e.com": [("TXT", "v=spf1 exists:gone.e.com -all")],
}

CASES = [
    ("1.2.3.4", "a@e.com", "", "pass", "ip4 cidr match"),
    ("5.5.5.5", "a@e.com", "", "fail", "ip4 no match, -all"),
    ("1.2.3.4", "a@mx.e.com", "", "pass", "mx then A"),
    ("1.2.3.4", "a@inc.e.com", "", "pass", "include returning pass matches"),
    ("5.5.5.5", "a@inc.e.com", "", "softfail", "include fail does not match"),
    ("1.2.3.4", "a@incnone.e.com", "", "permerror", "include with no record"),
    ("1.2.3.4", "a@red.e.com", "", "pass", "redirect"),
    ("1.2.3.4", "a@macro.e.com", "", "pass", "%{ir} macro exists"),
    ("1.2.3.4", "a@dbl.e.com", "", "permerror", "two v=spf1 records"),
    ("1.2.3.4", "a@cidr.e.com", "", "pass", "slash is legal in a domain-spec"),
    ("1.2.3.4", "a@badmod.e.com", "", "permerror", "unknown modifier bad macro"),
    ("1.2.3.4", "a@exponly.e.com", "", "permerror", "%{r} outside exp text"),
    ("2001:db8::1", "a@v6.e.com", "", "pass", "ipv6 prefix"),
    ("1.2.3.4", "a@void.e.com", "", "permerror", "void lookup limit"),
    ("1.2.3.4", "a@loop.e.com", "", "permerror", "include loop hits term limit"),
    ("1.2.3.4", "a@helo.e.com", "JUMPIN' JUPITER", "fail", "invalid helo macro"),
    ("1.2.3.4", "a@nothing.e.com", "", "none", "no record at all"),
    ("1.2.3.4", "a@nest1.e.com", "", "fail", "nested void counted once, not per level"),
]


@pytest.mark.parametrize(
    "ip,sender,helo,expected,label", CASES, ids=[c[4] for c in CASES]
)
def test_case(ip, sender, helo, expected, label):
    evaluator = Evaluator(ZoneResolver(ZONE), Limits())
    result = asyncio.run(evaluator.evaluate(ip, sender, helo))
    assert result.result == expected


def test_policy_override_does_no_dns():
    evaluator = Evaluator(
        ZoneResolver(ZONE), Limits(), policy_override="v=spf1 ip4:9.9.9.0/24 -all"
    )
    result = asyncio.run(evaluator.evaluate("9.9.9.9", "a@e.com"))
    assert result.result == "pass"
    assert result.dns_terms_used == 0


def _wide_zone(n: int = 14) -> dict:
    terms = " ".join(f"include:i{i}.e.com" for i in range(n))
    zone = {"big.e.com": [("TXT", f"v=spf1 {terms} ip4:1.2.3.4 -all")]}
    for i in range(n):
        zone[f"i{i}.e.com"] = [("TXT", "v=spf1 ip4:9.9.9.9 -all")]
    return zone


def test_term_limit_stops_at_eleven_of_ten():
    evaluator = Evaluator(ZoneResolver(_wide_zone()), Limits(max_queries=100))
    result = asyncio.run(evaluator.evaluate("1.2.3.4", "a@big.e.com"))
    assert result.result == "permerror"
    assert result.dns_terms_used == 11


def test_audit_counts_all_terms_but_never_upgrades_the_verdict():
    """A matching mechanism past the limit must still be permerror, not pass."""
    evaluator = Evaluator(
        ZoneResolver(_wide_zone()), Limits(max_queries=100, audit=True)
    )
    result = asyncio.run(evaluator.evaluate("1.2.3.4", "a@big.e.com"))
    assert result.result == "permerror"
    assert result.dns_terms_used == 14


def test_query_budget_exhaustion_is_a_verdict_not_an_exception():
    evaluator = Evaluator(ZoneResolver(_wide_zone()), Limits(max_queries=3))
    result = asyncio.run(evaluator.evaluate("1.2.3.4", "a@big.e.com"))
    assert result.result == "permerror"
    assert len(result.queries) <= 3
