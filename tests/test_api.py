"""The published surface. These are the promises other projects depend on."""
from __future__ import annotations

import asyncio
import json

import pytest

import spftrace
from spftrace import SpfUsageError, ZoneResolver

ZONE = {"e.com": [("TXT", "v=spf1 ip4:1.2.3.0/24 -all")]}


def test_sync_check_with_injected_resolver():
    result = spftrace.check("1.2.3.4", "a@e.com", resolver=ZoneResolver(ZONE))
    assert result.verdict == "pass"
    assert result.verdict == result.result


def test_async_check():
    async def go():
        return await spftrace.acheck("5.5.5.5", "a@e.com", resolver=ZoneResolver(ZONE))

    assert asyncio.run(go()).verdict == "fail"


def test_sync_check_inside_running_loop_raises_a_useful_error():
    async def go():
        with pytest.raises(SpfUsageError, match="acheck"):
            spftrace.check("1.2.3.4", "a@e.com", resolver=ZoneResolver(ZONE))

    asyncio.run(go())


def test_resolver_and_nameservers_are_mutually_exclusive():
    with pytest.raises(SpfUsageError, match="not both"):
        spftrace.check(
            "1.2.3.4", "a@e.com", resolver=ZoneResolver(ZONE), nameservers=["8.8.8.8"]
        )


def test_bare_domain_sender_is_treated_as_postmaster():
    result = spftrace.check("1.2.3.4", "e.com", resolver=ZoneResolver(ZONE))
    assert result.verdict == "pass"


def test_invalid_ip_is_a_permerror_not_an_exception():
    result = spftrace.check("not-an-ip", "a@e.com", resolver=ZoneResolver(ZONE))
    assert result.verdict == "permerror"


def test_policy_override_via_convenience_api():
    result = spftrace.check(
        "9.9.9.9",
        "a@e.com",
        policy="v=spf1 ip4:9.9.9.0/24 -all",
        resolver=ZoneResolver(ZONE),
    )
    assert result.verdict == "pass"
    assert result.dns_terms_used == 0


def test_to_dict_is_json_serialisable_and_has_the_documented_shape():
    result = spftrace.check("1.2.3.4", "a@e.com", resolver=ZoneResolver(ZONE))
    d = result.to_dict()
    json.dumps(d)  # must not raise
    for key in (
        "schema_version",
        "result",
        "explanation",
        "dns_terms_used",
        "void_lookups_used",
        "elapsed_ms",
        "warnings",
        "queries",
        "events",
    ):
        assert key in d, key
    assert d["schema_version"] == 1
    assert d["events"][0]["kind"] == "check_start"
    assert {"name", "rtype", "rcode", "answers", "ms", "void", "source"} <= set(
        d["queries"][0]
    )


def test_library_reads_no_environment_variables():
    """Config is explicit. A consuming app owns its own env, not this library."""
    import pathlib

    pkg = pathlib.Path(spftrace.__file__).parent
    offenders = [
        p.name
        for p in pkg.glob("*.py")
        if p.name != "cli.py" and ("os.environ" in p.read_text() or "getenv" in p.read_text())
    ]
    assert not offenders, f"env access outside the CLI: {offenders}"


def test_exports_are_importable():
    for name in spftrace.__all__:
        assert hasattr(spftrace, name), name


def test_version_is_present():
    assert spftrace.__version__
