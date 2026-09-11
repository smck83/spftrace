"""spftrace: an RFC 7208 SPF evaluator that shows its working.

The trace is the product, not a side effect. Every DNS query, macro expansion,
mechanism evaluation and limit decision is recorded and returned.

Quick use:

    import spftrace
    r = spftrace.check("203.0.113.1", "user@example.com")
    print(r.verdict)                 # pass | fail | softfail | neutral | none |
                                     # permerror | temperror
    print(r.to_dict())               # stable JSON-safe structure

Inside an async application (FastAPI and friends), await the async form:

    r = await spftrace.acheck("203.0.113.1", "user@example.com")

For full control over DNS, build the resolver and evaluator yourself:

    from spftrace import Evaluator, Limits, LiveResolver
    resolver = LiveResolver(["192.0.2.53"], timeout=3.0)
    result = await Evaluator(resolver, Limits(max_queries=75)).evaluate(ip, sender, helo)

The resolver is transport and may be reused. Everything scoped to one check,
including the query budget, the void count and the cache, lives in an
EvaluationSession built fresh by each evaluate() call.
"""
from __future__ import annotations

import asyncio
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _metadata_version
from typing import Iterable

from .errors import (
    SpfError,
    SpfNoneError,
    SpfPermError,
    SpfTempError,
    SpfUsageError,
)
from .evaluator import MAX_MX_RECORDS, MAX_PTR_NAMES, Evaluator
from .session import (
    DEFAULT_MAX_QUERIES,
    DEFAULT_PREFETCH_CONCURRENCY,
    DEFAULT_TIME_LIMIT,
    MAX_DNS_TERMS,
    MAX_VOID_LOOKUPS,
    EvaluationSession,
    Limits,
)
from .parser import Term, parse
from .prefetch import Prefetcher
from .resolver import BaseResolver, DnsError, LiveResolver, ZoneResolver
from .trace import DnsQueryRecord, Event, PrefetchStats, Result, Trace

try:
    __version__ = _metadata_version("spftrace")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"

#: Used only when no resolver and no nameservers are supplied. Callers that care
#: which resolver answers should pass their own; this library never reads the
#: system resolver configuration or any environment variable.
DEFAULT_NAMESERVERS: tuple[str, ...] = ("8.8.8.8",)

__all__ = [
    "__version__",
    "acheck",
    "check",
    "BaseResolver",
    "DEFAULT_MAX_QUERIES",
    "DEFAULT_NAMESERVERS",
    "DEFAULT_PREFETCH_CONCURRENCY",
    "DEFAULT_TIME_LIMIT",
    "DnsError",
    "DnsQueryRecord",
    "EvaluationSession",
    "Evaluator",
    "Event",
    "Limits",
    "LiveResolver",
    "MAX_DNS_TERMS",
    "MAX_MX_RECORDS",
    "MAX_PTR_NAMES",
    "MAX_VOID_LOOKUPS",
    "PrefetchStats",
    "Prefetcher",
    "Result",
    "SpfError",
    "SpfNoneError",
    "SpfPermError",
    "SpfTempError",
    "SpfUsageError",
    "Term",
    "Trace",
    "ZoneResolver",
    "parse",
]


async def acheck(
    ip: str,
    sender: str,
    helo: str = "",
    *,
    policy: str | None = None,
    resolver: BaseResolver | None = None,
    nameservers: Iterable[str] | None = None,
    timeout: float = 5.0,
    max_queries: int | None = DEFAULT_MAX_QUERIES,
    time_limit: float = DEFAULT_TIME_LIMIT,
    receiver: str = "spftrace",
    audit: bool = False,
    prefetch: bool = False,
) -> Result:
    """Evaluate SPF for `ip` sending as `sender`, returning a traced Result.

    RFC outcomes are never exceptions. A malformed record, a blown lookup limit
    or an exhausted query budget all come back as a `permerror` verdict with the
    reason in the trace, so a caller never has to wrap this in try/except just to
    survive a hostile zone. Exceptions are reserved for caller mistakes.

    Args:
        ip: the connecting IP. IPv4-mapped IPv6 is normalised to IPv4.
        sender: MAIL FROM address. A bare domain is treated as postmaster@domain.
        helo: HELO/EHLO name. Defaults to the sender domain.
        policy: evaluate this record instead of looking one up in DNS. Useful for
            testing a record you have not published yet.
        resolver: a ready-made resolver. Mutually exclusive with `nameservers`.
            A resolver is DNS transport only, so one may be shared freely across
            checks and across concurrent tasks. Pass a ZoneResolver to test
            offline. Note that budgets, counters and the lookup cache belong to
            the evaluation, not the resolver, so sharing one never carries state
            between checks.
        nameservers: resolver addresses to query. Defaults to DEFAULT_NAMESERVERS.
        timeout: per-query DNS timeout in seconds.
        max_queries: hard cap on real DNS queries for this one evaluation, or
            None for no cap.
        time_limit: deadline in seconds for this one evaluation, checked between
            terms and before every DNS query.
        receiver: value of the %{r} macro.
        audit: keep counting past the 10-term limit to report what a record
            really needs. The verdict is still forced to permerror, so this
            changes visibility and never the answer.
        prefetch: speculate the record tree's DNS lookups in parallel, up to
            ten at a time, while the evaluation itself proceeds sequentially
            as the RFC requires. Verdict, term count and void count are
            identical to a sequential run; only wall time changes. Costs
            speculative traffic on records that match early, reported in
            `Result.prefetch`.

    Raises:
        SpfUsageError: both `resolver` and `nameservers` were supplied, or a
            configuration value is out of range.
    """
    if resolver is not None and nameservers is not None:
        raise SpfUsageError(
            "pass either resolver or nameservers, not both: a supplied resolver "
            "already carries its own nameservers and timeout"
        )
    if time_limit <= 0:
        raise SpfUsageError(f"time_limit must be positive, got {time_limit!r}")
    if timeout <= 0:
        raise SpfUsageError(f"timeout must be positive, got {timeout!r}")
    if max_queries is not None and max_queries < 1:
        raise SpfUsageError(
            f"max_queries must be at least 1, or None for no cap, got {max_queries!r}"
        )
    if resolver is None:
        addresses = list(
            nameservers if nameservers is not None else DEFAULT_NAMESERVERS
        )
        if not addresses:
            raise SpfUsageError(
                "nameservers is empty: pass at least one resolver address, or "
                "omit it to use DEFAULT_NAMESERVERS"
            )
        resolver = LiveResolver(addresses, timeout=timeout)
    evaluator = Evaluator(
        resolver,
        Limits(
            time_limit=time_limit,
            max_queries=max_queries,
            audit=audit,
            prefetch=prefetch,
        ),
        receiver=receiver,
        policy_override=policy,
    )
    return await evaluator.evaluate(ip, sender, helo)


def check(
    ip: str,
    sender: str,
    helo: str = "",
    *,
    policy: str | None = None,
    resolver: BaseResolver | None = None,
    nameservers: Iterable[str] | None = None,
    timeout: float = 5.0,
    max_queries: int | None = DEFAULT_MAX_QUERIES,
    time_limit: float = DEFAULT_TIME_LIMIT,
    receiver: str = "spftrace",
    audit: bool = False,
    prefetch: bool = False,
) -> Result:
    """Blocking form of `acheck`, for scripts and sync code.

    Raises:
        SpfUsageError: called from inside a running event loop. The evaluator is
            async underneath; from async code, await `acheck` instead. Without
            this check asyncio raises a confusing "cannot be called from a
            running event loop" from several frames down.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise SpfUsageError(
            "spftrace.check() cannot be called from a running event loop. "
            "Use 'await spftrace.acheck(...)' instead."
        )
    return asyncio.run(
        acheck(
            ip,
            sender,
            helo,
            policy=policy,
            resolver=resolver,
            nameservers=nameservers,
            timeout=timeout,
            max_queries=max_queries,
            time_limit=time_limit,
            receiver=receiver,
            audit=audit,
            prefetch=prefetch,
        )
    )
