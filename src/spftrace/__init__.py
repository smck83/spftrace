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
    resolver = LiveResolver(["192.0.2.53"], timeout=3.0, max_queries=75)
    result = await Evaluator(resolver, Limits()).evaluate(ip, sender, helo)
"""
from __future__ import annotations

import asyncio
from typing import Iterable

from .errors import (
    SpfError,
    SpfNoneError,
    SpfPermError,
    SpfTempError,
    SpfUsageError,
)
from .evaluator import (
    DEFAULT_TIME_LIMIT,
    MAX_DNS_TERMS,
    MAX_MX_RECORDS,
    MAX_PTR_NAMES,
    MAX_VOID_LOOKUPS,
    Evaluator,
    Limits,
)
from .parser import Term, parse
from .resolver import BaseResolver, DnsError, LiveResolver, ZoneResolver
from .trace import DnsQueryRecord, Event, Result, Trace

__version__ = "0.1.0"

#: Used only when no resolver and no nameservers are supplied. Callers that care
#: which resolver answers should pass their own; this library never reads the
#: system resolver configuration or any environment variable.
DEFAULT_NAMESERVERS: tuple[str, ...] = ("8.8.8.8",)

#: Hard cap on real DNS queries per evaluation. This is not the RFC's 10-term
#: limit: that counts terms, not lookups, and ten `mx` terms with ten MX records
#: each is 10 terms but 111 queries. This cap stops a hostile zone from turning
#: one check into unbounded traffic.
DEFAULT_MAX_QUERIES = 75

__all__ = [
    "__version__",
    "acheck",
    "check",
    "BaseResolver",
    "DEFAULT_MAX_QUERIES",
    "DEFAULT_NAMESERVERS",
    "DEFAULT_TIME_LIMIT",
    "DnsError",
    "DnsQueryRecord",
    "Evaluator",
    "Event",
    "Limits",
    "LiveResolver",
    "MAX_DNS_TERMS",
    "MAX_MX_RECORDS",
    "MAX_PTR_NAMES",
    "MAX_VOID_LOOKUPS",
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
            Supply your own to add caching, or a ZoneResolver to test offline.
        nameservers: resolver addresses to query. Defaults to DEFAULT_NAMESERVERS.
        timeout: per-query DNS timeout in seconds.
        max_queries: hard cap on real DNS queries, or None for no cap.
        time_limit: overall deadline in seconds, checked between terms.
        receiver: value of the %{r} macro.
        audit: keep counting past the 10-term limit to report what a record
            really needs. The verdict is still forced to permerror, so this
            changes visibility and never the answer.

    Raises:
        SpfUsageError: both `resolver` and `nameservers` were supplied.
    """
    if resolver is not None and nameservers is not None:
        raise SpfUsageError(
            "pass either resolver or nameservers, not both: a supplied resolver "
            "already carries its own nameservers, timeout and query budget"
        )
    if resolver is None:
        resolver = LiveResolver(
            nameservers if nameservers is not None else DEFAULT_NAMESERVERS,
            timeout=timeout,
            max_queries=max_queries,
        )
    evaluator = Evaluator(
        resolver,
        Limits(time_limit=time_limit, audit=audit),
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
        )
    )
