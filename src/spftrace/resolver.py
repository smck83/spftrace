"""DNS layer. Every query is recorded: name, type, rcode, answers, timing, voidness.

Two implementations share one interface so the evaluator never knows the difference:
  LiveResolver  - dnspython against a configured server
  ZoneResolver  - in-memory zone, used by the RFC 7208 test suite harness
"""
from __future__ import annotations

import time
from typing import Iterable

from .errors import SpfPermError
from .trace import DnsQueryRecord

NOERROR = "NOERROR"
NXDOMAIN = "NXDOMAIN"
SERVFAIL = "SERVFAIL"
TIMEOUT = "TIMEOUT"


class DnsError(Exception):
    """Transient DNS failure. Maps to temperror."""


class BaseResolver:
    def __init__(self, max_queries: int | None = None) -> None:
        self.queries: list[DnsQueryRecord] = []
        self.max_queries = max_queries
        self.network_queries = 0
        self.void_count = 0
        self._cache: dict[tuple[str, str], tuple[str, list[str]]] = {}

    async def _lookup(self, name: str, rtype: str) -> tuple[str, list[str]]:
        raise NotImplementedError

    async def query(self, name: str, rtype: str) -> tuple[str, list[str]]:
        """Returns (rcode, answers). Raises DnsError on SERVFAIL/TIMEOUT."""
        key = (name.lower().rstrip("."), rtype)
        start = time.monotonic()
        if key in self._cache:
            rcode, answers = self._cache[key]
            source = "cache"
            elapsed = 0.0
        else:
            source = "dns"
            # The 10-term limit counts terms, not lookups: ten mx terms with ten
            # MX records each is 10 terms but 111 queries. This is the real cap.
            if self.max_queries is not None and self.network_queries >= self.max_queries:
                raise SpfPermError(
                    f"DNS query budget exceeded ({self.max_queries} lookups)"
                )
            self.network_queries += 1
            rcode, answers = await self._lookup(name, rtype)
            elapsed = (time.monotonic() - start) * 1000.0
            if rcode in (NOERROR, NXDOMAIN):
                self._cache[key] = (rcode, answers)
        void = rcode == NXDOMAIN or (rcode == NOERROR and not answers)
        # Counted here, once per real lookup. Counting per-term in the evaluator
        # double counts: every enclosing include re-counts its children's voids,
        # which turned a single void three includes deep into a false permerror.
        if void and source == "dns":
            self.void_count += 1
        self.queries.append(
            DnsQueryRecord(
                name=name,
                rtype=rtype,
                rcode=rcode,
                answers=list(answers),
                ms=elapsed,
                void=void,
                source=source,
            )
        )
        if rcode not in (NOERROR, NXDOMAIN):
            raise DnsError(f"{rtype} {name}: {rcode}")
        return rcode, answers


class LiveResolver(BaseResolver):
    def __init__(
        self,
        nameservers: Iterable[str],
        timeout: float = 5.0,
        max_queries: int | None = None,
    ) -> None:
        super().__init__(max_queries=max_queries)
        import dns.asyncresolver

        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = list(nameservers)
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def _lookup(self, name: str, rtype: str) -> tuple[str, list[str]]:
        import dns.exception
        import dns.rdatatype
        import dns.resolver

        try:
            answer = await self.resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return NXDOMAIN, []
        except dns.resolver.NoNameservers:
            return SERVFAIL, []
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            return TIMEOUT, []
        except dns.exception.DNSException as exc:
            raise DnsError(str(exc)) from exc

        out: list[str] = []
        if answer.rrset is not None:
            for rdata in answer.rrset:
                if rtype == "TXT":
                    # A TXT record is a sequence of <=255 byte strings, joined with
                    # no separator (RFC 7208 s3.3).
                    out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
                elif rtype == "MX":
                    out.append(str(rdata.exchange).rstrip("."))
                elif rtype == "PTR":
                    out.append(str(rdata.target).rstrip("."))
                else:
                    out.append(rdata.address)
        return NOERROR, out


class ZoneResolver(BaseResolver):
    """Zone is {name: [(rtype, value), ...]} or {name: 'TIMEOUT'}."""

    def __init__(
        self, zone: dict[str, object], max_queries: int | None = None
    ) -> None:
        super().__init__(max_queries=max_queries)
        self.zone = {k.lower().rstrip("."): v for k, v in zone.items()}

    async def _lookup(self, name: str, rtype: str) -> tuple[str, list[str]]:
        key = name.lower().rstrip(".")
        seen: set[str] = set()
        while True:
            entry = self.zone.get(key)
            if entry is None:
                return NXDOMAIN, []
            if entry == TIMEOUT:
                return TIMEOUT, []
            records = [r for r in entry if r[0] == rtype]  # type: ignore[union-attr]
            if records:
                return NOERROR, [r[1] for r in records]
            if any(r[0] == "*" for r in entry):  # type: ignore[union-attr]
                return TIMEOUT, []
            cnames = [r[1] for r in entry if r[0] == "CNAME"]  # type: ignore[union-attr]
            if cnames and key not in seen:
                seen.add(key)
                key = str(cnames[0]).lower().rstrip(".")
                continue
            return NOERROR, []
