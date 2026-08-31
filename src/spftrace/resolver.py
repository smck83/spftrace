"""DNS transport.

Two implementations share one interface so the evaluator never knows the difference:
  LiveResolver  - dnspython against a configured server
  ZoneResolver  - in-memory zone, used by the RFC 7208 test suite harness

Recording, counting, caching and limit enforcement all live on
EvaluationSession in session.py, one instance per SPF evaluation. A resolver is
config plus a socket and nothing more, which is what makes it safe to share.
"""
from __future__ import annotations

from typing import Iterable


NOERROR = "NOERROR"
NXDOMAIN = "NXDOMAIN"
SERVFAIL = "SERVFAIL"
TIMEOUT = "TIMEOUT"


class DnsError(Exception):
    """Transient DNS failure. Maps to temperror."""


class BaseResolver:
    """DNS transport. Holds configuration, never evaluation state.

    Subclass and implement `_lookup`. Counters, cache and the query trace live
    on EvaluationSession, so one resolver may serve many evaluations, including
    concurrent ones, without leaking state between them.
    """

    async def _lookup(self, name: str, rtype: str) -> tuple[str, list[str]]:
        raise NotImplementedError


class LiveResolver(BaseResolver):
    def __init__(
        self,
        nameservers: Iterable[str],
        timeout: float = 5.0,
    ) -> None:
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

    def __init__(self, zone: dict[str, object]) -> None:
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
