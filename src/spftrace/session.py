"""Per-evaluation state: budgets, counters, cache and the DNS query trace.

The split that matters:

    BaseResolver        transport only. Nameservers, timeout, sockets. Holds no
                        counters and no cache, so one resolver can safely serve
                        many evaluations, including concurrent ones.

    EvaluationSession   everything that belongs to a single check_host() run:
                        the query trace, the network query budget, the void
                        count, the deadline and the lookup cache.

Before 0.2.0 these lived together on the resolver. Reusing a resolver therefore
carried a previous check's void count and spent query budget into the next one,
which could turn a passing message into a permerror. Sharing DNS transport must
never share SPF evaluation state.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from .errors import SpfPermError, SpfTempError
from .resolver import NOERROR, NXDOMAIN, BaseResolver, DnsError
from .trace import DnsQueryRecord, Trace

MAX_DNS_TERMS = 10
MAX_VOID_LOOKUPS = 2
DEFAULT_TIME_LIMIT = 20.0

#: Hard cap on real DNS queries per evaluation. This is not the RFC's 10-term
#: limit: that counts terms, not lookups, and ten `mx` terms with ten MX records
#: each is 10 terms but 111 queries. This cap stops a hostile zone from turning
#: one check into unbounded traffic.
DEFAULT_MAX_QUERIES = 75


@dataclass
class Limits:
    """Budgets and counters for one evaluation.

    An instance handed to `Evaluator` is a template. Every call to `evaluate()`
    takes a fresh copy, so counters never carry between runs.
    """

    max_terms: int = MAX_DNS_TERMS
    max_void: int = MAX_VOID_LOOKUPS
    time_limit: float = DEFAULT_TIME_LIMIT
    max_queries: int | None = DEFAULT_MAX_QUERIES
    terms_used: int = 0
    void_used: int = 0
    started: float = field(default_factory=time.monotonic)
    # Audit mode keeps counting past a breached limit so the trace can report
    # how many lookups the record actually needs. The returned result is still
    # forced to permerror: this changes visibility, never the verdict.
    audit: bool = False
    audit_max_terms: int = 100
    terms_exceeded: bool = False
    void_exceeded: bool = False

    @property
    def exceeded(self) -> bool:
        return self.terms_exceeded or self.void_exceeded

    def fresh(self) -> "Limits":
        """A copy with the counters and clock reset, keeping the caller's config."""
        return Limits(
            max_terms=self.max_terms,
            max_void=self.max_void,
            time_limit=self.time_limit,
            max_queries=self.max_queries,
            audit=self.audit,
            audit_max_terms=self.audit_max_terms,
            started=time.monotonic(),
        )

    def remaining(self) -> float:
        return self.time_limit - (time.monotonic() - self.started)

    def check_deadline(self) -> None:
        if self.remaining() <= 0:
            raise SpfTempError("evaluation time limit exceeded")

    def consume_term(self, name: str) -> bool:
        """Returns True if this term is over the RFC limit (audit mode only)."""
        if self.terms_used >= self.max_terms:
            self.terms_exceeded = True
            if not self.audit or self.terms_used >= self.audit_max_terms:
                self.terms_used += 1
                raise SpfPermError(
                    f"DNS lookup limit exceeded ({self.max_terms}) at '{name}'"
                )
            self.terms_used += 1
            return True
        self.terms_used += 1
        return False


class EvaluationSession:
    """One SPF evaluation's DNS state, layered over a reusable resolver."""

    def __init__(
        self,
        resolver: BaseResolver,
        limits: Limits,
        trace: Trace | None = None,
    ) -> None:
        self.resolver = resolver
        self.limits = limits
        self.trace = trace
        self.queries: list[DnsQueryRecord] = []
        self.network_queries = 0
        self._cache: dict[tuple[str, str], tuple[str, list[str]]] = {}
        self._void_limit_flagged = False
        self._void_exempt = False
        #: Set by the evaluator so void events can name the term that caused
        #: them. Purely for the trace.
        self.current_term: str | None = None

    @property
    def void_count(self) -> int:
        return self.limits.void_used

    @contextmanager
    def void_exempt(self):
        """Lookups inside this block do not count against the void limit.

        RFC 7208 section 4.6.4: a non-existent `exp=` domain must not consume
        void budget. The exp record is fetched only after the verdict is already
        decided, so a missing explanation can never change the answer. Network
        queries are still counted and traced: the exemption is about the RFC
        limit, not about letting an unbounded number of lookups through.
        """
        previous = self._void_exempt
        self._void_exempt = True
        try:
            yield
        finally:
            self._void_exempt = previous

    def _note(self, kind: str, **data) -> None:
        if self.trace is not None:
            self.trace.add(kind, **data)

    async def query(self, name: str, rtype: str) -> tuple[str, list[str]]:
        """Returns (rcode, answers). Raises DnsError on SERVFAIL/TIMEOUT.

        The cache is evaluation-local, so a record that changes between two
        checks is seen by the second one. Within a check, repeated lookups are
        still served from cache: RFC 7208 evaluation revisits the same names
        often, and re-querying them wins nothing.
        """
        key = (name.lower().rstrip("."), rtype)
        start = time.monotonic()
        if key in self._cache:
            rcode, answers = self._cache[key]
            source = "cache"
            elapsed = 0.0
        else:
            source = "dns"
            # Checked here, not only between terms: one `mx` can issue a dozen
            # lookups, and a slow zone should not be able to run minutes past
            # the caller's deadline before anyone notices.
            self.limits.check_deadline()
            if (
                self.limits.max_queries is not None
                and self.network_queries >= self.limits.max_queries
            ):
                raise SpfPermError(
                    f"DNS query budget exceeded ({self.limits.max_queries} lookups)"
                )
            self.network_queries += 1
            try:
                rcode, answers = await asyncio.wait_for(
                    self.resolver._lookup(name, rtype),
                    timeout=max(self.limits.remaining(), 0.0),
                )
            except asyncio.TimeoutError as exc:
                raise SpfTempError("evaluation time limit exceeded") from exc
            elapsed = (time.monotonic() - start) * 1000.0
            if rcode in (NOERROR, NXDOMAIN):
                self._cache[key] = (rcode, answers)

        void = rcode == NXDOMAIN or (rcode == NOERROR and not answers)
        # Counted once per real lookup. Counting per-term double counts: every
        # enclosing include re-counts its children's voids, which turned a
        # single void three includes deep into a false permerror.
        if void and source == "dns" and not self._void_exempt:
            self.limits.void_used += 1

        # The record is appended before any limit is enforced. A trace that
        # omits the query which tripped the limit is worse than useless.
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

        # TXT is traced by the evaluator, which knows whether the answer is a
        # policy, an explanation or neither. Everything else — the A/AAAA behind
        # an `a`, the MX and its per-exchange address lookups, PTR — had no
        # trace event at all, so a non-matching `mx` rendered as a bare "no
        # match" with the actual work invisible. That is the one thing a reader
        # debugging a legitimate sender needs to see.
        if rtype != "TXT":
            self._note(
                "dns_lookup",
                name=name,
                rtype=rtype,
                rcode=rcode,
                answers=list(answers),
                ms=round(elapsed, 1),
                source=source,
                term=self.current_term,
            )

        if void and source == "dns" and not self._void_exempt:
            self._note(
                "void_lookup",
                used=self.limits.void_used,
                allowed=self.limits.max_void,
                name=name,
                term=self.current_term,
                note="a lookup returned NXDOMAIN or no answers; "
                     "exceeding the limit is permerror",
            )
            self._enforce_void(name)

        if rcode not in (NOERROR, NXDOMAIN):
            raise DnsError(f"{rtype} {name}: {rcode}")
        return rcode, answers

    def _enforce_void(self, name: str) -> None:
        """Stop at the void that breaches the limit, not at the end of the term.

        RFC 7208 section 4.6.4 caps void lookups partly as resource-exhaustion
        protection. Enforcing only after a mechanism finished meant a hostile
        zone could still extract every lookup an `mx` could make. In audit mode
        the evaluation continues so the trace can report the true count; the
        verdict is forced to permerror either way.
        """
        if self.limits.void_used <= self.limits.max_void:
            return
        self.limits.void_exceeded = True
        if not self._void_limit_flagged:
            self._void_limit_flagged = True
            self._note(
                "limit_exceeded",
                limit="void_lookups",
                used=self.limits.void_used,
                allowed=self.limits.max_void,
                name=name,
                term=self.current_term,
                note="beyond the RFC limit"
                     + (
                         "; counted for audit only, a real MTA stops here "
                         "with permerror"
                         if self.limits.audit
                         else ""
                     ),
            )
        if not self.limits.audit:
            raise SpfPermError(
                f"void DNS lookup limit exceeded ({self.limits.max_void}) "
                f"at '{self.current_term or name}'"
            )
