"""RFC 7208 check_host() with a full evaluation trace."""
from __future__ import annotations

import ipaddress
import re
import time

from . import macros as macro_mod
from .errors import SpfNoneError, SpfPermError, SpfTempError
from .macros import MacroContext, expand, truncate_domain
from .parser import DNS_MECHANISMS, QUALIFIERS, Term, VERSION_RE, parse
from .prefetch import PrefetchStats, Prefetcher
from .resolver import BaseResolver, DnsError
from .session import (
    DEFAULT_MAX_QUERIES,
    DEFAULT_TIME_LIMIT,
    MAX_DNS_TERMS,
    MAX_VOID_LOOKUPS,
    EvaluationSession,
    Limits,
)
from .trace import Result, Trace

MAX_MX_RECORDS = 10
MAX_PTR_NAMES = 10

LABEL_RE = re.compile(r"^[^.]{1,63}$")


def normalise_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def valid_domain(name: str) -> bool:
    name = name.rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return False
    return all(LABEL_RE.match(label) for label in name.split("."))


class Evaluator:
    def __init__(
        self,
        resolver: BaseResolver,
        limits: Limits | None = None,
        receiver: str = "spftrace",
        policy_override: str | None = None,
    ) -> None:
        self.resolver = resolver
        #: Caller's configuration. Treated as a template: each evaluate() call
        #: takes a fresh copy so counters never carry between runs.
        self.limits_template = limits or Limits()
        self.receiver = receiver
        self.policy_override = policy_override
        self.limits = self.limits_template
        self.trace = Trace()
        self.warnings: list[str] = []
        self.session = EvaluationSession(resolver, self.limits, self.trace)
        self._override_used = False
        self._prefetch_stats: PrefetchStats | None = None

    def _begin(self) -> None:
        """Build fresh per-run state. Called at the top of every evaluate().

        Before 0.2.0 an Evaluator was silently one-shot: a second evaluate()
        reused the first run's trace, counters and spent policy override, so
        identical inputs could return different verdicts.
        """
        self.limits = self.limits_template.fresh()
        self.trace = Trace()
        self.warnings = []
        self.session = EvaluationSession(self.resolver, self.limits, self.trace)
        self._override_used = False
        self._prefetch_stats: PrefetchStats | None = None

    # ---------- public entry point ----------

    async def evaluate(self, ip: str, sender: str, helo: str = "") -> Result:
        self._begin()
        started = time.monotonic()
        try:
            addr = normalise_ip(ip)
        except ValueError:
            self.trace.add("error", message=f"invalid IP address {ip!r}")
            return self._result("permerror", None, started)

        sender = sender.strip()
        helo = helo.strip().rstrip(".")
        if not sender:
            sender = f"postmaster@{helo}"
        if "@" not in sender:
            sender = f"postmaster@{sender}"
        localpart, _, domain = sender.rpartition("@")
        if not localpart:
            sender = f"postmaster@{domain}"
        if not helo:
            helo = domain

        if self.limits.prefetch:
            # Speculate the whole record tree in parallel while the sequential
            # walk below proceeds as before. See prefetch.py for why the walk
            # itself is never parallelised.
            self.session.prefetcher = Prefetcher(
                self.resolver, self.limits, addr, sender, helo, self.receiver
            )
            self.trace.add(
                "prefetch_start",
                domain=domain,
                concurrency=self.limits.prefetch_concurrency,
                note="speculative lookups run ahead of evaluation; "
                     "the evaluation order and verdict are unchanged",
            )
            self.session.prefetcher.start(domain, self.policy_override)

        explanation = None
        try:
            result, exp_term, exp_frame = await self.check_host(
                addr, domain, sender, helo, use_exp=True
            )
            if result == "fail" and exp_term is not None:
                explanation = await self._explanation(
                    addr, exp_frame, sender, helo, exp_term
                )
        except SpfNoneError as exc:
            self.trace.add("exit", result="none", reason=str(exc))
            result = "none"
        except SpfTempError as exc:
            self.trace.add("exit", result="temperror", reason=str(exc))
            result = "temperror"
        except SpfPermError as exc:
            self.trace.add("exit", result="permerror", reason=str(exc))
            result = "permerror"
        except DnsError as exc:
            self.trace.add("exit", result="temperror", reason=str(exc))
            result = "temperror"
        finally:
            if self.session.prefetcher is not None:
                self._prefetch_stats = await self.session.prefetcher.close()
                self.trace.add("prefetch_done", **self._prefetch_stats.to_dict())

        if self.limits.exceeded and result != "permerror":
            self.trace.add(
                "audit_override",
                observed=result,
                result="permerror",
                dns_terms=self.limits.terms_used,
                allowed=self.limits.max_terms,
                note="evaluation continued past the limit for counting only; "
                     "a conforming MTA returns permerror",
            )
            result = "permerror"

        return self._result(result, explanation, started)

    def _result(self, result: str, explanation: str | None, started: float) -> Result:
        self.trace.add(
            "result",
            result=result,
            dns_terms=self.limits.terms_used,
            void_lookups=self.limits.void_used,
        )
        return Result(
            result=result,
            explanation=explanation,
            trace=self.trace,
            queries=list(self.session.queries),
            dns_terms_used=self.limits.terms_used,
            void_lookups_used=self.limits.void_used,
            elapsed_ms=(time.monotonic() - started) * 1000.0,
            warnings=list(self.warnings),
            prefetch=self._prefetch_stats,
        )

    # ---------- check_host() ----------

    async def check_host(
        self,
        ip,
        domain: str,
        sender: str,
        helo: str,
        use_exp: bool = False,
    ) -> tuple[str, Term | None, str]:
        self.limits.check_deadline()
        self.trace.add(
            "check_start", ip=str(ip), domain=domain, sender=sender, helo=helo
        )

        if not valid_domain(domain):
            self.trace.add("domain_invalid", domain=domain)
            raise SpfNoneError(f"malformed domain {domain!r}")

        record_text = await self._fetch_policy(domain)
        try:
            record = parse(record_text)
        except SpfPermError as exc:
            self.trace.add("parse_error", policy=record_text, message=str(exc))
            raise
        self.trace.add(
            "policy_parsed",
            policy=record_text,
            terms=[t.raw for t in record.terms],
        )
        for w in record.warnings:
            msg = f"{domain}: {w}"
            if msg not in self.warnings:
                self.warnings.append(msg)

        ctx = MacroContext(
            ip=ip,
            sender=sender,
            helo=helo,
            domain=domain,
            receiver=self.receiver,
            session=self.session,
        )

        for term in record.terms:
            if not term.is_mechanism:
                continue
            self.limits.check_deadline()
            self.trace.add(
                "mech_start",
                index=term.index,
                mechanism=term.name,
                qualifier=QUALIFIERS[term.qualifier],
                raw=term.raw,
                arg=term.arg,
                cidr4=term.cidr4,
                cidr6=term.cidr6,
                dns_terms_used=self.limits.terms_used,
                void_used=self.limits.void_used,
            )
            matched = await self._eval_mechanism(term, ctx)
            if matched:
                result = QUALIFIERS[term.qualifier]
                self.trace.add(
                    "mech_match", mechanism=term.name, result=result, raw=term.raw
                )
                self.trace.add("eval_done", domain=domain, result=result)
                return result, (record.exp if use_exp else None), domain
            self.trace.add("mech_nomatch", mechanism=term.name, raw=term.raw)

        if record.redirect is not None:
            return await self._eval_redirect(record.redirect, ctx, sender, helo, use_exp)

        self.trace.add("eval_done", domain=domain, result="neutral", reason="default")
        return "neutral", (record.exp if use_exp else None), domain

    # ---------- policy retrieval ----------

    async def _fetch_policy(self, domain: str) -> str:
        if self.policy_override is not None and not self._override_used:
            self._override_used = True
            self.trace.add(
                "policy_override",
                domain=domain,
                policy=self.policy_override,
                note="supplied by user; no DNS term consumed",
            )
            return self.policy_override

        try:
            rcode, answers = await self.session.query(domain, "TXT")
        except DnsError as exc:
            self.trace.add("txt_error", domain=domain, message=str(exc))
            raise SpfTempError(f"TXT lookup failed for {domain}") from exc

        self.trace.add("txt_lookup", domain=domain, rcode=rcode, records=answers)
        spf_records = [a for a in answers if VERSION_RE.match(a)]
        if not spf_records:
            raise SpfNoneError(f"no v=spf1 record for {domain}")
        if len(spf_records) > 1:
            raise SpfPermError(f"multiple v=spf1 records for {domain}")
        return spf_records[0]

    # ---------- mechanisms ----------

    async def _target(self, term: Term, ctx: MacroContext) -> str:
        if term.arg is None:
            self.trace.add(
                "macro_expand", before=None, after=ctx.domain, note="implicit <domain>"
            )
            return ctx.domain
        expanded = await expand(term.arg, ctx)
        target = truncate_domain(expanded)
        self.trace.add(
            "macro_expand",
            mechanism=term.name,
            before=term.arg,
            after=target,
            truncated=target != expanded.rstrip("."),
        )
        return target

    async def _eval_mechanism(self, term: Term, ctx: MacroContext) -> bool:
        self.session.current_term = term.raw
        if term.name in DNS_MECHANISMS:
            if self.limits.consume_term(term.raw):
                self.trace.add(
                    "limit_exceeded",
                    limit="dns_terms",
                    used=self.limits.terms_used,
                    allowed=self.limits.max_terms,
                    term=term.raw,
                    note="beyond the RFC limit; counted for audit only, "
                         "a real MTA stops here with permerror",
                )
        try:
            if term.name == "all":
                return True
            if term.name == "ip4":
                return self._match_ip4(term, ctx)
            if term.name == "ip6":
                return self._match_ip6(term, ctx)
            if term.name == "a":
                return await self._match_a(term, ctx)
            if term.name == "mx":
                return await self._match_mx(term, ctx)
            if term.name == "ptr":
                return await self._match_ptr(term, ctx)
            if term.name == "exists":
                return await self._match_exists(term, ctx)
            if term.name == "include":
                return await self._match_include(term, ctx)
            raise SpfPermError(f"unhandled mechanism {term.name}")
        finally:
            # Void counting and enforcement now happen in EvaluationSession, at
            # the moment the offending lookup returns. See session._enforce_void.
            self.session.current_term = None

    def _match_ip4(self, term: Term, ctx: MacroContext) -> bool:
        if not ctx.is_v4:
            self.trace.add(
                "family_skip", mechanism="ip4", raw=term.raw,
                note="skipped: the connecting address is IPv6",
            )
            return False
        net = ipaddress.ip_network(f"{term.arg}/{term.cidr4}", strict=False)
        return ctx.ip in net

    def _match_ip6(self, term: Term, ctx: MacroContext) -> bool:
        if ctx.is_v4:
            self.trace.add(
                "family_skip", mechanism="ip6", raw=term.raw,
                note="skipped: the connecting address is IPv4",
            )
            return False
        net = ipaddress.ip_network(f"{term.arg}/{term.cidr6}", strict=False)
        return ctx.ip in net

    def _cidr(self, term: Term, ctx: MacroContext) -> int:
        if ctx.is_v4:
            return 32 if term.cidr4 is None else term.cidr4
        return 128 if term.cidr6 is None else term.cidr6

    def _addresses_match(self, addrs: list[str], term: Term, ctx: MacroContext) -> bool:
        prefix = self._cidr(term, ctx)
        for addr in addrs:
            try:
                net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
            except ValueError:
                continue
            if net.version == ctx.ip.version and ctx.ip in net:
                return True
        return False

    async def _match_a(self, term: Term, ctx: MacroContext) -> bool:
        target = await self._target(term, ctx)
        if not valid_domain(target):
            self.trace.add("target_invalid", mechanism="a", target=target)
            return False
        rtype = "A" if ctx.is_v4 else "AAAA"
        try:
            _, addrs = await self.session.query(target, rtype)
        except DnsError as exc:
            raise SpfTempError(f"a: {exc}") from exc
        return self._addresses_match(addrs, term, ctx)

    async def _match_mx(self, term: Term, ctx: MacroContext) -> bool:
        target = await self._target(term, ctx)
        if not valid_domain(target):
            self.trace.add("target_invalid", mechanism="mx", target=target)
            return False
        try:
            _, exchanges = await self.session.query(target, "MX")
        except DnsError as exc:
            raise SpfTempError(f"mx: {exc}") from exc
        if len(exchanges) > MAX_MX_RECORDS:
            raise SpfPermError(
                f"mx: more than {MAX_MX_RECORDS} MX records for {target}"
            )
        rtype = "A" if ctx.is_v4 else "AAAA"
        for exchange in exchanges:
            try:
                _, addrs = await self.session.query(exchange, rtype)
            except DnsError as exc:
                raise SpfTempError(f"mx: {exc}") from exc
            if self._addresses_match(addrs, term, ctx):
                self.trace.add("mx_match", exchange=exchange)
                return True
        return False

    async def _match_ptr(self, term: Term, ctx: MacroContext) -> bool:
        target = await self._target(term, ctx)
        rev = ctx.ip.reverse_pointer
        try:
            _, names = await self.session.query(rev, "PTR")
        except DnsError:
            return False
        rtype = "A" if ctx.is_v4 else "AAAA"
        target_l = target.lower().rstrip(".")
        for name in names[:MAX_PTR_NAMES]:
            name_l = name.lower().rstrip(".")
            if not (name_l == target_l or name_l.endswith("." + target_l)):
                continue
            try:
                _, addrs = await self.session.query(name, rtype)
            except DnsError:
                continue
            for addr in addrs:
                try:
                    if ipaddress.ip_address(addr) == ctx.ip:
                        self.trace.add("ptr_validated", name=name)
                        return True
                except ValueError:
                    continue
        return False

    async def _match_exists(self, term: Term, ctx: MacroContext) -> bool:
        target = await self._target(term, ctx)
        if not valid_domain(target):
            self.trace.add("target_invalid", mechanism="exists", target=target)
            return False
        try:
            rcode, addrs = await self.session.query(target, "A")
        except DnsError as exc:
            raise SpfTempError(f"exists: {exc}") from exc
        if not addrs:
            self.trace.add(
                "exists_miss", target=target, rcode=rcode,
                note="no A record, so the mechanism cannot match",
            )
        return bool(addrs)

    async def _match_include(self, term: Term, ctx: MacroContext) -> bool:
        target = await self._target(term, ctx)
        self.trace.add("recurse_in", via="include", domain=target)
        self.trace.push()
        try:
            result, _, _ = await self.check_host(
                ctx.ip, target, ctx.sender, ctx.helo, use_exp=False
            )
        except SpfNoneError as exc:
            self.trace.pop()
            self.trace.add("recurse_out", via="include", domain=target, result="none")
            raise SpfPermError(f"include:{target} has no SPF record") from exc
        self.trace.pop()
        self.trace.add("recurse_out", via="include", domain=target, result=result)
        if result == "pass":
            return True
        if result in ("fail", "softfail", "neutral"):
            return False
        if result == "temperror":
            raise SpfTempError(f"include:{target} temperror")
        raise SpfPermError(f"include:{target} permerror")

    async def _eval_redirect(
        self, term: Term, ctx: MacroContext, sender: str, helo: str, use_exp: bool
    ) -> tuple[str, Term | None, str]:
        if self.limits.consume_term(term.raw):
            self.trace.add(
                "limit_exceeded",
                limit="dns_terms",
                used=self.limits.terms_used,
                allowed=self.limits.max_terms,
                term=term.raw,
                note="beyond the RFC limit; counted for audit only",
            )
        self.session.current_term = term.raw
        target = await self._target(term, ctx)
        self.trace.add("recurse_in", via="redirect", domain=target)
        self.trace.push()
        try:
            result, exp_term, exp_domain = await self.check_host(
                ctx.ip, target, sender, helo, use_exp=use_exp
            )
        except SpfNoneError as exc:
            self.trace.pop()
            self.trace.add("recurse_out", via="redirect", domain=target, result="none")
            raise SpfPermError(f"redirect={target} has no SPF record") from exc
        self.trace.pop()
        self.trace.add("recurse_out", via="redirect", domain=target, result=result)
        return result, exp_term, exp_domain

    # ---------- exp ----------

    async def _explanation(
        self, ip, domain: str, sender: str, helo: str, exp_term: Term
    ) -> str | None:
        ctx = MacroContext(
            ip=ip,
            sender=sender,
            helo=helo,
            domain=domain,
            receiver=self.receiver,
            session=self.session,
        )
        try:
            # RFC 7208 4.6.4: a missing exp= domain must not consume void
            # budget. The verdict is already decided by this point.
            with self.session.void_exempt():
                target = truncate_domain(await expand(exp_term.arg or "", ctx))
                if not valid_domain(target):
                    return None
                _, answers = await self.session.query(target, "TXT")
                if len(answers) != 1:
                    return None
                text = await expand(answers[0], ctx, exp=True)
        except (SpfPermError, SpfTempError, DnsError, ValueError):
            return None
        if not macro_mod.LITERAL_OK.match(re.sub(r"%\{[^}]*\}", "", answers[0])):
            return None
        self.trace.add("exp", domain=target, text=text)
        return text
