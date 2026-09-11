"""Speculative DNS prefetch: parallel lookups, sequential evaluation.

SPF evaluation is short-circuit. The first matching mechanism decides the
verdict and nothing after it is evaluated, which is not a detail: it decides
whether the 10-term limit is reached, whether a void lookup is counted, and
therefore whether the answer is `pass` or `permerror`. Evaluating mechanisms
concurrently would have to rebuild all of that in a reduce step and stitch the
per-branch traces back together. That moves risk into the one component whose
whole value is matching the RFC.

So evaluation stays sequential and untouched. What runs in parallel is DNS.
The prefetcher reads the same record the evaluator is about to read, predicts
every lookup the evaluator could need (every term's target is derivable from
the record and the inputs), and issues them ahead of time under a concurrency
cap. The evaluator, on a cache miss, finds the answer already waiting or in
flight. Verdict, term count, void count and trace order come out identical
because the code that produces them has not changed. Only the waiting has.

Two rules keep that promise:

  * A prefetched answer is accounted as a live lookup, not a cache hit. It
    goes through the query budget and the void count in EvaluationSession
    exactly as if the evaluator had sent it, because a real MTA would have.
    Serving it as a cache hit would silently stop voids counting.

  * The prefetcher never raises into the evaluation and never shares the
    evaluator's counters. It has its own cap on speculative traffic; when it
    runs out, or a branch fails, the evaluator simply does that lookup live.
    A speculation failure is invisible except as lost speed.

The cost is speculative traffic. On a record that matches at its first term
the prefetcher may still have fetched the whole tree. That is bounded by the
same number as `max_queries`, reported in `Result.prefetch`, and is the price
of the speed. Evaluation traffic itself is unchanged.
"""
from __future__ import annotations

import asyncio
import time

from .errors import SpfPermError
from .macros import MacroContext, expand, truncate_domain
from .parser import VERSION_RE, parse
from .resolver import NOERROR, NXDOMAIN, BaseResolver, DnsError
from .session import Limits
from .trace import PrefetchStats

Key = tuple[str, str]


class _MacroSession:
    """What `expand()` needs for %{p}: a `query()` that returns answers or
    raises DnsError. Routed through the prefetcher so the PTR and address
    lookups behind %{p} are speculated too, and so nothing here ever touches
    the evaluator's counters."""

    def __init__(self, prefetcher: "Prefetcher") -> None:
        self._pf = prefetcher

    async def query(self, name: str, rtype: str) -> tuple[str, list[str]]:
        answer = await self._pf.lookup(name, rtype)
        if answer is None:
            raise DnsError("prefetch budget exhausted")
        rcode, answers = answer
        if rcode not in (NOERROR, NXDOMAIN):
            raise DnsError(f"{rtype} {name}: {rcode}")
        return rcode, answers


class Prefetcher:
    def __init__(
        self,
        resolver: BaseResolver,
        limits: Limits,
        ip,
        sender: str,
        helo: str,
        receiver: str,
    ) -> None:
        self.resolver = resolver
        self.limits = limits
        self.ip = ip
        self.sender = sender
        self.helo = helo
        self.receiver = receiver
        self.stats = PrefetchStats(concurrency=limits.prefetch_concurrency)
        self._sem = asyncio.Semaphore(limits.prefetch_concurrency)
        # Own cap on speculative traffic, separate from the evaluator's budget.
        # Sharing one counter would let speculation exhaust the budget and
        # turn a record that evaluates cleanly into a permerror.
        self._cap = limits.max_queries
        self._lookups: dict[Key, asyncio.Task] = {}
        self._walkers: set[asyncio.Task] = set()
        self._seen: set[str] = set()
        # Each nesting level costs at least one DNS term, so the sequential
        # evaluator cannot go deeper than the term limit lets it.
        self._max_depth = (
            limits.audit_max_terms if limits.audit else limits.max_terms
        )
        self._macro_session = _MacroSession(self)
        self._started = time.monotonic()
        self._closed = False

    # ---------- lifecycle ----------

    def start(self, domain: str, policy_text: str | None = None) -> None:
        """Begin walking from `domain`. Returns immediately; the walk runs as
        background tasks on the current loop."""
        if policy_text is None:
            # Issued here, synchronously, so the evaluator's very first query
            # finds it rather than sending its own and leaving the walker's
            # copy as waste.
            self._issue(domain, "TXT")
        self._spawn_walker(domain, policy_text, depth=0)

    async def close(self) -> PrefetchStats:
        """Cancel whatever is still speculating. Called once the verdict is
        known: nothing after that point is worth a DNS query."""
        if self._closed:
            return self.stats
        self._closed = True
        pending = [t for t in self._walkers if not t.done()]
        for t in pending:
            t.cancel()
        for t in self._lookups.values():
            if not t.done():
                t.cancel()
                self.stats.cancelled += 1
        await asyncio.gather(*self._walkers, *self._lookups.values(),
                             return_exceptions=True)
        self.stats.wall_ms = (time.monotonic() - self._started) * 1000.0
        return self.stats

    # ---------- the evaluator's side ----------

    def claim(self, key: Key):
        """Hand the evaluator something to await for `key`, or None if nothing
        was speculated for it. A task that failed for a reason other than DNS
        is not handed out: the evaluator does the lookup live and a bug in
        speculation stays a speed problem, never a verdict problem."""
        task = self._lookups.get(key)
        if task is None:
            return None
        if task.done():
            if task.cancelled():
                return None
            exc = task.exception()
            if exc is not None and not isinstance(exc, DnsError):
                return None
        self.stats.served += 1
        return self._serve(task, key)

    async def _serve(self, task: asyncio.Task, key: Key) -> tuple[str, list[str]]:
        try:
            answer = await task
        except (DnsError, asyncio.TimeoutError, asyncio.CancelledError):
            # The same outcomes a live lookup produces; let the session map
            # them to temperror exactly as it would have.
            raise
        except Exception:
            # Anything else is a speculation defect. Fall back to the live
            # lookup so it costs latency and never the verdict.
            name, rtype = key
            return await self.resolver._lookup(name, rtype)
        # One turn of the loop before handing the answer back. The evaluator
        # awaited this task first, so it would otherwise wake first and ask
        # for the next lookup before the walker, woken by the same answer,
        # has issued it. That turn lets the walker's issue pass run, so the
        # evaluator's next query finds a task instead of going live and
        # leaving the walker's copy as a duplicate.
        await asyncio.sleep(0)
        return answer

    # ---------- the speculative side ----------

    def _issue(self, name: str, rtype: str) -> asyncio.Task | None:
        """Start a speculative lookup, or return the one already started.

        Synchronous on purpose. The walker issues every first-level lookup of
        a record in one uninterrupted pass so that, by the time the evaluator
        asks for any of them, the task already exists to be claimed. See
        `_serve` for the other half of that arrangement.
        """
        key = (name.lower().rstrip("."), rtype)
        task = self._lookups.get(key)
        if task is not None:
            return task
        if self._closed:
            return None
        if self._cap is not None and self.stats.issued >= self._cap:
            return None
        if self.limits.remaining() <= 0:
            return None
        # Counted at creation, synchronously, so the cap is exact under
        # concurrency rather than racing between the check and the increment.
        self.stats.issued += 1
        task = asyncio.create_task(self._fetch(name, rtype))
        self._lookups[key] = task
        return task

    async def _fetch(self, name: str, rtype: str) -> tuple[str, list[str]]:
        async with self._sem:
            return await asyncio.wait_for(
                self.resolver._lookup(name, rtype),
                timeout=max(self.limits.remaining(), 0.0),
            )

    async def lookup(self, name: str, rtype: str) -> tuple[str, list[str]] | None:
        """Issue and await a speculative lookup. Never raises: a failure ends
        this branch of the walk, and the evaluator does the lookup live if it
        turns out to need it."""
        return await self._await(self._issue(name, rtype))

    async def _await(self, task: asyncio.Task | None):
        if task is None:
            return None
        try:
            # Shielded so cancelling a walker never cancels a lookup the
            # evaluator may be waiting on at the same moment.
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    def _spawn_walker(self, domain: str, policy_text: str | None, depth: int) -> None:
        if self._closed:
            return
        task = asyncio.create_task(self._walk(domain, policy_text, depth))
        self._walkers.add(task)

    async def _walk(self, domain: str, policy_text: str | None, depth: int) -> None:
        """Read one policy, issue every lookup its terms could need, then
        follow the ones that lead somewhere (includes, MX exchanges, PTR
        names)."""
        from .evaluator import valid_domain  # circular at module level

        domain_key = domain.lower().rstrip(".")
        if depth > self._max_depth or domain_key in self._seen:
            return
        self._seen.add(domain_key)

        if policy_text is None:
            if not valid_domain(domain):
                return
            answer = await self.lookup(domain, "TXT")
            if answer is None:
                return
            _, answers = answer
            records = [a for a in answers if VERSION_RE.match(a)]
            if len(records) != 1:
                return
            policy_text = records[0]

        try:
            record = parse(policy_text)
        except SpfPermError:
            return

        ctx = MacroContext(
            ip=self.ip,
            sender=self.sender,
            helo=self.helo,
            domain=domain,
            receiver=self.receiver,
            session=self._macro_session,
        )
        rtype = "A" if ctx.is_v4 else "AAAA"

        terms = [t for t in record.terms if t.is_mechanism]
        if record.redirect is not None:
            terms.append(record.redirect)

        # Pass one, synchronous: every term whose target needs no macro
        # expansion (the overwhelming common case — plain include: domains,
        # a, mx with a bare host) is issued here in one uninterrupted burst.
        # No await runs between them, so all of a record's siblings exist as
        # tasks before the loop yields, and the evaluator that resolved this
        # record's TXT finds each one already in flight to claim rather than
        # racing it to a live lookup. Terms needing a macro are deferred to
        # pass two; MX/PTR follow-ups are deferred because they need an answer.
        deferred = []
        follow_ups = []
        for term in terms:
            if term.name in ("all", "ip4", "ip6"):
                continue
            target = self._plain_target(term, ctx)
            if target is None and term.arg is not None and "%" in term.arg:
                deferred.append(term)
                continue
            self._issue_for(term, target, ctx, rtype, follow_ups, depth)

        # Pass two: macro targets (expansion may await, e.g. %{p}), then the
        # follow-ups that depend on an answer (MX exchanges, PTR names).
        for term in deferred:
            target = await self._target(term, ctx)
            self._issue_for(term, target, ctx, rtype, follow_ups, depth)
        if follow_ups:
            await asyncio.gather(*follow_ups, return_exceptions=True)

    def _issue_for(self, term, target, ctx, rtype, follow_ups, depth) -> None:
        """Issue the speculative lookup(s) a single term implies. Shared by
        both passes so a plain and a macro target are handled identically once
        the target is known."""
        if term.name == "ptr":
            # ptr keys off the connecting IP, not the (validated) target, so
            # it can run even when the target failed to resolve.
            task = self._issue(ctx.ip.reverse_pointer, "PTR")
            if task is not None and target is not None:
                follow_ups.append(self._follow_ptr(task, target, rtype))
            return
        if target is None:
            return
        if term.name in ("include", "redirect"):
            self._issue(target, "TXT")
            self._spawn_walker(target, None, depth + 1)
        elif term.name == "a":
            self._issue(target, rtype)
        elif term.name == "exists":
            self._issue(target, "A")
        elif term.name == "mx":
            task = self._issue(target, "MX")
            if task is not None:
                follow_ups.append(self._follow_mx(task, rtype))

    def _plain_target(self, term, ctx: MacroContext) -> str | None:
        """The term's target when it needs no macro expansion, else None.

        A macro-free domain-spec expands to itself, so the target is known
        without awaiting. This is what lets pass one run synchronously. Returns
        None both for an invalid target and for one that needs expansion; the
        caller distinguishes the two by looking for '%' in the arg.
        """
        from .evaluator import valid_domain

        if term.arg is None:
            target = ctx.domain
        elif "%" in term.arg:
            return None
        else:
            target = truncate_domain(term.arg)
        return target if valid_domain(target) else None

    async def _target(self, term, ctx: MacroContext) -> str | None:
        """Mirror of Evaluator._target without the trace. Macro expansion is
        a pure function of the inputs (plus DNS for %{p}, routed through the
        prefetcher), so this predicts the same target the evaluator will
        compute."""
        from .evaluator import valid_domain

        if term.arg is None:
            target = ctx.domain
        else:
            try:
                target = truncate_domain(await expand(term.arg, ctx))
            except (SpfPermError, ValueError):
                return None
        return target if valid_domain(target) else None

    async def _follow_mx(self, mx_task: asyncio.Task, rtype: str) -> None:
        from .evaluator import MAX_MX_RECORDS

        answer = await self._await(mx_task)
        if answer is None:
            return
        _, exchanges = answer
        if len(exchanges) > MAX_MX_RECORDS:
            return  # the evaluator permerrors here; nothing more is needed
        tasks = [self._issue(x, rtype) for x in exchanges]
        await asyncio.gather(*(self._await(t) for t in tasks), return_exceptions=True)

    async def _follow_ptr(self, ptr_task: asyncio.Task, target: str, rtype: str) -> None:
        from .evaluator import MAX_PTR_NAMES

        answer = await self._await(ptr_task)
        if answer is None:
            return
        _, names = answer
        target_l = target.lower().rstrip(".")
        wanted = [
            n for n in names[:MAX_PTR_NAMES]
            if n.lower().rstrip(".") == target_l
            or n.lower().rstrip(".").endswith("." + target_l)
        ]
        tasks = [self._issue(n, rtype) for n in wanted]
        await asyncio.gather(*(self._await(t) for t in tasks), return_exceptions=True)
