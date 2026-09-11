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

The tree is walked by callback, not by a parallel coroutine racing the
evaluator. When a record's TXT lookup is issued, a done-callback is attached
that parses the record and issues its children the instant the TXT resolves.
Callbacks fire in the order they were registered, and the prefetcher registers
its callback at issue time — before the evaluator has even awaited the same
task. So the children of a record are always issued before the evaluator,
resuming from that record's TXT, gets to iterate its terms. No sleeps, no
races: at every level the evaluator finds the next lookup already in flight.

Two rules keep the correctness promise:

  * A prefetched answer is accounted as a live lookup, not a cache hit. It
    goes through the query budget and the void count in EvaluationSession
    exactly as if the evaluator had sent it, because a real MTA would have.
    Serving it as a cache hit would silently stop voids counting.

  * The prefetcher never raises into the evaluation and never shares the
    evaluator's counters. It has its own cap on speculative traffic; when it
    runs out, or a branch fails for any non-DNS reason, the evaluator simply
    does that lookup live. A speculation defect costs latency, never a verdict.

The cost is speculative traffic. On a record that matches at its first term
the prefetcher may still have fetched part of the tree. That is bounded by the
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
        # Async side tasks: macro-target resolution and MX/PTR follow-ups.
        # Tracked so close() can cancel them; the tree walk itself is driven
        # by done-callbacks, not tasks.
        self._tasks: set[asyncio.Task] = set()
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
        """Begin speculating from `domain`. Returns immediately.

        With a policy override the record is in hand, so its children are
        issued synchronously right now. Otherwise the root TXT is issued with
        the callback that will issue the children once it resolves.
        """
        if policy_text is None:
            self._issue_policy(domain, 0)
        else:
            self._issue_children(domain, policy_text, 0)

    async def close(self) -> PrefetchStats:
        """Cancel whatever is still speculating. Called once the verdict is
        known: nothing after that point is worth a DNS query."""
        if self._closed:
            return self.stats
        self._closed = True
        for t in self._tasks:
            if not t.done():
                t.cancel()
        for t in self._lookups.values():
            if not t.done():
                t.cancel()
                self.stats.cancelled += 1
        await asyncio.gather(*self._tasks, *self._lookups.values(),
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
            return await task
        except (DnsError, asyncio.TimeoutError, asyncio.CancelledError):
            # The same outcomes a live lookup produces; let the session map
            # them to temperror exactly as it would have.
            raise
        except Exception:
            # A speculation defect. Fall back to the live lookup so it costs
            # latency and never the verdict.
            name, rtype = key
            return await self.resolver._lookup(name, rtype)

    # ---------- the speculative side ----------

    def _issue(self, name: str, rtype: str) -> asyncio.Task | None:
        """Start a speculative lookup, or return the one already in flight for
        this name. Synchronous, so a whole record's worth of lookups can be
        issued in one uninterrupted burst."""
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
        this branch, and the evaluator does the lookup live if it needs it.
        Used by the async side (MX/PTR follow-ups and the %{p} macro)."""
        return await self._await(self._issue(name, rtype))

    async def _await(self, task: asyncio.Task | None):
        if task is None:
            return None
        try:
            # Shielded so cancelling a side task never cancels a lookup the
            # evaluator may be awaiting at the same moment.
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    def _spawn(self, coro) -> None:
        if self._closed:
            coro.close()
            return
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _issue_policy(self, domain: str, depth: int) -> None:
        """Issue a record's TXT and arrange for its children to be issued the
        moment it resolves. The done-callback is registered here, before the
        evaluator awaits the same task, so the children exist before the
        evaluator — resuming from this TXT — iterates the record's terms."""
        from .evaluator import valid_domain

        if self._closed or depth > self._max_depth or not valid_domain(domain):
            return
        key = (domain.lower().rstrip("."), "TXT")
        already = key in self._lookups
        task = self._issue(domain, "TXT")
        if task is None or already:
            return
        task.add_done_callback(
            lambda t, d=domain, dep=depth: self._on_policy(d, dep, t)
        )

    def _on_policy(self, domain: str, depth: int, task: asyncio.Task) -> None:
        """Done-callback: the TXT for `domain` has resolved. Issue its
        children. Never raises — a callback that raised would only reach the
        loop's exception handler and speculation is best-effort anyway."""
        try:
            if task.cancelled() or task.exception() is not None:
                return
            _, answers = task.result()
        except Exception:
            return
        records = [a for a in answers if VERSION_RE.match(a)]
        if len(records) != 1:
            return
        self._issue_children(domain, records[0], depth)

    def _issue_children(self, domain: str, policy_text: str, depth: int) -> None:
        """Synchronously issue every lookup this record's terms could need.

        Macro-free targets (the common case: plain `include:` domains, `a`,
        `mx host`) are issued right here in one burst. Terms needing macro
        expansion, and the MX/PTR follow-ups that depend on an answer, are
        handed to async side tasks.
        """
        key = domain.lower().rstrip(".")
        if self._closed or depth > self._max_depth or key in self._seen:
            return
        self._seen.add(key)

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

        for term in terms:
            if term.name in ("all", "ip4", "ip6"):
                continue
            if term.arg is not None and "%" in term.arg:
                # Expansion may await (e.g. %{p} does DNS); resolve off-thread.
                self._spawn(self._resolve_macro_term(term, ctx, rtype, depth))
                continue
            target = self._plain_target(term, ctx)
            follow = self._dispatch(term, target, ctx, rtype, depth)
            if follow is not None:
                self._spawn(follow)

    def _dispatch(self, term, target, ctx, rtype, depth):
        """Issue the lookup(s) one term implies, given its already-computed
        target. Returns a follow-up coroutine (MX/PTR) to be awaited, or None.
        Synchronous, so it is safe to call from `_issue_children`'s burst."""
        name = term.name
        if name == "ptr":
            # ptr keys off the connecting IP, not the target, so it runs even
            # when the target itself did not resolve.
            task = self._issue(ctx.ip.reverse_pointer, "PTR")
            if task is not None and target is not None:
                return self._follow_ptr(task, target, rtype)
            return None
        if target is None:
            return None
        if name in ("include", "redirect"):
            self._issue_policy(target, depth + 1)
        elif name == "a":
            self._issue(target, rtype)
        elif name == "exists":
            self._issue(target, "A")
        elif name == "mx":
            task = self._issue(target, "MX")
            if task is not None:
                return self._follow_mx(task, rtype)
        return None

    async def _resolve_macro_term(self, term, ctx, rtype, depth) -> None:
        target = await self._target(term, ctx)
        follow = self._dispatch(term, target, ctx, rtype, depth)
        if follow is not None:
            await follow

    def _plain_target(self, term, ctx: MacroContext) -> str | None:
        """The term's target when it needs no macro expansion, else None.

        A macro-free domain-spec expands to itself, so the target is known
        without awaiting. This is what lets the issue burst run synchronously.
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
        """Mirror of Evaluator._target without the trace. Macro expansion is a
        pure function of the inputs (plus DNS for %{p}, routed through the
        prefetcher), so this predicts the same target the evaluator computes."""
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
