# Changelog

## 0.2.1

### Added

- **Address lookups are now in the trace.** Every DNS query was already recorded
  in `Result.queries`, but only TXT lookups produced a trace event. A `mx` that
  did not match therefore rendered as "Evaluating mechanism mx" followed by "The
  mechanism did not match", with the MX query and the per-exchange A/AAAA
  lookups invisible — the one detail someone debugging a legitimate sender is
  looking for. `EvaluationSession.query` now emits a `dns_lookup` event for
  every non-TXT query, carrying name, rtype, rcode, answers, ms, source
  (`dns`/`cache`) and the term that caused it. TXT is unchanged: the evaluator
  emits `txt_lookup` because it knows whether the answer is a policy.
- The CLI renders those lookups under the mechanism that issued them, listing
  the answers so the reader can see the addresses the client IP was compared
  against, and marking cache hits so the elapsed times still read correctly.

This is additive. No verdict changes, and `schema_version` stays at 1.

## 0.2.0

An external review of 0.1.1 found that DNS state which belongs to a single SPF
evaluation was living on the resolver instead. Reusing a resolver, which the
0.1.1 README explicitly recommended, therefore carried one check's state into
the next. This release separates the two. The core SPF semantics are unchanged
and all 203 RFC 7208 conformance cases still pass.

### Fixed

- **A previous check could change a later check's verdict.** The void-lookup
  count lived on the resolver, so a shared resolver made an unrelated later
  evaluation inherit it. A domain that evaluated to `pass` on a fresh resolver
  returned `permerror` on a reused one. Void counting is now per evaluation.
- **The DNS query budget drained across checks.** `max_queries` was a resolver
  lifetime cap, so a long-running service using a shared resolver would begin
  returning `permerror` for legitimate senders once the budget ran out. It is
  now a per-evaluation cap, which is what an MTA needs: one budget per message.
- **The resolver cache never expired.** Entries, including NXDOMAIN, were kept
  for the life of the resolver with no TTL, so a published SPF change was
  invisible to a long-running process. The cache is now scoped to a single
  evaluation. Within a check it still removes duplicate lookups.
- **A returned `Result` could change afterwards.** `Result.queries` aliased the
  resolver's live list, so a later unrelated check appended to an already
  returned result. Results are now snapshots.
- **Sharing a resolver across concurrent evaluations was unsafe.** With counters
  and cache moved off the resolver, concurrent checks no longer interfere.
- **`Evaluator` was silently one-shot.** A second `evaluate()` call reused the
  first run's trace, counters and spent `policy_override`, so identical inputs
  could return different verdicts. `evaluate()` now builds fresh state each call
  and is safe to reuse.
- **The void limit was enforced too late.** Voids were counted as they happened
  but only enforced after the enclosing mechanism finished, so an `mx` with a
  dozen dead exchanges issued every lookup before returning `permerror`. The
  limit is a resource-exhaustion protection, so it is now enforced the moment
  the offending lookup returns. The verdict is unchanged; the DNS traffic is
  not. Audit mode still counts past the limit for visibility.
- **`spftrace --version` reported the wrong version.** `__version__` was
  maintained separately from the package metadata and had been left at `0.1.0`
  in the 0.1.1 release. It is now derived from installed package metadata.
- **The CLI printed the default time limit even when `--time-limit` was given.**
  Presentation only; the correct value was always used for evaluation.
- **Invalid configuration failed late and obscurely.** A non-positive
  `time_limit` or `timeout`, a `max_queries` below 1, or an empty `nameservers`
  sequence now raise `SpfUsageError` at the API boundary.

### Changed

- `time_limit` is now checked before every DNS query as well as between terms,
  and caps the remaining time of each lookup. Previously a single mechanism
  issuing many slow lookups could overrun the limit by an unbounded margin.
  It remains a cooperative deadline, not a hard real-time guarantee.
- Void-limit trace events (`void_lookup`, `limit_exceeded`) are now emitted at
  the query that caused them rather than at the end of the mechanism, and carry
  a `name` key for the DNS name alongside the existing `term`.

### Breaking

- `LiveResolver` and `ZoneResolver` no longer accept `max_queries`. Pass it on
  `Limits`, or as the existing `max_queries=` argument to `check`/`acheck`.
- `BaseResolver` no longer has `queries`, `network_queries`, `void_count`,
  `max_queries` or `_cache`. Subclasses only implement `_lookup`, which is
  unchanged. Read the counters from `Result` instead.
- `Limits` and the constants `DEFAULT_TIME_LIMIT`, `DEFAULT_MAX_QUERIES`,
  `MAX_DNS_TERMS` and `MAX_VOID_LOOKUPS` moved from `spftrace.evaluator` to
  `spftrace.session`. The top-level `spftrace.` imports are unchanged.
- `Limits.sync_void()` is gone. The session enforces the void limit directly.
- `Evaluator.limits` is now the live per-run copy, replaced on each
  `evaluate()`. The caller's configuration is kept on `Evaluator.limits_template`.
- `cli.render_text()` takes a `time_limit` argument.
- `MacroContext` takes `session=` instead of `resolver=` and no longer takes
  `limits=`.

### Migration

```python
# 0.1.1
resolver = LiveResolver(["192.0.2.53"], timeout=3.0, max_queries=75)
result = await Evaluator(resolver, Limits()).evaluate(ip, sender, helo)

# 0.2.0
resolver = LiveResolver(["192.0.2.53"], timeout=3.0)
result = await Evaluator(resolver, Limits(max_queries=75)).evaluate(ip, sender, helo)
```

Callers using `spftrace.check()` or `spftrace.acheck()` without passing their own
resolver need no changes. Those paths always built fresh state per call and were
not affected by the state-lifetime defects above.

### Added

- `spftrace.EvaluationSession`, the per-evaluation DNS state object.
- `tests/test_lifecycle.py`: 19 tests covering state isolation between checks,
  concurrent use of one resolver, evaluator reuse, cache lifetime, early void
  enforcement, deadline behaviour under slow DNS, version consistency and
  configuration validation. Sixteen of them fail against 0.1.1.

## 0.1.1

- Packaging fixes.

## 0.1.0

- Initial release.
