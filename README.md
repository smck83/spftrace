# spftrace

An RFC 7208 SPF evaluator that shows its working.

Most SPF libraries answer `pass` or `fail` and throw the reasoning away. spftrace
returns the reasoning: every DNS query with its rcode and timing, every macro
expansion before and after, every mechanism with its qualifier and why it did or
did not match, the running DNS-term and void-lookup counters, and the exact term
that broke a limit.

It is a library. There is no web UI here, and no framework dependency. Build your
own CLI, API or service on top.

- Own implementation of `check_host()`, not a wrapper around another evaluator
- Passes all 203 cases of the official openspf.org RFC 7208 test suite
- Async core with a blocking convenience wrapper
- One runtime dependency: dnspython
- Reads no environment variables and no system resolver config. Configuration is
  explicit, so the consuming application stays in charge

## Install

```
pip install spftrace
```

## Use

```python
import spftrace

result = spftrace.check("203.0.113.1", "user@example.com")

print(result.verdict)          # pass, fail, softfail, neutral, none,
                               # permerror or temperror
print(result.dns_terms_used)   # against the RFC limit of 10
print(result.to_dict())        # JSON-safe, with the full event trace
```

From async code, await the async form instead. Calling `check()` inside a running
event loop raises `SpfUsageError` telling you so, rather than a confusing asyncio
error from several frames down.

```python
result = await spftrace.acheck("203.0.113.1", "user@example.com")
```

### In FastAPI

```python
from fastapi import FastAPI
import spftrace

app = FastAPI()

@app.get("/check")
async def check(ip: str, sender: str):
    result = await spftrace.acheck(
        ip, sender, nameservers=["1.1.1.1"], max_queries=75
    )
    return result.to_dict()
```

Do not let users pass arbitrary resolver addresses through to `nameservers`. That
turns your service into an SSRF-ish DNS proxy. Offer a fixed set of resolvers and
map the user's choice to one server side.

### Options

```python
await spftrace.acheck(
    ip,
    sender,
    helo="mail.example.net",     # defaults to the sender domain
    policy="v=spf1 -all",        # evaluate this instead of looking one up
    nameservers=["192.0.2.53"],  # defaults to 8.8.8.8
    timeout=5.0,                 # per-query DNS timeout
    max_queries=75,              # hard cap on real lookups
    time_limit=20.0,             # deadline, checked between terms and before
                                 # every DNS query
    receiver="mta01",            # value of the %{r} macro
    audit=False,                 # see below
)
```

`policy=` evaluates a record you paste in rather than one published in DNS, which
is how you test a change before shipping it.

### Bring your own resolver

Pass a `resolver` instead of `nameservers` to point at your own DNS, or to test
with no network at all.

```python
from spftrace import Evaluator, Limits, ZoneResolver

zone = {"e.com": [("TXT", "v=spf1 ip4:1.2.3.0/24 -all")]}
result = await Evaluator(ZoneResolver(zone), Limits()).evaluate("1.2.3.4", "a@e.com")
```

Subclass `BaseResolver` and implement
`async _lookup(name, rtype) -> (rcode, answers)` for anything else. That method is
the whole contract: return the rcode and the answer strings, and let the library
do the rest.

**A resolver is transport only.** It holds nameservers, a timeout and a socket.
It holds no counters, no cache and no trace. Everything scoped to a single check
lives in an `EvaluationSession` that `evaluate()` builds fresh each time, so one
resolver can serve many checks, including concurrent ones, without leaking state
between them.

```python
resolver = LiveResolver(["192.0.2.53"])   # build once, reuse for the process

async def check(ip, sender):
    return await spftrace.acheck(ip, sender, resolver=resolver)
```

This is a change in 0.2.0. Before it, the query budget, the void count, the query
trace and the DNS cache all lived on the resolver, so reusing one carried a
previous check's state into the next and could turn a passing message into a
`permerror`. See CHANGELOG.md.

The lookup cache is deliberately scoped to one evaluation. Within a check it
still removes duplicate lookups, which is where nearly all the benefit is. Across
checks it would have no TTL, and serving a stale SPF record is an authentication
error rather than a performance detail. A shared TTL-aware cache may arrive later
as an explicit opt-in.

## Errors are verdicts

RFC outcomes are never exceptions. A malformed record, a lookup-limit breach, an
exhausted query budget and a DNS timeout all come back as a `permerror` or
`temperror` verdict with the reason in the trace. You do not have to wrap a check
in `try` just to survive a hostile zone.

`SpfUsageError` is the exception you may see, and it always means the calling code
is wrong: `check()` from inside an event loop, `resolver` and `nameservers`
supplied together, or a configuration value out of range such as a non-positive
`time_limit`.

## Audit mode

The 10-term limit means evaluation stops at the eleventh lookup, so neither a real
MTA nor a normal check can tell you how many lookups an over-limit record actually
needs. `audit=True` keeps counting past the limit and reports the true figure.

The verdict is still forced to `permerror`. Visibility changes; the answer never
does. A matching mechanism sitting past the limit does not become a `pass`.

## Command line

```
spftrace 203.0.113.1 user@example.com
spftrace 203.0.113.1 user@example.com --json
spftrace 203.0.113.1 user@example.com --policy "v=spf1 include:_spf.example.net -all"
spftrace 203.0.113.1 user@example.com --dns 1.1.1.1 --audit
```

`--dns` also reads `SPFTRACE_DNS`. That environment variable is a CLI convenience
only; the library itself never reads it.

## Result

| Attribute | Meaning |
| --- | --- |
| `verdict` (alias `result`) | the RFC 7208 result string |
| `explanation` | expanded `exp=` text, on `fail` only |
| `trace` | ordered `Event` log with recursion depth |
| `queries` | every DNS query: name, type, rcode, answers, ms, void, source |
| `dns_terms_used` | terms consumed against the limit of 10 |
| `void_lookups_used` | void lookups against the limit of 2 |
| `elapsed_ms` | wall time for the evaluation |
| `warnings` | non-fatal notes about the record |
| `prefetch` | speculation stats when `prefetch=True`, else `None` |

`to_dict()` is the stable JSON contract and carries `schema_version`. Additive keys
will not bump it; a change consumers must notice will.

The trace shows every lookup, not just the ones that decided the verdict. A `mx`
term emits a `dns_lookup` event for the MX query and one for each exchange it
resolves, so a mechanism that did not match still tells you which hosts were
checked and what they resolved to. Only the exchanges actually queried appear:
`mx` stops at the first match, and the trace does not imply work that never
happened. The address family follows the connecting IP, per RFC 7208 section 5.3
— an IPv4 client produces `A` lookups only, an IPv6 client `AAAA` only, never
both.

## Parallel DNS prefetch

Evaluation is sequential because SPF is short-circuit: the first matching
mechanism decides the verdict, and that ordering is what fixes the term and
void counts. But the DNS behind a record need not be sequential. A record like
`_netblocks.mimecast.com`, which fans out to five regional includes, spends
almost all its wall time waiting on round trips taken one at a time.

`prefetch=True` speculates those lookups in parallel — up to ten at once —
while the untouched sequential evaluator runs and finds each answer already
waiting:

```python
r = spftrace.check(ip, sender, prefetch=True)   # or Limits(prefetch=True), or --prefetch
```

The verdict, the term count, the void count and the order of the trace are
identical to a sequential run; only wall time changes. This is verified by
running the full RFC 7208 corpus both ways and asserting they agree on every
case. A prefetched answer is charged to the query budget and the void count
like any live lookup, because a receiving MTA would have sent it; speculation
is capped, is cancelled the moment the verdict is known, and on any failure
falls back to a live lookup, so it can never change the answer. The cost is
speculative traffic on records that match early — reported in `Result.prefetch`.
Off by default.

## Limits enforced

- 10 DNS terms over `include`, `a`, `mx`, `ptr`, `exists` and `redirect`, not
  `ip4`, `ip6` or `all`
- 2 void lookups, counted once per real lookup by the evaluation session, and
  enforced the moment the third one returns rather than at the end of the
  mechanism. An `mx` pointing at a dozen dead exchanges stops after the third,
  which is the point of the limit. Counting per term instead double counts:
  every enclosing `include` re-counts its children, and a single void three
  includes deep became a false `permerror`
- 10 MX records per `mx`, 10 PTR names per `ptr`
- `exp` and `%{p}` do DNS but do not count against the term limit
- A separate hard cap on real queries, 75 by default, because the term limit
  counts terms and not lookups: ten `mx` terms with ten MX records each is 10
  terms but 111 queries. The cap is per evaluation, so it resets for every
  message rather than draining over the life of a resolver

## Tests

```
pip install -e ".[test]"
pytest
```

The RFC 7208 corpus is fetched from a pinned commit and its sha256 is verified, so
the gate cannot shift underneath you. It is not vendored. `pytest --rfc-strict`
fails rather than skips when the corpus cannot be fetched; CI uses it.
`SPFTRACE_RFC_CORPUS=/path/to/rfc7208-tests.yml` runs the suite offline, still
hash-checked.

## Licence

MIT.
