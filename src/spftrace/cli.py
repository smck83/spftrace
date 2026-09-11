"""Command line front end. Renders the trace in the ORF-style step format."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from . import DEFAULT_MAX_QUERIES, DEFAULT_NAMESERVERS, __version__
from .evaluator import Evaluator
from .session import DEFAULT_TIME_LIMIT, MAX_VOID_LOOKUPS, Limits
from .resolver import LiveResolver
from .trace import Result

VERDICT = {
    "pass": "The policy designates the argument IP as a permitted sender.",
    "fail": "The policy does NOT designate the argument IP as a permitted sender.",
    "softfail": "The policy does NOT designate the argument IP as permitted sender, "
    "but it's not quite confident about it.",
    "neutral": "The policy makes no assertion about the argument IP.",
    "none": "No SPF policy was found for the domain.",
    "permerror": "The policy could not be evaluated: permanent error.",
    "temperror": "The policy could not be evaluated: transient error, retry later.",
}


def render_text(
    result: Result,
    dns_server: str = "",
    time_limit: float = DEFAULT_TIME_LIMIT,
) -> str:
    lines: list[str] = []
    if dns_server:
        lines.append("PARAMETERS")
        lines.append(f"DNS server: {dns_server}")
        lines.append(f"Evaluation time limit: {time_limit:g} seconds "
                     "(RFC 7208 Section 4.6.4)")
        lines.append(f"Maximum number of void DNS lookups: {MAX_VOID_LOOKUPS} "
                     "(RFC 7208 Section 4.6.4)")
        lines.append("Standards compliance: RFC 7208 (April 2014)")
        lines.append("")

    for ev in result.trace.to_list():
        indent = "  " * ev["depth"]
        stamp = f"+{ev['at_ms']:.0f} ms"
        kind = ev["kind"]
        head = f"{stamp:>10} {indent}"
        if kind == "check_start":
            lines.append(f"{head}SPF check starting.")
            lines.append(f"{head}  IP: {ev['ip']}")
            lines.append(f"{head}  Sender: {ev['sender']}")
            lines.append(f"{head}  Domain: {ev['domain']}")
            lines.append(f"{head}  EHLO/HELO domain: {ev['helo']}")
        elif kind == "txt_lookup":
            lines.append(f"{head}Retrieving DNS TXT record for \"{ev['domain']}\".")
            if ev["records"]:
                for i, rec in enumerate(ev["records"], 1):
                    lines.append(f"{head}  Line #{i}: \"{rec}\"")
            else:
                lines.append(f"{head}  No TXT records ({ev['rcode']}).")
        elif kind == "dns_lookup":
            via = " (from cache, no query sent)" if ev["source"] == "cache" else ""
            lines.append(
                f"{head}Retrieving DNS {ev['rtype']} record for "
                f"\"{ev['name']}\"{via}."
            )
            if ev["answers"]:
                for answer in ev["answers"]:
                    lines.append(f"{head}  {answer}")
            else:
                lines.append(f"{head}  No {ev['rtype']} records ({ev['rcode']}).")
        elif kind == "policy_override":
            lines.append(f"{head}Policy supplied by user for \"{ev['domain']}\" "
                         "(no DNS lookup, no DNS term consumed).")
            lines.append(f"{head}  Policy: \"{ev['policy']}\"")
        elif kind == "policy_parsed":
            lines.append(f"{head}The policy passed syntax validation.")
            lines.append(f"{head}Evaluating SPF mechanisms.")
        elif kind == "parse_error":
            lines.append(f"{head}Syntax error: {ev['message']}")
        elif kind == "mech_start":
            lines.append(f"{head}Evaluating mechanism \"{ev['mechanism']}\".")
            lines.append(f"{head}  Qualifier: \"{ev['qualifier']}\"")
            if ev.get("arg"):
                lines.append(f"{head}  Argument: \"{ev['arg']}\"")
            if ev.get("cidr4") is not None:
                lines.append(f"{head}  CIDR length (IPv4): {ev['cidr4']}")
            if ev.get("cidr6") is not None:
                lines.append(f"{head}  CIDR length (IPv6): {ev['cidr6']}")
            lines.append(
                f"{head}  DNS limits status: DNS terms {ev['dns_terms_used']} of 10 "
                f"allowed. Void lookups {ev['void_used']} of 2 allowed."
            )
        elif kind == "macro_expand" and ev.get("before"):
            lines.append(
                f"{head}Domain argument after macro expansion: \"{ev['after']}\"."
            )
        elif kind == "limit_exceeded":
            lines.append(
                f"{head}DNS lookup limit exceeded at \"{ev['term']}\" "
                f"({ev['used']} of {ev['allowed']}). {ev['note']}"
            )
        elif kind == "void_lookup":
            lines.append(
                f"{head}A void DNS lookup was encountered "
                f"({ev['used']} of {ev['allowed']} allowed) at \"{ev['term']}\"."
            )
        elif kind == "family_skip":
            lines.append(
                f"{head}The \"{ev['mechanism']}\" mechanism was {ev['note']}."
            )
        elif kind == "exists_miss":
            lines.append(
                f"{head}\"{ev['target']}\" returned {ev['rcode']}; {ev['note']}."
            )
        elif kind == "audit_override":
            lines.append(
                f"{head}Audit mode: evaluation reached \"{ev['observed']}\" but the "
                f"record needs {ev['dns_terms']} lookups of {ev['allowed']} allowed. "
                f"Returning \"permerror\"."
            )
        elif kind == "recurse_in":
            lines.append(f"{head}Entering recursive evaluation ({ev['via']}).")
        elif kind == "recurse_out":
            lines.append(
                f"{head}Returned from recursive evaluation with \"{ev['result']}\"."
            )
        elif kind == "mech_match":
            lines.append(
                f"{head}The mechanism matched with the \"{ev['result']}\" qualifier."
            )
        elif kind == "mech_nomatch":
            lines.append(f"{head}The mechanism did not match.")
        elif kind == "target_invalid":
            lines.append(f"{head}Target \"{ev['target']}\" is not a valid domain; "
                         "mechanism cannot match.")
        elif kind == "domain_invalid":
            lines.append(f"{head}Malformed domain \"{ev['domain']}\".")
        elif kind == "ptr_validated":
            lines.append(f"{head}Forward-confirmed PTR name \"{ev['name']}\".")
        elif kind == "mx_match":
            lines.append(f"{head}Matched via MX host \"{ev['exchange']}\".")
        elif kind == "eval_done":
            lines.append(
                f"{head}Policy evaluation for \"{ev['domain']}\" finished with "
                f"SPF \"{ev['result']}\"."
            )
        elif kind == "exp":
            lines.append(f"{head}Explanation from \"{ev['domain']}\": {ev['text']}")
        elif kind in ("exit", "error", "txt_error"):
            lines.append(f"{head}{ev.get('reason') or ev.get('message')}")
        elif kind == "result":
            pass

    lines.append("")
    lines.append("TEST SUMMARY")
    lines.append(
        f"The evaluation completed in {result.elapsed_ms:.0f} ms. "
        f"DNS terms used: {result.dns_terms_used} of 10. "
        f"Void lookups: {result.void_lookups_used} of 2."
    )
    lines.append(f"Result: SPF {result.result}")
    lines.append(VERDICT.get(result.result, ""))
    if result.explanation:
        lines.append(f"Explanation: {result.explanation}")
    for warning in result.warnings:
        lines.append(f"Warning: {warning}")
    return "\n".join(lines)


async def run(args: argparse.Namespace) -> int:
    resolver = LiveResolver(
        [args.dns], timeout=args.timeout
    )
    ev = Evaluator(
        resolver,
        Limits(
            time_limit=args.time_limit,
            max_queries=args.max_queries,
            audit=args.audit,
        ),
        receiver=args.receiver,
        policy_override=args.policy,
    )
    result = await ev.evaluate(args.ip, args.sender, args.helo or "")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(render_text(result, dns_server=args.dns, time_limit=args.time_limit))
    return 0 if result.result in ("pass", "neutral", "softfail", "fail", "none") else 1


def main() -> int:
    p = argparse.ArgumentParser(prog="spftrace", description="SPF evaluator with trace")
    p.add_argument("ip", help="connecting IP address")
    p.add_argument("sender", help="MAIL FROM address (or domain)")
    p.add_argument("--helo", help="HELO/EHLO domain")
    p.add_argument("--policy", help="override the sender domain's SPF record")
    p.add_argument(
        "--dns",
        default=os.environ.get("SPFTRACE_DNS", DEFAULT_NAMESERVERS[0]),
        help="resolver IP (or set SPFTRACE_DNS)",
    )
    p.add_argument(
        "--audit",
        action="store_true",
        help="keep counting lookups past the 10 limit; result stays permerror",
    )
    p.add_argument(
        "--max-queries", type=int, default=DEFAULT_MAX_QUERIES, dest="max_queries"
    )
    p.add_argument("--version", action="version", version=f"spftrace {__version__}")
    p.add_argument("--receiver", default="spftrace", help="value for the %%{r} macro")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout")
    p.add_argument("--time-limit", type=float, default=DEFAULT_TIME_LIMIT)
    p.add_argument("--json", action="store_true", help="emit the raw trace as JSON")
    return asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
