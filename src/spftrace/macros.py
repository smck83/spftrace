"""RFC 7208 Section 7 macro expansion."""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Any

from .errors import SpfPermError

DELIMS = ".-+,/_="
UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

MACRO_RE = re.compile(
    r"%(?:(%)|(_)|(-)|\{([a-zA-Z])(\d*)([rR]?)([.\-+,/_=]*)\}|(.|$))"
)

# macro-literal = %x21-24 / %x26-7E  (visible, excluding "%")
LITERAL_OK = re.compile(r"^[\x21-\x24\x26-\x7e]*$")


@dataclass
class MacroContext:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    sender: str  # localpart@domain
    helo: str
    domain: str  # <domain> of the current check_host()
    receiver: str = "spftrace"
    #: The EvaluationSession for this check. Macros that touch DNS (%{p})
    #: go through it so their lookups are counted and traced like any other.
    session: Any = None

    @property
    def localpart(self) -> str:
        return self.sender.rsplit("@", 1)[0] or "postmaster"

    @property
    def sender_domain(self) -> str:
        return self.sender.rsplit("@", 1)[-1]

    @property
    def is_v4(self) -> bool:
        return self.ip.version == 4

    def ip_macro(self) -> str:
        if self.is_v4:
            return str(self.ip)
        # IPv6 expands to dot-separated nibbles
        packed = self.ip.packed.hex()
        return ".".join(packed)

    def ip_readable(self) -> str:
        return str(self.ip)

    def ip_version_label(self) -> str:
        return "in-addr" if self.is_v4 else "ip6"


async def validated_domain(ctx: MacroContext) -> str:
    """The %{p} macro: PTR of the connecting IP, forward-confirmed."""
    from .resolver import DnsError

    rev = (
        ipaddress.ip_address(str(ctx.ip)).reverse_pointer
        if not isinstance(ctx.ip, str)
        else ""
    )
    try:
        _, names = await ctx.session.query(rev, "PTR")
    except DnsError:
        return "unknown"
    if not names:
        return "unknown"
    candidates: list[str] = []
    # RFC 7208 4.6.4: no more than 10 PTR names are processed.
    for name in names[:10]:
        rtype = "A" if ctx.is_v4 else "AAAA"
        try:
            _, addrs = await ctx.session.query(name, rtype)
        except DnsError:
            continue
        for addr in addrs:
            try:
                if ipaddress.ip_address(addr) == ctx.ip:
                    candidates.append(name.rstrip("."))
                    break
            except ValueError:
                continue
    if not candidates:
        return "unknown"
    target = ctx.domain.lower().rstrip(".")
    for name in candidates:
        if name.lower() == target:
            return name
    for name in candidates:
        if name.lower().endswith("." + target):
            return name
    return candidates[0]


def _transform(value: str, digits: str, reverse: bool, delims: str) -> str:
    seps = delims or "."
    parts = re.split("[" + re.escape(seps) + "]", value)
    if reverse:
        parts.reverse()
    if digits:
        n = int(digits)
        if n == 0:
            raise SpfPermError("macro digit transformer must be non-zero")
        parts = parts[-n:]
    return ".".join(parts)


def _url_escape(value: str) -> str:
    out = []
    for ch in value:
        if ch in UNRESERVED:
            out.append(ch)
        else:
            out.extend("%%%02X" % b for b in ch.encode("utf-8"))
    return "".join(out)


async def expand(macro_string: str, ctx: MacroContext, exp: bool = False) -> str:
    """Expand a macro-string. Raises SpfPermError on invalid syntax."""
    out: list[str] = []
    pos = 0
    for m in MACRO_RE.finditer(macro_string):
        literal = macro_string[pos : m.start()]
        if not LITERAL_OK.match(literal):
            raise SpfPermError(f"invalid character in macro-string: {literal!r}")
        out.append(literal)
        pos = m.end()
        pct, underscore, hyphen, letter, digits, rev, delims, bad = m.groups()
        if pct:
            out.append("%")
            continue
        if underscore:
            out.append(" ")
            continue
        if hyphen:
            out.append("%20")
            continue
        if bad is not None:
            raise SpfPermError("invalid macro escape '%%%s'" % bad)
        low = letter.lower()
        if low in ("c", "r", "t") and not exp:
            raise SpfPermError(f"macro %{{{letter}}} is only valid in exp text")
        if low == "s":
            value = ctx.sender
        elif low == "l":
            value = ctx.localpart
        elif low == "o":
            value = ctx.sender_domain
        elif low == "d":
            value = ctx.domain
        elif low == "i":
            value = ctx.ip_macro()
        elif low == "p":
            value = await validated_domain(ctx)
        elif low == "v":
            value = ctx.ip_version_label()
        elif low == "h":
            value = ctx.helo
        elif low == "c":
            value = ctx.ip_readable()
        elif low == "r":
            value = ctx.receiver
        elif low == "t":
            value = str(int(time.time()))
        else:
            raise SpfPermError(f"unknown macro letter {letter!r}")
        value = _transform(value, digits, bool(rev), delims)
        if letter.isupper():
            value = _url_escape(value)
        out.append(value)
    tail = macro_string[pos:]
    if not LITERAL_OK.match(tail):
        raise SpfPermError(f"invalid character in macro-string: {tail!r}")
    out.append(tail)
    return "".join(out)


def truncate_domain(name: str) -> str:
    """RFC 7208 s7.3: trim leading labels until <= 253 characters."""
    name = name.rstrip(".")
    while len(name) > 253 and "." in name:
        name = name.split(".", 1)[1]
    return name


ALLOWED_LETTERS = set("slodiphv")
EXP_ONLY_LETTERS = set("crt")


def validate_macro_string(macro_string: str, exp: bool = False) -> None:
    """Syntax-only validation, performed at parse time (RFC 7208 s7.1)."""
    pos = 0
    for m in MACRO_RE.finditer(macro_string):
        literal = macro_string[pos : m.start()]
        if not LITERAL_OK.match(literal):
            raise SpfPermError(f"invalid character in macro-string: {literal!r}")
        pos = m.end()
        pct, underscore, hyphen, letter, digits, rev, delims, bad = m.groups()
        if pct or underscore or hyphen:
            continue
        if bad is not None:
            raise SpfPermError("invalid macro escape '%%%s'" % bad)
        low = letter.lower()
        if low in EXP_ONLY_LETTERS:
            if not exp:
                raise SpfPermError(
                    f"macro %{{{letter}}} is only valid in exp text"
                )
        elif low not in ALLOWED_LETTERS:
            raise SpfPermError(f"unknown macro letter {letter!r}")
        if digits and int(digits) == 0:
            raise SpfPermError("macro digit transformer must be non-zero")
    tail = macro_string[pos:]
    if not LITERAL_OK.match(tail):
        raise SpfPermError(f"invalid character in macro-string: {tail!r}")
