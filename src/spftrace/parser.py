"""RFC 7208 Section 12 grammar: parse a policy into terms, or fail loudly."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .errors import SpfPermError
from .macros import validate_macro_string

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DNS_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}

VERSION_RE = re.compile(r"^v=spf1(?=$| )", re.I)
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-_.]*$")
IP4_CIDR_RE = re.compile(r"^(0|[1-9]\d?)$")
IP6_CIDR_RE = re.compile(r"^(0|[1-9]\d{0,2})$")
IP4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
TOPLABEL_RE = re.compile(
    r"^(?:[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9])$"
)
MACRO_EXPAND_END_RE = re.compile(r"(?:%\{[a-zA-Z]\d*[rR]?[.\-+,/_=]*\}|%%|%_|%-)$")
PRINTABLE_RE = re.compile(r"^[\x20-\x7e]*$")


@dataclass
class Term:
    raw: str
    is_mechanism: bool
    name: str  # mechanism name or modifier name
    qualifier: str = "+"
    arg: str | None = None  # domain-spec / network / macro-string
    cidr4: int | None = None
    cidr6: int | None = None
    index: int = 0


@dataclass
class Record:
    text: str
    terms: list[Term] = field(default_factory=list)
    redirect: Term | None = None
    exp: Term | None = None
    warnings: list[str] = field(default_factory=list)


def _validate_domain_spec(spec: str, term: str) -> None:
    if not spec:
        raise SpfPermError(f"{term}: empty domain-spec")
    validate_macro_string(spec)
    if len(spec) > 255:
        raise SpfPermError(f"{term}: domain-spec too long")
    if MACRO_EXPAND_END_RE.search(spec):
        return
    body = spec[:-1] if spec.endswith(".") else spec
    if "." not in body:
        raise SpfPermError(f"{term}: domain-spec must be fully qualified: {spec!r}")
    toplabel = body.rsplit(".", 1)[1]
    if not TOPLABEL_RE.match(toplabel):
        raise SpfPermError(f"{term}: invalid top-level label {toplabel!r}")
    for label in body.split("."):
        if not label or len(label) > 63:
            raise SpfPermError(f"{term}: invalid label in {spec!r}")


def _parse_dual_cidr(rest: str, term: str) -> tuple[str, int | None, int | None]:
    """Strip a trailing [/n][//n] from the argument portion.

    Only an all-digit run counts as a CIDR length; "/" is otherwise a legal
    character inside a domain-spec (RFC 7208 s7.1/2), so a:foo/bar.example.com
    is a domain, not a syntax error.
    """
    cidr4 = cidr6 = None
    m = re.search(r"//(\d+)$", rest)
    if m:
        raw = m.group(1)
        if not IP6_CIDR_RE.match(raw) or int(raw) > 128:
            raise SpfPermError(f"{term}: bad ipv6 cidr {raw!r}")
        cidr6 = int(raw)
        rest = rest[: m.start()]
    m = re.search(r"(?<!/)/(\d+)$", rest)
    if m:
        raw = m.group(1)
        if not IP4_CIDR_RE.match(raw) or int(raw) > 32:
            raise SpfPermError(f"{term}: bad ipv4 cidr {raw!r}")
        cidr4 = int(raw)
        rest = rest[: m.start()]
    return rest, cidr4, cidr6


def _parse_ip4(value: str, term: str) -> tuple[str, int]:
    net, cidr = (value.split("/", 1) + [None])[:2] if "/" in value else (value, None)
    if cidr is not None:
        if not IP4_CIDR_RE.match(cidr):
            raise SpfPermError(f"{term}: bad cidr {cidr!r}")
        if int(cidr) > 32:
            raise SpfPermError(f"{term}: cidr out of range")
    m = IP4_RE.match(net)
    if not m:
        raise SpfPermError(f"{term}: invalid IPv4 network {net!r}")
    for octet in m.groups():
        if (len(octet) > 1 and octet[0] == "0") or int(octet) > 255:
            raise SpfPermError(f"{term}: invalid IPv4 network {net!r}")
    return net, 32 if cidr is None else int(cidr)


def _parse_ip6(value: str, term: str) -> tuple[str, int]:
    import ipaddress

    net, cidr = value.rsplit("/", 1) if "/" in value else (value, None)
    if cidr is not None:
        if not IP6_CIDR_RE.match(cidr):
            raise SpfPermError(f"{term}: bad cidr {cidr!r}")
        if int(cidr) > 128:
            raise SpfPermError(f"{term}: cidr out of range")
    try:
        ipaddress.IPv6Address(net)
    except ValueError as exc:
        raise SpfPermError(f"{term}: invalid IPv6 network {net!r}") from exc
    return net, 128 if cidr is None else int(cidr)


def parse(text: str) -> Record:
    if not PRINTABLE_RE.match(text):
        raise SpfPermError("record contains non-printable or non-ASCII characters")
    if not VERSION_RE.match(text):
        raise SpfPermError("record does not start with v=spf1")

    rec = Record(text=text)
    body = text[len("v=spf1") :]
    if body and not body.startswith(" "):
        raise SpfPermError("version must be followed by a space")

    raw_terms = [t for t in body.split(" ") if t]
    for i, raw in enumerate(raw_terms):
        rec.terms.append(_parse_term(raw, i, rec))
    return rec


def _parse_term(raw: str, index: int, rec: Record) -> Term:
    qualifier = "+"
    head = raw
    if head[0] in QUALIFIERS:
        qualifier, head = head[0], head[1:]
        if not head:
            raise SpfPermError(f"bare qualifier {raw!r}")

    lower = head.lower()
    name = re.split(r"[:/]", lower, 1)[0]

    # Modifier? Only when there is an "=" before any ":" or "/".
    eq = head.find("=")
    colon = head.find(":")
    slash = head.find("/")
    is_modifier = eq > 0 and (colon == -1 or eq < colon) and (slash == -1 or eq < slash)

    if is_modifier:
        if raw[0] in QUALIFIERS:
            raise SpfPermError(f"modifier cannot take a qualifier: {raw!r}")
        mod_name, value = head.split("=", 1)
        if not NAME_RE.match(mod_name):
            raise SpfPermError(f"invalid modifier name {mod_name!r}")
        low = mod_name.lower()
        term = Term(raw=raw, is_mechanism=False, name=low, arg=value, index=index)
        if low in ("redirect", "exp"):
            _validate_domain_spec(value, low)
            if low == "redirect":
                if rec.redirect is not None:
                    raise SpfPermError("duplicate redirect modifier")
                rec.redirect = term
            else:
                if rec.exp is not None:
                    raise SpfPermError("duplicate exp modifier")
                rec.exp = term
        else:
            validate_macro_string(value)
            rec.warnings.append(f"unknown modifier {mod_name!r} ignored")
        return term

    if name not in MECHANISMS:
        raise SpfPermError(f"unknown mechanism {head!r}")

    rest = head[len(name) :]
    term = Term(raw=raw, is_mechanism=True, name=name, qualifier=qualifier, index=index)

    if name == "all":
        if rest:
            raise SpfPermError(f"'all' takes no argument: {raw!r}")
        return term

    if name in ("ip4", "ip6"):
        if not rest.startswith(":") or len(rest) == 1:
            raise SpfPermError(f"{name} requires a network argument")
        value = raw[raw.index(":") + 1 :]
        if name == "ip4":
            term.arg, term.cidr4 = _parse_ip4(value, name)
        else:
            term.arg, term.cidr6 = _parse_ip6(value, name)
        return term

    if name in ("include", "exists"):
        if not rest.startswith(":") or len(rest) == 1:
            raise SpfPermError(f"{name} requires a domain-spec")
        term.arg = raw[raw.index(":") + 1 :]
        _validate_domain_spec(term.arg, name)
        return term

    if name == "ptr":
        if rest:
            if not rest.startswith(":") or len(rest) == 1:
                raise SpfPermError("ptr: invalid argument")
            term.arg = raw[raw.index(":") + 1 :]
            _validate_domain_spec(term.arg, name)
        rec.warnings.append("'ptr' is deprecated (RFC 7208 s5.5); avoid it")
        return term

    # a / mx
    if rest.startswith(":"):
        arg = raw[raw.index(":") + 1 :]
        arg, term.cidr4, term.cidr6 = _parse_dual_cidr(arg, name)
        if not arg:
            raise SpfPermError(f"{name}: empty domain-spec")
        term.arg = arg
        _validate_domain_spec(arg, name)
    elif rest.startswith("/"):
        leftover, term.cidr4, term.cidr6 = _parse_dual_cidr(rest, name)
        if leftover:
            raise SpfPermError(f"{name}: invalid argument {rest!r}")
    elif rest:
        raise SpfPermError(f"{name}: invalid argument {rest!r}")
    return term
