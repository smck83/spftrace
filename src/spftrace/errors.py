"""SPF evaluation errors, mapped to RFC 7208 result codes."""
from __future__ import annotations


class SpfError(Exception):
    result = "permerror"


class SpfPermError(SpfError):
    result = "permerror"


class SpfTempError(SpfError):
    result = "temperror"


class SpfNoneError(SpfError):
    """Not an error as such: check_host() exits with 'none'."""

    result = "none"


class SpfUsageError(RuntimeError):
    """Caller error, not an RFC outcome.

    Raised for mistakes in how spftrace is called, never for anything a remote
    domain's DNS can cause. RFC results always come back as a verdict on Result.
    """
