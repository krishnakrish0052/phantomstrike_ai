"""
server_core.security — defensive hardening primitives for the tool platform.

Currently exposes :mod:`command_sanitizer`, used to neutralise OS command
injection at the boundary where user-supplied request parameters are
interpolated into shell command strings before being handed to
``execute_command`` (which runs them via ``subprocess.Popen(..., shell=True)``).
"""

from .command_sanitizer import (
    CommandSanitizationError,
    quote_arg,
    safe_extra_args,
    safe_url,
    safe_host,
    safe_port,
    safe_path,
    safe_token,
)

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
