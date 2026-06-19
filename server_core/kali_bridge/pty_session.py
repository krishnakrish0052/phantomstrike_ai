"""
pty_session.py — PTY-based interactive tool control for Kali tools.

Supports: msfconsole, meterpreter, sqlmap shell, hydra, nc, ssh,
and any other interactive CLI tool that expects a terminal.

Uses pexpect for robust pseudo-terminal management with full output
capture, timeout handling, and graceful cleanup.
"""

import logging
import os
import re
import signal
import time
import uuid
from typing import List, Optional

logger = logging.getLogger(__name__)


# ── ANSI / control-sequence stripping ────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][0-9;]*[^\x07]*\x07|\x1b\].*?\x1b\\|\r")


class PTYSession:
    """Pseudo-terminal control for interactive Kali tools.

    Wraps a pexpect.spawn process and provides synchronous send/receive
    with sensible timeouts.  Output is buffered in-memory and available
    for retrieval at any time.

    Typical usage::

        sess = PTYSession("msfconsole -q")
        if sess.start():
            out = sess.send("use auxiliary/scanner/portscan/tcp")
            out = sess.send("set RHOSTS 192.168.1.1")
            out = sess.send("run")
        sess.close()

    Attributes:
        session_id (str):  unique 12-char session identifier.
        command (str):     the CLI command string used to spawn the process.
        output_buffer (list):  all output lines captured so far.
        is_active (bool):  whether the underlying process is still alive.
    """

    def __init__(self, command: str, session_id: Optional[str] = None) -> None:
        """Initialise a PTYSession for the given command.

        Args:
            command:     full CLI invocation (e.g. ``"sqlmap -u http://target"``).
            session_id:  optional override for the auto-generated session id.
        """
        self.session_id = session_id or str(uuid.uuid4())[:12]
        self.command = command
        self.process = None          # pexpect.spawn instance
        self.output_buffer: List[str] = []
        self.is_active = False
        self._read_timeout = 2       # seconds to wait for output after send
        self._start_time: Optional[float] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Spawn the command inside a PTY and return True on success.

        Sets the terminal dimensions to a generous size so that tools
        that paginate output (e.g. msfconsole) do not choke.

        Returns:
            True if the process was spawned successfully, False otherwise.
        """
        try:
            import pexpect  # deferred import — only Kali hosts need this
        except ImportError:
            logger.error(
                "pty_session: pexpect is not installed — "
                "PTY sessions require pexpect (pip install pexpect)."
            )
            return False

        try:
            self.process = pexpect.spawn(
                self.command,
                encoding="utf-8",
                timeout=30,
                env=self._build_env(),
            )
            # Set generous terminal dimensions to avoid pagination issues.
            self.process.setwinsize(200, 80)   # rows, cols
            self.is_active = True
            self._start_time = time.time()
            logger.info(
                "pty_session [%s]: spawned %r",
                self.session_id,
                self.command,
            )

            # Consume initial banner / prompt — most tools print something.
            try:
                self.process.expect(".+", timeout=3)
                initial = self._clean(self.process.before or "")
                if initial:
                    self.output_buffer.append(initial)
            except Exception:
                pass  # some tools produce no banner at all

            return True

        except Exception as exc:
            logger.error(
                "pty_session [%s]: failed to spawn %r — %s",
                self.session_id,
                self.command,
                exc,
            )
            self.is_active = False
            return False

    def send(self, cmd: str) -> str:
        """Send a command to the interactive tool and return captured output.

        The command string is sent followed by a newline.  The method
        waits up to ``_read_timeout`` seconds for output before returning
        whatever was captured so far.

        Args:
            cmd:  the command string to send (without trailing newline).

        Returns:
            The captured output text (ANSI codes stripped).  Empty string
            if the session is no longer alive.
        """
        if not self.is_alive():
            logger.warning(
                "pty_session [%s]: send called on dead session",
                self.session_id,
            )
            return ""

        try:
            self.process.sendline(cmd)
            # Some tools need a moment to start producing output.
            time.sleep(0.3)
            output = self.read_output()
            return output
        except Exception as exc:
            logger.error(
                "pty_session [%s]: send failed — %s",
                self.session_id,
                exc,
            )
            self.is_active = False
            return ""

    def read_output(self) -> str:
        """Drain any pending output from the PTY and return it.

        Non-blocking: returns whatever is available immediately without
        waiting for a prompt or delimiter.

        Returns:
            Cleaned output text, or empty string if nothing is pending.
        """
        if not self.is_alive():
            return ""

        try:
            self.process.expect(".+", timeout=self._read_timeout)
            raw = self.process.before or ""
            cleaned = self._clean(raw)
            if cleaned:
                self.output_buffer.append(cleaned)
            return cleaned
        except Exception:
            # Timeout or EOF — return whatever was buffered before the call.
            try:
                residual = self._clean(self.process.before or "")
                if residual:
                    self.output_buffer.append(residual)
                return residual
            except Exception:
                return ""

    def read_until(self, pattern: str, timeout: int = 10) -> str:
        """Block until *pattern* appears in output, then return all captured text.

        Useful for waiting on specific prompts (e.g. ``"meterpreter >"``)
        after issuing a long-running command.

        Args:
            pattern:  a regex pattern (pexpect style) or literal string.
            timeout:  maximum seconds to wait.

        Returns:
            All text captured before the pattern matched.  Returns empty
            string on timeout.
        """
        if not self.is_alive():
            return ""
        try:
            index = self.process.expect([pattern, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
            raw = self.process.before or ""
            cleaned = self._clean(raw)
            if cleaned:
                self.output_buffer.append(cleaned)
            return cleaned
        except Exception:
            return ""

    # ── Status ─────────────────────────────────────────────────────────────────

    def is_alive(self) -> bool:
        """Return True if the underlying process is running."""
        if self.process is None:
            return False
        return self.process.isalive() and self.is_active

    @property
    def uptime(self) -> float:
        """Seconds since the session was started (0 if never started)."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def full_output(self) -> str:
        """Return the entire output buffer as a single string."""
        return "\n".join(self.output_buffer)

    # ── Cleanup ────────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Gracefully terminate the PTY process and mark the session inactive."""
        if self.process is None:
            return
        try:
            # Try graceful first, then SIGKILL.
            self.process.sendline("exit")
            time.sleep(0.5)
            if self.process.isalive():
                self.process.terminate(force=True)
        except Exception:
            pass
        finally:
            self.is_active = False
            logger.info(
                "pty_session [%s]: closed (uptime %.1fs)",
                self.session_id,
                self.uptime,
            )

    def __del__(self) -> None:
        """Ensure the PTY is cleaned up even if the caller forgets."""
        try:
            self.close()
        except Exception:
            pass

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _clean(text: str) -> str:
        """Strip ANSI escape sequences, carriage returns, and trailing whitespace."""
        if not text:
            return ""
        cleaned = _ANSI_RE.sub("", text)
        cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
        return cleaned.strip()

    @staticmethod
    def _build_env() -> dict:
        """Build a clean environment dict for the spawned process.

        Inherits the current environment but removes any variables that
        might interfere with interactive tool behaviour.
        """
        env = os.environ.copy()
        # Prevent pagination in tools that respect PAGER.
        env.setdefault("PAGER", "cat")
        env.setdefault("MANPAGER", "cat")
        # Ensure UTF-8 terminal.
        env.setdefault("LANG", "en_US.UTF-8")
        env.setdefault("LC_ALL", "en_US.UTF-8")
        env["TERM"] = "xterm-256color"
        return env
