"""
kali_session_pool.py — Pooled manager for concurrent Kali tool PTY sessions.

Maintains a bounded set of active PTYSession instances with lookup,
listing, and bulk-kill operations.  Designed to be used as a singleton
via singletons.py.
"""

import logging
import threading
from typing import Dict, List, Optional

from .pty_session import PTYSession

logger = logging.getLogger(__name__)


class KaliSessionPool:
    """Pool of active Kali tool PTY sessions.

    Sessions are indexed by their unique ``session_id``.  The pool enforces
    a configurable maximum to prevent resource exhaustion.

    Typical usage::

        pool = KaliSessionPool(max_sessions=20)
        sess = pool.spawn("msfconsole", "msfconsole -q")
        # ... use sess ...
        pool.kill(sess.session_id)

    Attributes:
        sessions (dict):  ``{session_id: PTYSession}`` mapping.
        max (int):        maximum number of concurrent sessions.
    """

    def __init__(self, max_sessions: int = 20) -> None:
        """Initialise the session pool.

        Args:
            max_sessions:  hard cap on concurrent sessions.
        """
        self.sessions: Dict[str, PTYSession] = {}
        self.max = max_sessions
        self._lock = threading.Lock()
        logger.info("kali_session_pool: initialised (max=%d)", max_sessions)

    # ── Session lifecycle ──────────────────────────────────────────────────────

    def spawn(self, tool: str, command: str) -> Optional[PTYSession]:
        """Create and start a new PTY session for *tool*.

        If the pool is full the caller receives ``None`` — they should
        either wait and retry, or kill an idle session first.

        Args:
            tool:     human-readable tool name (e.g. ``"metasploit"``).
            command:  full CLI invocation string.

        Returns:
            A started ``PTYSession``, or ``None`` if the pool is full
            or the session failed to start.
        """
        with self._lock:
            if len(self.sessions) >= self.max:
                logger.warning(
                    "kali_session_pool: pool full (%d/%d) — rejecting %r",
                    len(self.sessions),
                    self.max,
                    tool,
                )
                return None

            sess = PTYSession(command)
            if not sess.start():
                logger.error(
                    "kali_session_pool: failed to start %r session",
                    tool,
                )
                return None

            self.sessions[sess.session_id] = sess
            logger.info(
                "kali_session_pool: spawned %s [%s] (%d/%d)",
                tool,
                sess.session_id,
                len(self.sessions),
                self.max,
            )
            return sess

    def get(self, sid: str) -> Optional[PTYSession]:
        """Retrieve a session by id, or ``None`` if not found."""
        with self._lock:
            return self.sessions.get(sid)

    def list_all(self) -> List[dict]:
        """Return a lightweight summary of every active session.

        Each entry contains ``session_id``, ``command``, ``is_active``,
        and ``uptime`` seconds — enough for dashboard display without
        serialising the entire PTY buffer.
        """
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "command": s.command,
                    "is_active": s.is_alive(),
                    "uptime": round(s.uptime, 1),
                    "output_lines": len(s.output_buffer),
                }
                for s in self.sessions.values()
            ]

    def kill(self, sid: str) -> bool:
        """Close and remove a single session.  Returns True if it existed."""
        with self._lock:
            sess = self.sessions.pop(sid, None)
        if sess is None:
            logger.debug("kali_session_pool: kill %r — not found", sid)
            return False
        sess.close()
        logger.info(
            "kali_session_pool: killed %r (%d/%d)",
            sid,
            len(self.sessions),
            self.max,
        )
        return True

    def kill_all(self) -> int:
        """Close every active session and return the count killed."""
        with self._lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        count = len(sessions)
        for sess in sessions:
            try:
                sess.close()
            except Exception as exc:
                logger.warning(
                    "kali_session_pool: error closing session %s — %s",
                    sess.session_id,
                    exc,
                )
        logger.info("kali_session_pool: killed all %d sessions", count)
        return count

    @property
    def count(self) -> int:
        """Current number of active sessions."""
        with self._lock:
            return len(self.sessions)

    @property
    def is_full(self) -> bool:
        """True if no more sessions can be spawned."""
        with self._lock:
            return len(self.sessions) >= self.max

    # ── Cleanup ────────────────────────────────────────────────────────────────

    def __del__(self) -> None:
        """Best-effort cleanup on garbage collection."""
        try:
            self.kill_all()
        except Exception:
            pass
