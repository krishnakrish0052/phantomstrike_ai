"""
server_core/db.py

Shared SQLite database for PhantomStrike.

Single database file at <data_dir>/phantomstrike.db.
All tables are created on first run (CREATE TABLE IF NOT EXISTS).
Thread-safe via a single lock.

Design notes:
  - One connection per instance, kept open for the lifetime of the process.
  - WAL journal mode for better read/write concurrency.
  - Follows the same patterns as SessionStore / RunHistoryStore (SRP, KISS).
  - New feature areas add their own tables here — no separate DB files.

Current tables:
  llm_sessions        — one row per LLM analysis session
  llm_vulnerabilities — parsed vulnerabilities linked to a session
  chat_sessions       — named chat conversation threads
  chat_messages       — individual messages within a chat thread
  credentials         — discovered credentials/hashes/keys/tokens (loot)
  loot                — non-credential artifacts (flags, files, configs)
  exploit_generations — generated exploit code with verification status
  attack_chains       — multi-stage attack chain definitions
  browser_agent_sessions — browser agent exploration sessions
  http_proxy_history  — intercepted HTTP request/response history
  cve_intel_cache     — cached CVE intelligence data
  exploit_evidence    — evidence (screenshots, logs) for exploit generations
  http_testing_rules  — custom HTTP match/replace rules for testing
  bugbounty_assessments — bug bounty assessment sessions
  proxy_sessions      — phantom proxy session metadata
  defense_events      — defensive action audit log
  missions            — phased autonomous attack missions
  mission_phases      — individual phases within a mission
  mission_findings    — findings discovered during a mission phase
  kali_sessions       — active Kali tool PTY session bookkeeping
  cracked_hashes      — hash cracking results archive
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

import server_core.config_core as config_core

logger = logging.getLogger(__name__)

DB_FILE_NAME = "phantomstrike.db"


class PhantomStrikeDB:
  """Shared SQLite database.

  Instantiated once in singletons.py and shared across all blueprints.
  """

  def __init__(self, data_dir: Optional[str] = None) -> None:
    self._data_dir = data_dir or config_core.default_data_dir()
    self._db_path = os.path.join(self._data_dir, DB_FILE_NAME)
    self._lock = threading.Lock()
    os.makedirs(self._data_dir, exist_ok=True)
    self._conn = self._connect()
    self._ensure_tables()

  # ── Connection ──────────────────────────────────────────────────────────────

  def _connect(self) -> sqlite3.Connection:
    conn = sqlite3.connect(self._db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.commit()
    logger.debug("db: opened %s", self._db_path)
    return conn

  def _ensure_tables(self) -> None:
    """Create all tables if they don't exist yet."""
    with self._lock:
      cur = self._conn.cursor()
      cur.executescript("""
        CREATE TABLE IF NOT EXISTS llm_sessions (
          session_id    TEXT PRIMARY KEY,
          target        TEXT NOT NULL,
          objective     TEXT DEFAULT 'comprehensive',
          status        TEXT DEFAULT 'running',
          risk_level    TEXT,
          summary       TEXT,
          full_response TEXT,
          raw_scan_data TEXT,
          provider      TEXT,
          model         TEXT,
          tool_loops    INTEGER DEFAULT 0,
          started_at    TEXT DEFAULT (datetime('now')),
          completed_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS llm_vulnerabilities (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id  TEXT REFERENCES llm_sessions(session_id) ON DELETE CASCADE,
          vuln_name   TEXT,
          severity    TEXT,
          port        TEXT,
          service     TEXT,
          description TEXT,
          fix_text    TEXT,
          created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_sessions (
          id         TEXT PRIMARY KEY,
          name       TEXT DEFAULT '',
          summary    TEXT DEFAULT '',
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
          id              INTEGER PRIMARY KEY AUTOINCREMENT,
          chat_session_id TEXT REFERENCES chat_sessions(id) ON DELETE CASCADE,
          role            TEXT NOT NULL,
          content         TEXT NOT NULL,
          stats           TEXT DEFAULT NULL,
          is_summarized   INTEGER DEFAULT 0,
          created_at      TEXT DEFAULT (datetime('now'))
        );
      """)
      self._conn.commit()

    # ── Auto-migrations ───────────────────────────────────────────────────────
    self._migrate_chat_messages_stats()
    self._migrate_credentials_loot()
    self._migrate_orchestrator_tables()

    logger.debug("db: tables verified")

  # ── Auto-migrations ─────────────────────────────────────────────────────────

  def _migrate_chat_messages_stats(self) -> None:
    """Add stats column to chat_messages if missing (existing DBs)."""
    cur = self._conn.execute("PRAGMA table_info(chat_messages)")
    columns = {row[1] for row in cur.fetchall()}
    if "stats" not in columns:
      self._conn.execute("ALTER TABLE chat_messages ADD COLUMN stats TEXT DEFAULT NULL")
      self._conn.commit()
      logger.info("db: migrated chat_messages — added stats column")

  def _migrate_credentials_loot(self) -> None:
    """Create credentials and loot tables if missing (existing DBs)."""
    with self._lock:
      self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS credentials (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id  TEXT,
          cred_id     TEXT UNIQUE NOT NULL,
          type        TEXT NOT NULL DEFAULT 'plaintext',
          username    TEXT DEFAULT '',
          secret      TEXT DEFAULT '',
          hash_type   TEXT DEFAULT '',
          service     TEXT DEFAULT '',
          host        TEXT DEFAULT '',
          port        TEXT DEFAULT '',
          source_tool TEXT DEFAULT '',
          evidence    TEXT DEFAULT '',
          tags        TEXT DEFAULT '[]',
          verified    INTEGER DEFAULT 0,
          notes       TEXT DEFAULT '',
          created_at  TEXT DEFAULT (datetime('now')),
          updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
        CREATE INDEX IF NOT EXISTS idx_credentials_host    ON credentials(host);
        CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
        CREATE INDEX IF NOT EXISTS idx_credentials_type    ON credentials(type);

        CREATE TABLE IF NOT EXISTS loot (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id  TEXT,
          loot_id     TEXT UNIQUE NOT NULL,
          loot_type   TEXT NOT NULL DEFAULT 'other',
          title       TEXT NOT NULL,
          content     TEXT DEFAULT '',
          path        TEXT DEFAULT '',
          host        TEXT DEFAULT '',
          source_tool TEXT DEFAULT '',
          tags        TEXT DEFAULT '[]',
          notes       TEXT DEFAULT '',
          created_at  TEXT DEFAULT (datetime('now')),
          updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_loot_session ON loot(session_id);
        CREATE INDEX IF NOT EXISTS idx_loot_type    ON loot(loot_type);
        CREATE INDEX IF NOT EXISTS idx_loot_host    ON loot(host);

        CREATE TABLE IF NOT EXISTS exploit_generations (
          id                  INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id          TEXT,
          cve_id              TEXT DEFAULT '',
          vuln_type           TEXT NOT NULL,
          exploit_code        TEXT NOT NULL,
          target_info         TEXT DEFAULT '{}',
          language            TEXT DEFAULT 'python',
          evasion_applied     TEXT DEFAULT 'none',
          verified            INTEGER DEFAULT 0,
          verification_output TEXT DEFAULT '',
          created_at          TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS attack_chains (
          id             TEXT PRIMARY KEY,
          session_id     TEXT,
          chain_name     TEXT NOT NULL,
          target_software TEXT NOT NULL,
          stages_json    TEXT NOT NULL DEFAULT '[]',
          overall_prob   REAL DEFAULT 0.0,
          complexity     TEXT DEFAULT 'MEDIUM',
          notes          TEXT DEFAULT '',
          created_at     TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS browser_agent_sessions (
          id             TEXT PRIMARY KEY,
          session_id     TEXT,
          target_url     TEXT NOT NULL,
          screenshot_path TEXT DEFAULT '',
          page_source    TEXT DEFAULT '',
          network_logs   TEXT DEFAULT '[]',
          console_errors TEXT DEFAULT '[]',
          security_score INTEGER DEFAULT 0,
          findings_json  TEXT DEFAULT '[]',
          created_at     TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS http_proxy_history (
          id              INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id      TEXT,
          request_url     TEXT NOT NULL,
          request_method  TEXT DEFAULT 'GET',
          request_headers TEXT DEFAULT '{}',
          request_body    TEXT DEFAULT '',
          response_status INTEGER DEFAULT 0,
          response_headers TEXT DEFAULT '{}',
          response_body   TEXT DEFAULT '',
          vuln_findings   TEXT DEFAULT '[]',
          timestamp       TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS cve_intel_cache (
          cve_id            TEXT PRIMARY KEY,
          description       TEXT DEFAULT '',
          cvss_score        REAL DEFAULT 0.0,
          severity          TEXT DEFAULT '',
          published_date    TEXT DEFAULT '',
          affected_products TEXT DEFAULT '[]',
          exploit_data      TEXT DEFAULT '{}',
          cached_at         TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS exploit_evidence (
          id             INTEGER PRIMARY KEY AUTOINCREMENT,
          exploit_gen_id INTEGER REFERENCES exploit_generations(id) ON DELETE CASCADE,
          evidence_type  TEXT NOT NULL DEFAULT 'screenshot',
          evidence_path  TEXT DEFAULT '',
          evidence_data  TEXT DEFAULT '',
          notes          TEXT DEFAULT '',
          created_at     TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS http_testing_rules (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id    TEXT,
          name          TEXT NOT NULL DEFAULT '',
          rule_type     TEXT NOT NULL DEFAULT 'match_replace',
          where_clause  TEXT DEFAULT 'url',
          pattern       TEXT NOT NULL,
          replacement   TEXT DEFAULT '',
          enabled       INTEGER DEFAULT 1,
          created_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS bugbounty_assessments (
          id             TEXT PRIMARY KEY,
          session_id     TEXT,
          domain         TEXT NOT NULL,
          scope          TEXT DEFAULT '',
          out_of_scope   TEXT DEFAULT '',
          workflow_types TEXT DEFAULT '[]',
          findings_json  TEXT DEFAULT '{}',
          summary        TEXT DEFAULT '',
          created_at     TEXT DEFAULT (datetime('now')),
          completed_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_exploit_gen_cve ON exploit_generations(cve_id);
        CREATE INDEX IF NOT EXISTS idx_attack_chains_session ON attack_chains(session_id);
        CREATE INDEX IF NOT EXISTS idx_browser_sessions ON browser_agent_sessions(session_id);
        CREATE INDEX IF NOT EXISTS idx_http_history_url ON http_proxy_history(request_url);
        CREATE INDEX IF NOT EXISTS idx_http_history_session ON http_proxy_history(session_id);
        CREATE INDEX IF NOT EXISTS idx_bb_assess_session ON bugbounty_assessments(session_id);

        CREATE TABLE IF NOT EXISTS proxy_sessions (
          id TEXT PRIMARY KEY,
          exit_ip TEXT, circuit_id TEXT, identity_type TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          closed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS defense_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL, threat_level INTEGER DEFAULT 0,
          target TEXT, details TEXT DEFAULT '{}',
          action_taken TEXT, created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS missions (
          id TEXT PRIMARY KEY,
          prompt TEXT NOT NULL, status TEXT DEFAULT 'pending',
          stealth_level TEXT DEFAULT 'maximum',
          phases_json TEXT DEFAULT '[]',
          started_at TEXT, completed_at TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_missions_status ON missions(status);

        CREATE TABLE IF NOT EXISTS mission_phases (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE,
          phase_order INTEGER, agent_type TEXT,
          tools_used TEXT DEFAULT '[]', success INTEGER DEFAULT 0,
          findings_json TEXT DEFAULT '{}',
          started_at TEXT, completed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_mp_mission ON mission_phases(mission_id);

        CREATE TABLE IF NOT EXISTS mission_findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          mission_id TEXT, phase_id INTEGER,
          finding_type TEXT, severity TEXT,
          title TEXT, description TEXT,
          data_json TEXT DEFAULT '{}',
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_mf_mission ON mission_findings(mission_id);

        CREATE TABLE IF NOT EXISTS kali_sessions (
          session_id TEXT PRIMARY KEY,
          tool_name TEXT NOT NULL, command TEXT,
          is_active INTEGER DEFAULT 1,
          output_log TEXT DEFAULT '',
          spawned_at TEXT DEFAULT (datetime('now')),
          closed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS cracked_hashes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          hash TEXT NOT NULL, plaintext TEXT,
          hash_type TEXT, tool TEXT,
          gpu_used TEXT, cracked_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_ch_hash ON cracked_hashes(hash);
      """)
      self._conn.commit()
      logger.debug("db: credentials/loot tables verified")

  def _migrate_orchestrator_tables(self) -> None:
    """Create orchestrator-related tables if missing (existing DBs)."""
    with self._lock:
      self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS agent_actions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          mission_id TEXT, agent_id TEXT, agent_type TEXT,
          action_type TEXT, tool_name TEXT, params_json TEXT DEFAULT '{}',
          result_json TEXT DEFAULT '{}', success INTEGER DEFAULT 0,
          execution_time REAL DEFAULT 0.0,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_aa_mission ON agent_actions(mission_id);
        CREATE INDEX IF NOT EXISTS idx_aa_agent ON agent_actions(agent_id);

        CREATE TABLE IF NOT EXISTS agent_learnings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          technique TEXT NOT NULL, target_type TEXT,
          success_count INTEGER DEFAULT 0, failure_count INTEGER DEFAULT 0,
          defense_triggers TEXT DEFAULT '[]', avg_execution_time REAL DEFAULT 0.0,
          last_used_at TEXT, effectiveness_score REAL DEFAULT 0.5
        );

        CREATE TABLE IF NOT EXISTS fix_plans (
          id TEXT PRIMARY KEY,
          vuln_id TEXT, mission_id TEXT,
          title TEXT NOT NULL, description TEXT, root_cause TEXT,
          plan_json TEXT DEFAULT '{}', status TEXT DEFAULT 'pending_approval',
          approved_by TEXT, approved_at TEXT,
          executed_at TEXT, verified_at TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS bug_bounty_reports (
          id TEXT PRIMARY KEY,
          program_name TEXT, scope_domain TEXT,
          vulnerability_type TEXT, severity TEXT, cvss_score REAL,
          title TEXT, description TEXT, impact TEXT, remediation TEXT,
          poc_code TEXT, status TEXT DEFAULT 'draft',
          platform TEXT, platform_report_id TEXT,
          bounty_amount REAL DEFAULT 0.0,
          created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS supply_chain_findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package_name TEXT, package_registry TEXT, version TEXT,
          vulnerability_type TEXT, severity TEXT,
          description TEXT, cve_id TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS reverse_engineering_sessions (
          id TEXT PRIMARY KEY,
          file_name TEXT, file_type TEXT, file_hash TEXT,
          architecture TEXT, findings_json TEXT DEFAULT '{}',
          functions_identified INTEGER DEFAULT 0,
          vulnerabilities_found INTEGER DEFAULT 0,
          created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS agent_personas (
          id TEXT PRIMARY KEY,
          agent_type TEXT NOT NULL, persona_name TEXT,
          system_prompt TEXT, temperature REAL DEFAULT 0.7,
          max_tokens INTEGER DEFAULT 4096,
          created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS social_engineering_campaigns (
          id TEXT PRIMARY KEY,
          mission_id TEXT, campaign_type TEXT,
          targets_json TEXT DEFAULT '[]', template_json TEXT DEFAULT '{}',
          emails_sent INTEGER DEFAULT 0, clicks INTEGER DEFAULT 0,
          credentials_captured INTEGER DEFAULT 0,
          status TEXT DEFAULT 'draft',
          created_at TEXT DEFAULT (datetime('now'))
        );
      """)
      self._conn.commit()
      logger.debug("db: orchestrator tables verified")

  # ── Internal helpers ─────────────────────────────────────────────────────────

  def _row_to_dict(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
      return None
    return dict(row)

  def _rows_to_list(self, rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]

  # ── LLM Sessions ─────────────────────────────────────────────────────────────

  def create_llm_session(
    self,
    session_id: str,
    target: str,
    objective: str = "comprehensive",
    provider: str = "",
    model: str = "",
  ) -> None:
    """Insert a new LLM session row with status 'running'."""
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO llm_sessions
          (session_id, target, objective, provider, model, status)
        VALUES (?, ?, ?, ?, ?, 'running')
        """,
        (session_id, target, objective, provider, model),
      )
      self._conn.commit()

  def update_llm_session(self, session_id: str, **fields: Any) -> None:
    """Update one or more columns on an existing session row.

    Allowed fields: status, risk_level, summary, full_response,
                    raw_scan_data, tool_loops, completed_at
    """
    allowed = {
      "status", "risk_level", "summary", "full_response",
      "raw_scan_data", "tool_loops", "completed_at",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
      return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [session_id]
    with self._lock:
      self._conn.execute(
        f"UPDATE llm_sessions SET {set_clause} WHERE session_id = ?",
        values,
      )
      self._conn.commit()

  def get_llm_session(self, session_id: str) -> Optional[Dict[str, Any]]:
    """Return a single session dict, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM llm_sessions WHERE session_id = ?",
        (session_id,),
      )
      return self._row_to_dict(cur.fetchone())

  def list_llm_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
    """Return most recent sessions, newest first."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM llm_sessions ORDER BY started_at DESC LIMIT ?",
        (limit,),
      )
      return self._rows_to_list(cur.fetchall())

  # ── LLM Vulnerabilities ───────────────────────────────────────────────────────

  def save_llm_vulnerability(self, session_id: str, vuln: Dict[str, Any]) -> int:
    """Insert a parsed vulnerability and return its rowid."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO llm_vulnerabilities
          (session_id, vuln_name, severity, port, service, description, fix_text)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
          session_id,
          vuln.get("vuln_name", ""),
          vuln.get("severity", ""),
          vuln.get("port", ""),
          vuln.get("service", ""),
          vuln.get("description", ""),
          vuln.get("fix", vuln.get("fix_text", "")),
        ),
      )
      self._conn.commit()
      return cur.lastrowid

  def get_llm_vulnerabilities(self, session_id: str) -> List[Dict[str, Any]]:
    """Return all vulnerabilities for a session."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM llm_vulnerabilities WHERE session_id = ? ORDER BY id",
        (session_id,),
      )
      return self._rows_to_list(cur.fetchall())

  # ── Chat Sessions ─────────────────────────────────────────────────────────────

  def create_chat_session(self, session_id: str, name: str = "") -> Dict[str, Any]:
    """Insert a new chat session and return it as a dict."""
    with self._lock:
      self._conn.execute(
        "INSERT OR IGNORE INTO chat_sessions (id, name) VALUES (?, ?)",
        (session_id, name),
      )
      self._conn.commit()
      cur = self._conn.execute("SELECT * FROM chat_sessions WHERE id = ?", (session_id,))
      return self._row_to_dict(cur.fetchone()) or {}

  def rename_chat_session(self, session_id: str, name: str) -> None:
    """Update the name of a chat session."""
    with self._lock:
      self._conn.execute(
        "UPDATE chat_sessions SET name = ?, updated_at = datetime('now') WHERE id = ?",
        (name, session_id),
      )
      self._conn.commit()

  def update_chat_summary(self, session_id: str, summary: str) -> None:
    """Replace the rolling summary for a chat session."""
    with self._lock:
      self._conn.execute(
        "UPDATE chat_sessions SET summary = ?, updated_at = datetime('now') WHERE id = ?",
        (summary, session_id),
      )
      self._conn.commit()

  def delete_chat_session(self, session_id: str) -> None:
    """Delete a chat session and all its messages (CASCADE)."""
    with self._lock:
      self._conn.execute("DELETE FROM chat_sessions WHERE id = ?", (session_id,))
      self._conn.commit()

  def get_chat_session(self, session_id: str) -> Optional[Dict[str, Any]]:
    """Return a single chat session dict, or None."""
    with self._lock:
      cur = self._conn.execute("SELECT * FROM chat_sessions WHERE id = ?", (session_id,))
      return self._row_to_dict(cur.fetchone())

  def list_chat_sessions(self) -> List[Dict[str, Any]]:
    """Return all chat sessions, newest first."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM chat_sessions ORDER BY updated_at DESC"
      )
      return self._rows_to_list(cur.fetchall())

  # ── Chat Messages ─────────────────────────────────────────────────────────────

  def add_chat_message(self, chat_session_id: str, role: str, content: str, stats: Optional[str] = None) -> int:
    """Insert a message and return its rowid."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO chat_messages (chat_session_id, role, content, stats)
        VALUES (?, ?, ?, ?)
        """,
        (chat_session_id, role, content, stats),
      )
      self._conn.execute(
        "UPDATE chat_sessions SET updated_at = datetime('now') WHERE id = ?",
        (chat_session_id,),
      )
      self._conn.commit()
      return cur.lastrowid  # type: ignore[return-value]

  def get_active_chat_messages(self, chat_session_id: str) -> List[Dict[str, Any]]:
    """Return non-summarized messages for a session, oldest first."""
    with self._lock:
      cur = self._conn.execute(
        """
        SELECT * FROM chat_messages
        WHERE chat_session_id = ? AND is_summarized = 0
        ORDER BY id ASC
        """,
        (chat_session_id,),
      )
      return self._rows_to_list(cur.fetchall())

  def get_all_chat_messages(self, chat_session_id: str) -> List[Dict[str, Any]]:
    """Return all messages (including summarized) for a session, oldest first."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM chat_messages WHERE chat_session_id = ? ORDER BY id ASC",
        (chat_session_id,),
      )
      return self._rows_to_list(cur.fetchall())

  def mark_messages_summarized(self, message_ids: List[int]) -> None:
    """Mark a batch of messages as folded into the rolling summary."""
    if not message_ids:
      return
    placeholders = ",".join("?" for _ in message_ids)
    with self._lock:
      self._conn.execute(
        f"UPDATE chat_messages SET is_summarized = 1 WHERE id IN ({placeholders})",
        message_ids,
      )
      self._conn.commit()

  def count_active_chat_messages(self, chat_session_id: str) -> int:
    """Return count of non-summarized messages for a session."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT COUNT(*) FROM chat_messages WHERE chat_session_id = ? AND is_summarized = 0",
        (chat_session_id,),
      )
      row = cur.fetchone()
      return row[0] if row else 0

  # ── Credentials ───────────────────────────────────────────────────────────────

  def add_credential(self, cred: Dict[str, Any], session_id: Optional[str] = None) -> str:
    """Insert a credential record and return its cred_id."""
    import uuid
    cred_id = cred.get("cred_id") or f"cred_{uuid.uuid4().hex[:8]}"
    tags = json.dumps(cred.get("tags", []) if isinstance(cred.get("tags"), list) else [])
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO credentials
          (session_id, cred_id, type, username, secret, hash_type, service, host,
           port, source_tool, evidence, tags, verified, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
          session_id or cred.get("session_id", ""),
          cred_id,
          cred.get("type", "plaintext"),
          cred.get("username", ""),
          cred.get("secret", ""),
          cred.get("hash_type", ""),
          cred.get("service", ""),
          cred.get("host", ""),
          cred.get("port", ""),
          cred.get("source_tool", ""),
          cred.get("evidence", ""),
          tags,
          1 if cred.get("verified") else 0,
          cred.get("notes", ""),
        ),
      )
      self._conn.commit()
    return cred_id

  def get_credential(self, cred_id: str) -> Optional[Dict[str, Any]]:
    """Return a single credential dict or None."""
    with self._lock:
      cur = self._conn.execute("SELECT * FROM credentials WHERE cred_id = ?", (cred_id,))
      row = self._row_to_dict(cur.fetchone())
    if row and isinstance(row.get("tags"), str):
      try:
        row["tags"] = json.loads(row["tags"])
      except Exception:
        row["tags"] = []
    return row

  def list_credentials(
    self,
    session_id: Optional[str] = None,
    host: Optional[str] = None,
    service: Optional[str] = None,
    cred_type: Optional[str] = None,
    tag: Optional[str] = None,
    query: Optional[str] = None,
  ) -> List[Dict[str, Any]]:
    """Return credentials matching all provided filters."""
    clauses: List[str] = []
    params: List[Any] = []
    if session_id:
      clauses.append("session_id = ?")
      params.append(session_id)
    if host:
      clauses.append("host LIKE ?")
      params.append(f"%{host}%")
    if service:
      clauses.append("service LIKE ?")
      params.append(f"%{service}%")
    if cred_type:
      clauses.append("type = ?")
      params.append(cred_type)
    if tag:
      clauses.append("tags LIKE ?")
      params.append(f'%"{tag}"%')
    if query:
      clauses.append("(username LIKE ? OR host LIKE ? OR service LIKE ? OR notes LIKE ?)")
      params.extend([f"%{query}%"] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM credentials {where} ORDER BY created_at DESC",
        params,
      )
      rows = self._rows_to_list(cur.fetchall())
    for row in rows:
      if isinstance(row.get("tags"), str):
        try:
          row["tags"] = json.loads(row["tags"])
        except Exception:
          row["tags"] = []
    return rows

  def update_credential(self, cred_id: str, **fields: Any) -> None:
    """Update allowed fields on a credential row."""
    allowed = {
      "type", "username", "secret", "hash_type", "service", "host", "port",
      "source_tool", "evidence", "tags", "verified", "notes", "session_id",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
      return
    if "tags" in updates and isinstance(updates["tags"], list):
      updates["tags"] = json.dumps(updates["tags"])
    updates["updated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [cred_id]
    with self._lock:
      self._conn.execute(
        f"UPDATE credentials SET {set_clause} WHERE cred_id = ?",
        values,
      )
      self._conn.commit()

  def delete_credential(self, cred_id: str) -> None:
    """Delete a credential record."""
    with self._lock:
      self._conn.execute("DELETE FROM credentials WHERE cred_id = ?", (cred_id,))
      self._conn.commit()

  # ── Loot ──────────────────────────────────────────────────────────────────────

  def add_loot(self, loot: Dict[str, Any], session_id: Optional[str] = None) -> str:
    """Insert a loot record and return its loot_id."""
    import uuid
    loot_id = loot.get("loot_id") or f"loot_{uuid.uuid4().hex[:8]}"
    tags = json.dumps(loot.get("tags", []) if isinstance(loot.get("tags"), list) else [])
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO loot
          (session_id, loot_id, loot_type, title, content, path, host, source_tool, tags, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
          session_id or loot.get("session_id", ""),
          loot_id,
          loot.get("loot_type", "other"),
          loot.get("title", ""),
          loot.get("content", ""),
          loot.get("path", ""),
          loot.get("host", ""),
          loot.get("source_tool", ""),
          tags,
          loot.get("notes", ""),
        ),
      )
      self._conn.commit()
    return loot_id

  def get_loot(self, loot_id: str) -> Optional[Dict[str, Any]]:
    """Return a single loot record or None."""
    with self._lock:
      cur = self._conn.execute("SELECT * FROM loot WHERE loot_id = ?", (loot_id,))
      row = self._row_to_dict(cur.fetchone())
    if row and isinstance(row.get("tags"), str):
      try:
        row["tags"] = json.loads(row["tags"])
      except Exception:
        row["tags"] = []
    return row

  def list_loot(
    self,
    session_id: Optional[str] = None,
    loot_type: Optional[str] = None,
    host: Optional[str] = None,
    tag: Optional[str] = None,
    query: Optional[str] = None,
  ) -> List[Dict[str, Any]]:
    """Return loot records matching all provided filters."""
    clauses: List[str] = []
    params: List[Any] = []
    if session_id:
      clauses.append("session_id = ?")
      params.append(session_id)
    if loot_type:
      clauses.append("loot_type = ?")
      params.append(loot_type)
    if host:
      clauses.append("host LIKE ?")
      params.append(f"%{host}%")
    if tag:
      clauses.append("tags LIKE ?")
      params.append(f'%"{tag}"%')
    if query:
      clauses.append("(title LIKE ? OR content LIKE ? OR host LIKE ? OR notes LIKE ?)")
      params.extend([f"%{query}%"] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM loot {where} ORDER BY created_at DESC",
        params,
      )
      rows = self._rows_to_list(cur.fetchall())
    for row in rows:
      if isinstance(row.get("tags"), str):
        try:
          row["tags"] = json.loads(row["tags"])
        except Exception:
          row["tags"] = []
    return rows

  def update_loot(self, loot_id: str, **fields: Any) -> None:
    """Update allowed fields on a loot row."""
    allowed = {"loot_type", "title", "content", "path", "host", "source_tool", "tags", "notes", "session_id"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
      return
    if "tags" in updates and isinstance(updates["tags"], list):
      updates["tags"] = json.dumps(updates["tags"])
    updates["updated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [loot_id]
    with self._lock:
      self._conn.execute(
        f"UPDATE loot SET {set_clause} WHERE loot_id = ?",
        values,
      )
      self._conn.commit()

  def delete_loot(self, loot_id: str) -> None:
    """Delete a loot record."""
    with self._lock:
      self._conn.execute("DELETE FROM loot WHERE loot_id = ?", (loot_id,))
      self._conn.commit()

  # ── Exploit Generations ──────────────────────────────────────────────────────

  def create_exploit_generation(
    self,
    session_id: str,
    cve_id: str,
    vuln_type: str,
    exploit_code: str,
    target_info: str = '{}',
    language: str = 'python',
    evasion_applied: str = 'none',
  ) -> int:
    """Insert a new exploit generation row and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO exploit_generations
          (session_id, cve_id, vuln_type, exploit_code, target_info, language, evasion_applied)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, cve_id, vuln_type, exploit_code, target_info, language, evasion_applied),
      )
      self._conn.commit()
      return cur.lastrowid

  def get_exploit_generation(self, gen_id: int) -> Optional[Dict[str, Any]]:
    """Return a single exploit generation dict, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM exploit_generations WHERE id = ?",
        (gen_id,),
      )
      return self._row_to_dict(cur.fetchone())

  def list_exploit_generations(
    self,
    session_id: Optional[str] = None,
    vuln_type: Optional[str] = None,
    limit: int = 50,
  ) -> List[Dict[str, Any]]:
    """Return exploit generations, optionally filtered by session_id and/or vuln_type."""
    clauses: List[str] = []
    params: List[Any] = []
    if session_id:
      clauses.append("session_id = ?")
      params.append(session_id)
    if vuln_type:
      clauses.append("vuln_type = ?")
      params.append(vuln_type)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM exploit_generations {where} ORDER BY created_at DESC LIMIT ?",
        params + [limit],
      )
      return self._rows_to_list(cur.fetchall())

  def verify_exploit_generation(self, gen_id: int, verification_output: str) -> None:
    """Mark an exploit generation as verified with the given output."""
    with self._lock:
      self._conn.execute(
        "UPDATE exploit_generations SET verified = 1, verification_output = ? WHERE id = ?",
        (verification_output, gen_id),
      )
      self._conn.commit()

  # ── Attack Chains ────────────────────────────────────────────────────────────

  def create_attack_chain(
    self,
    id: str,
    session_id: str,
    chain_name: str,
    target_software: str,
    stages_json: str = '[]',
    overall_prob: float = 0.0,
    complexity: str = 'MEDIUM',
    notes: str = '',
  ) -> Dict[str, Any]:
    """Insert a new attack chain and return it as a dict."""
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO attack_chains
          (id, session_id, chain_name, target_software, stages_json, overall_prob, complexity, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (id, session_id, chain_name, target_software, stages_json, overall_prob, complexity, notes),
      )
      self._conn.commit()
      cur = self._conn.execute("SELECT * FROM attack_chains WHERE id = ?", (id,))
      return self._row_to_dict(cur.fetchone()) or {}

  def get_attack_chain(self, id: str) -> Optional[Dict[str, Any]]:
    """Return a single attack chain dict, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM attack_chains WHERE id = ?",
        (id,),
      )
      return self._row_to_dict(cur.fetchone())

  def list_attack_chains(
    self,
    session_id: Optional[str] = None,
    limit: int = 50,
  ) -> List[Dict[str, Any]]:
    """Return attack chains, optionally filtered by session_id."""
    if session_id:
      with self._lock:
        cur = self._conn.execute(
          "SELECT * FROM attack_chains WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
          (session_id, limit),
        )
        return self._rows_to_list(cur.fetchall())
    else:
      with self._lock:
        cur = self._conn.execute(
          "SELECT * FROM attack_chains ORDER BY created_at DESC LIMIT ?",
          (limit,),
        )
        return self._rows_to_list(cur.fetchall())

  def delete_attack_chain(self, id: str) -> None:
    """Delete an attack chain."""
    with self._lock:
      self._conn.execute("DELETE FROM attack_chains WHERE id = ?", (id,))
      self._conn.commit()

  # ── Browser Agent Sessions ───────────────────────────────────────────────────

  def create_browser_session(
    self,
    id: str,
    session_id: str,
    target_url: str,
    screenshot_path: str = '',
    page_source: str = '',
    network_logs: str = '[]',
    console_errors: str = '[]',
    security_score: int = 0,
    findings_json: str = '[]',
  ) -> Dict[str, Any]:
    """Insert a new browser agent session and return it as a dict."""
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO browser_agent_sessions
          (id, session_id, target_url, screenshot_path, page_source, network_logs, console_errors, security_score, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (id, session_id, target_url, screenshot_path, page_source, network_logs, console_errors, security_score, findings_json),
      )
      self._conn.commit()
      cur = self._conn.execute("SELECT * FROM browser_agent_sessions WHERE id = ?", (id,))
      return self._row_to_dict(cur.fetchone()) or {}

  def get_browser_session(self, id: str) -> Optional[Dict[str, Any]]:
    """Return a single browser agent session dict, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM browser_agent_sessions WHERE id = ?",
        (id,),
      )
      return self._row_to_dict(cur.fetchone())

  def list_browser_sessions(
    self,
    session_id: Optional[str] = None,
    limit: int = 50,
  ) -> List[Dict[str, Any]]:
    """Return browser agent sessions, optionally filtered by session_id."""
    if session_id:
      with self._lock:
        cur = self._conn.execute(
          "SELECT * FROM browser_agent_sessions WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
          (session_id, limit),
        )
        return self._rows_to_list(cur.fetchall())
    else:
      with self._lock:
        cur = self._conn.execute(
          "SELECT * FROM browser_agent_sessions ORDER BY created_at DESC LIMIT ?",
          (limit,),
        )
        return self._rows_to_list(cur.fetchall())

  # ── HTTP Proxy History ──────────────────────────────────────────────────────

  def add_http_history(
    self,
    session_id: str,
    request_url: str,
    request_method: str = 'GET',
    request_headers: str = '{}',
    request_body: str = '',
    response_status: int = 0,
    response_headers: str = '{}',
    response_body: str = '',
    vuln_findings: str = '[]',
  ) -> int:
    """Insert a new HTTP proxy history entry and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO http_proxy_history
          (session_id, request_url, request_method, request_headers, request_body,
           response_status, response_headers, response_body, vuln_findings)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, request_url, request_method, request_headers, request_body,
         response_status, response_headers, response_body, vuln_findings),
      )
      self._conn.commit()
      return cur.lastrowid

  def list_http_history(
    self,
    session_id: Optional[str] = None,
    url_pattern: Optional[str] = None,
    limit: int = 100,
  ) -> List[Dict[str, Any]]:
    """Return HTTP proxy history entries, optionally filtered."""
    clauses: List[str] = []
    params: List[Any] = []
    if session_id:
      clauses.append("session_id = ?")
      params.append(session_id)
    if url_pattern:
      clauses.append("request_url LIKE ?")
      params.append(f"%{url_pattern}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM http_proxy_history {where} ORDER BY timestamp DESC LIMIT ?",
        params + [limit],
      )
      return self._rows_to_list(cur.fetchall())

  def search_http_history(
    self,
    query: str,
    limit: int = 100,
  ) -> List[Dict[str, Any]]:
    """Search HTTP proxy history across request/response bodies and URLs."""
    like = f"%{query}%"
    with self._lock:
      cur = self._conn.execute(
        """
        SELECT * FROM http_proxy_history
        WHERE request_url LIKE ? OR request_body LIKE ? OR response_body LIKE ?
        ORDER BY timestamp DESC LIMIT ?
        """,
        (like, like, like, limit),
      )
      return self._rows_to_list(cur.fetchall())

  # ── CVE Intel Cache ─────────────────────────────────────────────────────────

  def upsert_cve_cache(
    self,
    cve_id: str,
    description: str = '',
    cvss_score: float = 0.0,
    severity: str = '',
    published_date: str = '',
    affected_products: str = '[]',
    exploit_data: str = '{}',
  ) -> None:
    """Insert or update a CVE cache entry."""
    with self._lock:
      self._conn.execute(
        """
        INSERT INTO cve_intel_cache
          (cve_id, description, cvss_score, severity, published_date, affected_products, exploit_data, cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(cve_id) DO UPDATE SET
          description = excluded.description,
          cvss_score = excluded.cvss_score,
          severity = excluded.severity,
          published_date = excluded.published_date,
          affected_products = excluded.affected_products,
          exploit_data = excluded.exploit_data,
          cached_at = datetime('now')
        """,
        (cve_id, description, cvss_score, severity, published_date, affected_products, exploit_data),
      )
      self._conn.commit()

  def get_cve_cache(self, cve_id: str) -> Optional[Dict[str, Any]]:
    """Return a single CVE cache entry, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM cve_intel_cache WHERE cve_id = ?",
        (cve_id,),
      )
      return self._row_to_dict(cur.fetchone())

  def search_cve_cache(
    self,
    query: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
  ) -> List[Dict[str, Any]]:
    """Search CVE cache by description text and/or severity."""
    clauses: List[str] = []
    params: List[Any] = []
    if query:
      clauses.append("(cve_id LIKE ? OR description LIKE ?)")
      params.extend([f"%{query}%", f"%{query}%"])
    if severity:
      clauses.append("severity = ?")
      params.append(severity)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM cve_intel_cache {where} ORDER BY cached_at DESC LIMIT ?",
        params + [limit],
      )
      return self._rows_to_list(cur.fetchall())

  # ── Exploit Evidence ────────────────────────────────────────────────────────

  def add_exploit_evidence(
    self,
    exploit_gen_id: int,
    evidence_type: str = 'screenshot',
    evidence_path: str = '',
    evidence_data: str = '',
    notes: str = '',
  ) -> int:
    """Insert a new exploit evidence record and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO exploit_evidence
          (exploit_gen_id, evidence_type, evidence_path, evidence_data, notes)
        VALUES (?, ?, ?, ?, ?)
        """,
        (exploit_gen_id, evidence_type, evidence_path, evidence_data, notes),
      )
      self._conn.commit()
      return cur.lastrowid

  def get_exploit_evidence(self, evidence_id: int) -> Optional[Dict[str, Any]]:
    """Return a single exploit evidence record, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM exploit_evidence WHERE id = ?",
        (evidence_id,),
      )
      return self._row_to_dict(cur.fetchone())

  def list_exploit_evidence(
    self,
    exploit_gen_id: Optional[int] = None,
    limit: int = 50,
  ) -> List[Dict[str, Any]]:
    """Return exploit evidence records, optionally filtered by exploit_gen_id."""
    if exploit_gen_id is not None:
      with self._lock:
        cur = self._conn.execute(
          "SELECT * FROM exploit_evidence WHERE exploit_gen_id = ? ORDER BY created_at DESC LIMIT ?",
          (exploit_gen_id, limit),
        )
        return self._rows_to_list(cur.fetchall())
    else:
      with self._lock:
        cur = self._conn.execute(
          "SELECT * FROM exploit_evidence ORDER BY created_at DESC LIMIT ?",
          (limit,),
        )
        return self._rows_to_list(cur.fetchall())

  # ── HTTP Testing Rules ──────────────────────────────────────────────────────

  def save_http_rule(
    self,
    session_id: str,
    name: str = '',
    rule_type: str = 'match_replace',
    where_clause: str = 'url',
    pattern: str = '',
    replacement: str = '',
    enabled: int = 1,
  ) -> int:
    """Insert a new HTTP testing rule and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO http_testing_rules
          (session_id, name, rule_type, where_clause, pattern, replacement, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, name, rule_type, where_clause, pattern, replacement, enabled),
      )
      self._conn.commit()
      return cur.lastrowid

  def list_http_rules(
    self,
    session_id: Optional[str] = None,
    rule_type: Optional[str] = None,
  ) -> List[Dict[str, Any]]:
    """Return HTTP testing rules, optionally filtered by session_id and/or rule_type."""
    clauses: List[str] = []
    params: List[Any] = []
    if session_id:
      clauses.append("session_id = ?")
      params.append(session_id)
    if rule_type:
      clauses.append("rule_type = ?")
      params.append(rule_type)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM http_testing_rules {where} ORDER BY created_at DESC",
        params,
      )
      return self._rows_to_list(cur.fetchall())

  def delete_http_rule(self, rule_id: int) -> None:
    """Delete an HTTP testing rule."""
    with self._lock:
      self._conn.execute("DELETE FROM http_testing_rules WHERE id = ?", (rule_id,))
      self._conn.commit()

  # ── Bug Bounty Assessments ──────────────────────────────────────────────────

  def create_bugbounty_assessment(
    self,
    id: str,
    session_id: str,
    domain: str,
    scope: str = '',
    out_of_scope: str = '',
    workflow_types: str = '[]',
  ) -> Dict[str, Any]:
    """Insert a new bug bounty assessment and return it as a dict."""
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO bugbounty_assessments
          (id, session_id, domain, scope, out_of_scope, workflow_types)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (id, session_id, domain, scope, out_of_scope, workflow_types),
      )
      self._conn.commit()
      cur = self._conn.execute("SELECT * FROM bugbounty_assessments WHERE id = ?", (id,))
      return self._row_to_dict(cur.fetchone()) or {}

  def update_bugbounty_assessment(self, id: str, **fields: Any) -> None:
    """Update allowed fields on a bug bounty assessment.

    Allowed fields: findings_json, summary, completed_at, scope, out_of_scope
    """
    allowed = {"findings_json", "summary", "completed_at", "scope", "out_of_scope"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
      return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [id]
    with self._lock:
      self._conn.execute(
        f"UPDATE bugbounty_assessments SET {set_clause} WHERE id = ?",
        values,
      )
      self._conn.commit()

  def get_bugbounty_assessment(self, id: str) -> Optional[Dict[str, Any]]:
    """Return a single bug bounty assessment dict, or None if not found."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM bugbounty_assessments WHERE id = ?",
        (id,),
      )
      return self._row_to_dict(cur.fetchone())

  def list_bugbounty_assessments(
    self,
    session_id: Optional[str] = None,
    domain: Optional[str] = None,
    limit: int = 50,
  ) -> List[Dict[str, Any]]:
    """Return bug bounty assessments, optionally filtered by session_id and/or domain."""
    clauses: List[str] = []
    params: List[Any] = []
    if session_id:
      clauses.append("session_id = ?")
      params.append(session_id)
    if domain:
      clauses.append("domain LIKE ?")
      params.append(f"%{domain}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with self._lock:
      cur = self._conn.execute(
        f"SELECT * FROM bugbounty_assessments {where} ORDER BY created_at DESC LIMIT ?",
        params + [limit],
      )
      return self._rows_to_list(cur.fetchall())

  # ── Missions ──────────────────────────────────────────────────────────────────

  def create_mission(
    self,
    id: str,
    prompt: str,
    stealth: str = "maximum",
  ) -> Dict[str, Any]:
    """Insert a new mission row with status 'pending'."""
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO missions (id, prompt, stealth_level)
        VALUES (?, ?, ?)
        """,
        (id, prompt, stealth),
      )
      self._conn.commit()
      cur = self._conn.execute("SELECT * FROM missions WHERE id = ?", (id,))
      return self._row_to_dict(cur.fetchone()) or {}

  def update_mission(self, id: str, **fields: Any) -> None:
    """Update allowed fields on a mission row.

    Allowed fields: status, stealth_level, phases_json, started_at, completed_at
    """
    allowed = {"status", "stealth_level", "phases_json", "started_at", "completed_at"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
      return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [id]
    with self._lock:
      self._conn.execute(
        f"UPDATE missions SET {set_clause} WHERE id = ?",
        values,
      )
      self._conn.commit()

  def get_mission(self, id: str) -> Optional[Dict[str, Any]]:
    """Return a single mission dict, or None."""
    with self._lock:
      cur = self._conn.execute("SELECT * FROM missions WHERE id = ?", (id,))
      return self._row_to_dict(cur.fetchone())

  def list_missions(self, limit: int = 50) -> List[Dict[str, Any]]:
    """Return most recent missions, newest first."""
    with self._lock:
      cur = self._conn.execute(
        "SELECT * FROM missions ORDER BY created_at DESC LIMIT ?",
        (limit,),
      )
      return self._rows_to_list(cur.fetchall())

  # ── Mission Phases ────────────────────────────────────────────────────────────

  def add_mission_phase(
    self,
    mission_id: str,
    phase_order: int,
    agent_type: str,
  ) -> int:
    """Insert a new mission phase and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO mission_phases (mission_id, phase_order, agent_type, started_at)
        VALUES (?, ?, ?, datetime('now'))
        """,
        (mission_id, phase_order, agent_type),
      )
      self._conn.commit()
      return cur.lastrowid

  def update_mission_phase(self, id: int, **fields: Any) -> None:
    """Update allowed fields on a mission phase row.

    Allowed fields: tools_used, success, findings_json, completed_at
    """
    allowed = {"tools_used", "success", "findings_json", "completed_at"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
      return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [id]
    with self._lock:
      self._conn.execute(
        f"UPDATE mission_phases SET {set_clause} WHERE id = ?",
        values,
      )
      self._conn.commit()

  # ── Mission Findings ──────────────────────────────────────────────────────────

  def add_mission_finding(
    self,
    mission_id: str,
    finding_type: str,
    title: str,
    description: str,
    data_json: str = "{}",
  ) -> int:
    """Insert a mission finding and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO mission_findings
          (mission_id, finding_type, title, description, data_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (mission_id, finding_type, title, description, data_json),
      )
      self._conn.commit()
      return cur.lastrowid

  # ── Defense Events ────────────────────────────────────────────────────────────

  def log_defense_event(
    self,
    event_type: str,
    threat_level: int = 0,
    target: str = "",
    details: str = "{}",
    action_taken: str = "",
  ) -> int:
    """Log a defensive event and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO defense_events
          (event_type, threat_level, target, details, action_taken)
        VALUES (?, ?, ?, ?, ?)
        """,
        (event_type, threat_level, target, details, action_taken),
      )
      self._conn.commit()
      return cur.lastrowid

  # ── Kali Sessions ─────────────────────────────────────────────────────────────

  def create_kali_session(
    self,
    sid: str,
    tool_name: str,
    command: str,
  ) -> None:
    """Record a new active Kali PTY session."""
    with self._lock:
      self._conn.execute(
        """
        INSERT OR IGNORE INTO kali_sessions (session_id, tool_name, command)
        VALUES (?, ?, ?)
        """,
        (sid, tool_name, command),
      )
      self._conn.commit()

  def close_kali_session(self, sid: str) -> None:
    """Mark a Kali PTY session as closed."""
    with self._lock:
      self._conn.execute(
        "UPDATE kali_sessions SET is_active = 0, closed_at = datetime('now') WHERE session_id = ?",
        (sid,),
      )
      self._conn.commit()

  # ── Cracked Hashes ────────────────────────────────────────────────────────────

  def save_cracked_hash(
    self,
    hash_val: str,
    plaintext: str,
    hash_type: str = "",
    tool: str = "",
    gpu_used: str = "",
  ) -> int:
    """Record a cracked hash and return its id."""
    with self._lock:
      cur = self._conn.execute(
        """
        INSERT INTO cracked_hashes (hash, plaintext, hash_type, tool, gpu_used)
        VALUES (?, ?, ?, ?, ?)
        """,
        (hash_val, plaintext, hash_type, tool, gpu_used),
      )
      self._conn.commit()
      return cur.lastrowid

  # ── Lifecycle ─────────────────────────────────────────────────────────────────

  def close(self) -> None:
    """Close the database connection. Called on server shutdown."""
    with self._lock:
      try:
        self._conn.close()
        logger.debug("db: connection closed")
      except Exception as exc:
        logger.warning("db: error closing connection: %s", exc)
