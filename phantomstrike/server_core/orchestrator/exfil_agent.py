"""
server_core/orchestrator/exfil_agent.py

Data exfiltration specialist agent.

Handles secure extraction of loot: database dumps, file archives,
credentials, screenshots, and audio/video captures. Supports multiple
exfiltration channels (DNS, HTTPS, WebSocket, ICMP) with optional
compression and encryption.

Works standalone with simulated channel output.
"""

import logging
import time
from typing import Any, Dict, List, Optional

from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)


class ExfilAgent:
    """Data exfiltration specialist — securely extract loot from target.

    Channels supported:
      - HTTPS POST (chunked, TLS 1.3)
      - DNS tunnelling (TXT records, AAAA records)
      - WebSocket streaming
      - ICMP tunnelling
      - Cloud storage upload (S3, GCS presigned URLs)

    Features:
      - Compression (gzip, zstd) before transfer
      - AES-256-GCM encryption at rest
      - Chunked transfer with resume capability
      - Bandwidth throttling for stealth
    """

    AGENT_NAME = "exfil"

    # Simulated channel handlers
    CHANNEL_HANDLERS: Dict[str, callable] = {}

    def __init__(self, llm_client: Any = None):
        self._llm = llm_client
        self._register_channels()

    def _register_channels(self) -> None:
        self.CHANNEL_HANDLERS = {
            "exfil_channel": self._channel_https,
            "compression": self._compress_data,
            "encryption": self._encrypt_data,
            "db_dumper": self._dump_database,
            "compressor": self._compress_data,
        }

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run data exfiltration for the given phase.

        Args:
            phase: Phase spec with id, tools_needed, parameters, etc.
            context: Shared memory context (loot paths, credentials, session).

        Returns:
            Dict with success, data, error, elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        tools = phase.get("tools_needed", [])
        params = phase.get("parameters", {})
        label = phase.get("label", phase_id)
        target_server = params.get("target", "loot_server")

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"EXFIL AGENT — {label}", "📤", "CYBER_ORANGE"
            ),
        )

        # Identify loot from context
        loot = self._identify_loot(context)
        if not loot:
            logger.warning("No loot identified in context — nothing to exfiltrate")
            elapsed = time.time() - start
            return {
                "success": True,
                "data": {"exfiltrated": [], "note": "No loot identified"},
                "elapsed_seconds": round(elapsed, 2),
            }

        logger.info("Identified %d loot item(s) for exfiltration", len(loot))

        # Process each loot item through selected tools
        exfiltrated: List[Dict[str, Any]] = []
        errors: List[str] = []

        for item in loot:
            item_result: Dict[str, Any] = {"source": item, "exfiltrated": False}
            try:
                # Apply compression if requested
                if "compression" in tools or "compressor" in tools:
                    compress_result = self._compress_data(item, params, context)
                    item_result["compression"] = compress_result
                    item = {
                        **item,
                        "data": compress_result.get("compressed_data", item.get("data", "")),
                    }

                # Apply encryption if requested
                if "encryption" in tools:
                    encrypt_result = self._encrypt_data(item, params, context)
                    item_result["encryption"] = encrypt_result
                    item = {
                        **item,
                        "data": encrypt_result.get("encrypted_data", item.get("data", "")),
                    }

                # Exfiltrate via channel
                channel_type = params.get("channel", "https")
                channel_handler = self.CHANNEL_HANDLERS.get("exfil_channel", self._channel_https)
                transfer_result = channel_handler(item, params, context, channel_type)
                item_result["transfer"] = transfer_result
                item_result["exfiltrated"] = transfer_result.get("success", False)

            except Exception as exc:
                msg = f"Exfil of {item.get('path', 'unknown')} failed: {str(exc)}"
                logger.exception(msg)
                errors.append(msg)
                item_result["error"] = str(exc)

            exfiltrated.append(item_result)

        any_success = any(item.get("exfiltrated") for item in exfiltrated)
        elapsed = time.time() - start

        # Compute stats
        total_bytes = sum(
            item.get("transfer", {}).get("bytes_sent", 0) for item in exfiltrated
        )

        return {
            "success": any_success or not errors,
            "data": {
                "exfiltrated_items": exfiltrated,
                "total_items": len(exfiltrated),
                "successful_items": sum(1 for item in exfiltrated if item.get("exfiltrated")),
                "total_bytes_exfiltrated": total_bytes,
                "target_server": target_server,
            },
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Loot identification
    # ------------------------------------------------------------------

    def _identify_loot(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify data to exfiltrate from the shared context."""
        loot: List[Dict[str, Any]] = []

        # Search context for file paths, DB names, credential sets
        for v in context.values():
            if isinstance(v, dict):
                # PostExploitAgent file browser output
                if "interesting_files" in v:
                    for fpath in v["interesting_files"]:
                        loot.append({"path": fpath, "type": "file", "source_agent": "post_exploit"})

                # ExploitAgent SQLMap output
                if "dbs_found" in v:
                    for db in v["dbs_found"]:
                        loot.append({"path": f"database://{db}", "type": "database", "source_agent": "exploit"})

                # Credentials found
                if "credentials_found" in v:
                    for cred in v["credentials_found"]:
                        loot.append({"path": f"credential://{cred.get('username', '?')}", "type": "credential", "data": cred, "source_agent": "exploit"})

                # Harvested credentials
                if "credentials_harvested" in v:
                    for cred in v["credentials_harvested"]:
                        loot.append({"path": f"credential://{cred.get('username', '?')}", "type": "credential", "data": cred, "source_agent": "post_exploit"})

        # Deduplicate by path
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for item in loot:
            if item["path"] not in seen:
                seen.add(item["path"])
                deduped.append(item)
        return deduped

    # ------------------------------------------------------------------
    # Channel handlers (simulated)
    # ------------------------------------------------------------------

    def _channel_https(
        self, item: Dict, params: Dict, ctx: Dict, channel: str = "https"
    ) -> Dict[str, Any]:
        """Simulated HTTPS POST exfiltration."""
        return {
            "channel": "https",
            "success": True,
            "destination": params.get("loot_server", "https://c2.example.com/ingest"),
            "chunks": 3,
            "bytes_sent": len(str(item.get("data", ""))) or 2048,
            "tls_version": "TLS 1.3",
            "note": "[STUB] HTTPS POST — integrate requests with chunked upload",
        }

    def _simulate_dns_tunnel(
        self, item: Dict, params: Dict, ctx: Dict
    ) -> Dict[str, Any]:
        """Simulated DNS tunnelling exfiltration."""
        return {
            "channel": "dns_tunnel",
            "success": True,
            "domain": "tunnel.c2.example.com",
            "record_type": "TXT",
            "packets": 35,
            "bytes_sent": len(str(item.get("data", ""))) or 1024,
            "note": "[STUB] DNS tunnel — integrate dnslib + custom resolver",
        }

    def _simulate_websocket(
        self, item: Dict, params: Dict, ctx: Dict
    ) -> Dict[str, Any]:
        """Simulated WebSocket streaming."""
        return {
            "channel": "websocket",
            "success": True,
            "endpoint": "wss://c2.example.com/stream",
            "frames": 12,
            "bytes_sent": len(str(item.get("data", ""))) or 4096,
            "note": "[STUB] WebSocket — integrate websockets client",
        }

    def _simulate_icmp_tunnel(
        self, item: Dict, params: Dict, ctx: Dict
    ) -> Dict[str, Any]:
        """Simulated ICMP tunnelling."""
        return {
            "channel": "icmp_tunnel",
            "success": True,
            "destination": params.get("loot_server", "10.0.0.1"),
            "packets": 50,
            "bytes_sent": len(str(item.get("data", ""))) or 512,
            "note": "[STUB] ICMP tunnel — integrate scapy or raw sockets",
        }

    # ------------------------------------------------------------------
    # Data processing
    # ------------------------------------------------------------------

    def _compress_data(self, item: Dict, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Simulated data compression."""
        return {
            "algorithm": params.get("compression", "gzip"),
            "original_size": len(str(item.get("data", ""))) or 4096,
            "compressed_size": len(str(item.get("data", ""))) // 2 or 2048,
            "ratio": "50%",
            "note": "[STUB] Compression — integrate gzip/zstd module",
        }

    def _encrypt_data(self, item: Dict, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Simulated AES-256-GCM encryption."""
        return {
            "algorithm": "AES-256-GCM",
            "key_source": "ephemeral ECDH",
            "original_size": len(str(item.get("data", ""))) or 4096,
            "note": "[STUB] Encryption — integrate cryptography module with ECDH key exchange",
        }

    def _dump_database(self, item: Dict, params: Dict, ctx: Dict) -> Dict[str, Any]:
        """Simulated database dump."""
        return {
            "tool": "db_dumper",
            "db_type": "mysql",
            "target": item.get("path", "unknown"),
            "tables_dumped": 42,
            "rows": 150000,
            "dump_size_bytes": 2_097_152,
            "success": True,
            "note": "[STUB] DB dump — integrate mysqldump/pg_dump subprocess",
        }
