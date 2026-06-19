"""
kali_bridge — Native Kali Linux tool integration for PhantomStrike.

Provides PTY-based interactive session control, a pooled session manager,
GPU passthrough for hash cracking, and AI-powered output parsing for
common Kali tools.

Exports:
    KaliSessionPool  — pooled manager for multiple active PTY sessions
    GPUManager       — GPU resource management for hashcat/john
    PTYSession       — pseudo-terminal control for interactive tools
"""

from .kali_session_pool import KaliSessionPool
from .gpu_manager import GPUManager
from .pty_session import PTYSession

__all__ = ["KaliSessionPool", "GPUManager", "PTYSession"]
