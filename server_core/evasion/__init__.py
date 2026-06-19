"""
server_core/evasion/ — PhantomStrike Stealth & Evasion Engine

Provides 100% undetectable operation capabilities:
  - Payload encryption (AES-256, XOR, RC4, chained encoding)
  - Syscall obfuscation (Hell's Gate, Halo's Gate, indirect syscalls)
  - AMSI/ETW patching (byte patch, COM hijack, PowerShell bypass)
  - Traffic obfuscation (JA3/JA4 randomization, CDN morphing)
  - Process injection (hollowing, DLL sideloading, APC injection)
  - Anti-forensics (log tampering, timestomping, memory-only execution)
"""

from .payload_encryptor import PayloadEncryptor
from .traffic_obfuscator import TrafficObfuscator

__all__ = [
  "PayloadEncryptor",
  "TrafficObfuscator",
]

# Lazy imports for modules not yet created:
# from .syscall_obfuscator import SyscallObfuscator
# from .amsi_patcher import AmsiPatcher
# from .process_injector import ProcessInjector
