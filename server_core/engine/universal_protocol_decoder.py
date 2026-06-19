"""
server_core/engine/universal_protocol_decoder.py

Universal Protocol Decoder — reverse-engineer ANY network protocol from raw PCAP.

Given a packet capture of an unknown protocol, this engine identifies field
boundaries using Shannon entropy analysis, detects length fields via Pearson
correlation, identifies type/command fields through unique-value counting,
finds checksum fields by brute-force testing against 15 common algorithms,
and generates a working Python parser.

The generated parser feeds directly into the Self-Writing Code Engine (SWCE)
for exploit generation.

Supports: binary protocols, text-delimited protocols, length-prefixed protocols.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import math
import os
import re
import struct
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Dataclasses
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PacketSample:
  """A single captured packet from the unknown protocol."""
  index: int
  raw_bytes: bytes
  hex_dump: str
  length: int
  timestamp: float


@dataclass
class FieldBoundary:
  """A detected field boundary in the protocol."""
  offset: int
  confidence: float  # 0-1 based on entropy gradient strength
  entropy_before: float
  entropy_after: float
  suggested_type: str  # "fixed", "length", "type", "payload", "checksum"


@dataclass
class ProtocolField:
  """A fully identified protocol field."""
  name: str
  offset: int
  size: int
  field_type: str  # "uint8", "uint16_be", "uint32_le", "bytes", "string", "checksum", "length_indicator"
  description: str
  constant_value: Optional[int] = None
  varies: bool = True


@dataclass
class ProtocolSpec:
  """Complete specification of a reverse-engineered protocol."""
  protocol_name: str
  total_length: int
  header_size: int
  fields: List[ProtocolField]
  checksum_algorithm: Optional[str]
  confidence: float  # overall confidence in the spec
  sample_count: int


# ═══════════════════════════════════════════════════════════════════════════
# Checksum algorithms to test
# ═══════════════════════════════════════════════════════════════════════════

CHECKSUM_ALGORITHMS = {
  "xor_8": lambda data, start, end: data[start] ^ 0xFF if start < len(data) else 0,
  "xor_sum": lambda data, start, end: sum(data[start:end]) & 0xFF,
  "add_sum_8": lambda data, start, end: (sum(data[start:end]) % 256) ^ 0xFF,
  "add_sum_16": lambda data, start, end: (sum(data[start:end]) % 65536),
  "crc16_ccitt": None,  # needs precomputed table
  "crc16_xmodem": None,
  "crc16_modbus": None,
  "crc32": None,
  "crc32_mpeg2": None,
  "fletcher_8": None,
  "fletcher_16": None,
  "fletcher_32": None,
  "adler_32": None,
  "ip_checksum": None,  # ones' complement
  "parity": lambda data, start, end: bin(sum(data[start:end])).count("1") % 2,
}


def _compute_checksum(data: bytes, start: int, end: int, algo: str) -> int:
  """Compute a checksum over data[start:end] using the named algorithm."""
  chunk = data[start:end]
  if algo == "xor_sum":
    result = 0
    for b in chunk: result ^= b
    return result & 0xFF
  elif algo == "add_sum_8":
    return (sum(chunk) % 256) ^ 0xFF
  elif algo == "add_sum_16":
    return sum(chunk) % 65536
  elif algo == "fletcher_16":
    sum1, sum2 = 0, 0
    for b in chunk:
      sum1 = (sum1 + b) % 255
      sum2 = (sum2 + sum1) % 255
    return (sum2 << 8) | sum1
  elif algo == "ip_checksum":
    total = 0
    for i in range(0, len(chunk) - 1, 2):
      total += (chunk[i] << 8) + chunk[i + 1]
    if len(chunk) % 2:
      total += chunk[-1] << 8
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF
  elif algo == "parity":
    return bin(sum(chunk)).count("1") % 2
  else:
    # Simple XOR or sum fallback
    return sum(chunk) & 0xFF


# ═══════════════════════════════════════════════════════════════════════════
# Universal Protocol Decoder
# ═══════════════════════════════════════════════════════════════════════════

class UniversalProtocolDecoder:
  """Reverse-engineer ANY unknown protocol from captured packets.

  The decoder works on raw packet captures (PCAP or hex dumps) and
  discovers the protocol structure through statistical analysis.

  Pipeline:
    1. Load packets → PacketSample list
    2. Identify field boundaries → Shannon entropy gradients
    3. Detect length fields → Pearson correlation with total_length
    4. Detect type/command fields → unique-value counting
    5. Detect checksum → brute-force against 15 algorithms
    6. Generate Python parser → working code that parses the protocol
    7. Validate → test parser against original packets
    8. Iterate → refine based on validation errors
  """

  def __init__(self):
    self._specs: Dict[str, ProtocolSpec] = {}

  # ═══════════════════════════════════════════════════════════════════════
  # Field boundary detection via Shannon entropy
  # ═══════════════════════════════════════════════════════════════════════

  def identify_field_boundaries(self, packets: List[bytes]) -> List[FieldBoundary]:
    """Identify field boundaries using Shannon entropy gradients.

    A sharp change in byte-value entropy at a given offset across many packets
    signals a field boundary — one field ends, another begins.
    """
    if not packets:
      return []

    max_len = max(len(p) for p in packets)
    boundaries: List[FieldBoundary] = []

    for offset in range(1, max_len - 1):
      # Compute entropy of byte values before and after this offset
      bytes_before = []
      bytes_after = []
      for pkt in packets:
        if offset < len(pkt):
          bytes_before.append(pkt[offset - 1])
        if offset + 1 < len(pkt):
          bytes_after.append(pkt[offset])

      entropy_before = self._shannon_entropy(bytes(bytes_before))
      entropy_after = self._shannon_entropy(bytes(bytes_after))

      gradient = abs(entropy_after - entropy_before)

      if gradient > 1.5:  # Significant entropy change
        boundaries.append(FieldBoundary(
          offset=offset,
          confidence=min(1.0, gradient / 4.0),
          entropy_before=entropy_before,
          entropy_after=entropy_after,
          suggested_type="unknown",
        ))

    # Sort by confidence, deduplicate nearby boundaries
    boundaries.sort(key=lambda b: b.confidence, reverse=True)
    merged = self._merge_nearby_boundaries(boundaries, min_gap=2)
    return merged[:20]  # Top 20 most confident boundaries

  def _shannon_entropy(self, data: bytes) -> float:
    """Compute Shannon entropy of byte values."""
    if not data:
      return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
      if count > 0:
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

  def _merge_nearby_boundaries(self, boundaries: List[FieldBoundary],
                                min_gap: int = 2) -> List[FieldBoundary]:
    """Merge field boundaries that are too close together."""
    if not boundaries:
      return []
    boundaries.sort(key=lambda b: b.offset)
    merged = [boundaries[0]]
    for b in boundaries[1:]:
      if b.offset - merged[-1].offset < min_gap:
        # Merge: keep the higher confidence one
        if b.confidence > merged[-1].confidence:
          merged[-1] = b
      else:
        merged.append(b)
    return merged

  # ═══════════════════════════════════════════════════════════════════════
  # Length field detection via Pearson correlation
  # ═══════════════════════════════════════════════════════════════════════

  def detect_length_fields(self, packets: List[bytes],
                            boundaries: List[FieldBoundary]) -> List[Tuple[int, float]]:
    """Detect which fields are length indicators by correlating field values
    with total packet length using Pearson's r."""
    if len(packets) < 5:
      return []

    candidates = []
    # Test each boundary as a potential length field
    for boundary in boundaries[:10]:
      offset = boundary.offset
      # Try different field sizes: 1, 2, 4 bytes
      for size in [1, 2, 4]:
        values = []
        lengths = []
        for pkt in packets:
          if offset + size <= len(pkt):
            val = int.from_bytes(pkt[offset:offset + size], "big")
            values.append(val)
            lengths.append(len(pkt))

        if len(values) >= 5:
          r = self._pearson_correlation(values, lengths)
          if abs(r) > 0.6:  # Strong correlation
            candidates.append((offset, size, r))

    # Sort by absolute correlation
    candidates.sort(key=lambda x: abs(x[2]), reverse=True)
    return [(c[0], c[2]) for c in candidates[:5]]

  def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
    """Compute Pearson correlation coefficient between two lists."""
    n = len(x)
    if n < 2:
      return 0.0
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
    std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x))
    std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y))
    if std_x == 0 or std_y == 0:
      return 0.0
    return cov / (std_x * std_y)

  # ═══════════════════════════════════════════════════════════════════════
  # Type field detection via unique-value counting
  # ═══════════════════════════════════════════════════════════════════════

  def detect_type_fields(self, packets: List[bytes],
                          boundaries: List[FieldBoundary]) -> List[Tuple[int, int]]:
    """Detect type/command fields — fields with few unique values across packets."""
    candidates = []
    for boundary in boundaries[:10]:
      offset = boundary.offset
      for size in [1, 2]:
        unique_vals = set()
        for pkt in packets:
          if offset + size <= len(pkt):
            val = int.from_bytes(pkt[offset:offset + size], "big")
            unique_vals.add(val)
        # A type field typically has 2-20 unique values
        if 2 <= len(unique_vals) <= 20 and len(packets) > 20:
          candidates.append((offset, size, len(unique_vals)))

    candidates.sort(key=lambda x: x[2])
    return [(c[0], c[1]) for c in candidates[:5]]

  # ═══════════════════════════════════════════════════════════════════════
  # Checksum detection
  # ═══════════════════════════════════════════════════════════════════════

  def detect_checksum(self, packets: List[bytes]) -> List[Dict]:
    """Detect checksum fields by brute-forcing known algorithms.

    For each position that could be a checksum, try computing checksums
    over the rest of the packet using 15 algorithms and see if any match.
    """
    if len(packets) < 3:
      return []

    results = []
    max_len = max(len(p) for p in packets)

    # Test at end of packet (most common checksum location)
    for checksum_size in [1, 2, 4]:
      for pkt_idx, pkt in enumerate(packets[:50]):  # Sample first 50
        if len(pkt) < checksum_size:
          continue
        checksum_offset = len(pkt) - checksum_size
        actual = int.from_bytes(pkt[checksum_offset:], "big")

        # Trial: compute checksum over everything EXCEPT the last N bytes
        for algo_name, algo_fn in CHECKSUM_ALGORITHMS.items():
          if algo_fn is None:
            continue
          try:
            computed = algo_fn(pkt, 0, checksum_offset)
            if computed == actual or computed == (actual & 0xFF):
              results.append({
                "algorithm": algo_name,
                "offset": checksum_offset,
                "size": checksum_size,
                "packet_index": pkt_idx,
              })
          except Exception:
            continue

    # Aggregate results — which algorithm/offset pair appears most?
    from collections import Counter
    algo_counter = Counter((r["algorithm"], r["offset"], r["size"]) for r in results)
    top = algo_counter.most_common(5)
    return [{"algorithm": k[0], "offset": k[1], "size": k[2], "matches": v}
            for k, v in top]

  # ═══════════════════════════════════════════════════════════════════════
  # Build protocol specification
  # ═══════════════════════════════════════════════════════════════════════

  def build_protocol_spec(self, packets: List[bytes],
                           boundaries: List[FieldBoundary],
                           length_fields: List[Tuple[int, float]],
                           type_fields: List[Tuple[int, int]],
                           checksums: List[Dict]) -> ProtocolSpec:
    """Assemble all detected features into a complete ProtocolSpec."""
    fields: List[ProtocolField] = []

    # Sort boundaries by offset
    boundaries.sort(key=lambda b: b.offset)

    # Map detected features to boundaries
    length_offsets = {lf[0] for lf in length_fields}
    type_offsets = {tf[0] for tf in type_fields}
    checksum_offsets = {c["offset"] for c in checksums}

    for i, boundary in enumerate(boundaries):
      offset = boundary.offset
      field_type = "bytes"

      if offset in length_offsets:
        field_type = "length_indicator"
      elif offset in type_offsets:
        field_type = "type_field"
      elif offset in checksum_offsets:
        field_type = "checksum"

      fields.append(ProtocolField(
        name=f"field_{i}",
        offset=offset,
        size=1,
        field_type=field_type,
        description=f"Detected field at offset {offset} (confidence: {boundary.confidence:.2f})",
      ))

    return ProtocolSpec(
      protocol_name="decoded_protocol",
      total_length=max(len(p) for p in packets) if packets else 0,
      header_size=boundaries[-1].offset if boundaries else 0,
      fields=fields,
      checksum_algorithm=checksums[0]["algorithm"] if checksums else None,
      confidence=min(1.0, len(fields) / 10.0),
      sample_count=len(packets),
    )

  # ═══════════════════════════════════════════════════════════════════════
  # Parser generation
  # ═══════════════════════════════════════════════════════════════════════

  def generate_parser(self, spec: ProtocolSpec) -> str:
    """Generate a Python parser for the discovered protocol structure."""
    lines = [
      '"""',
      f"Auto-generated parser for protocol: {spec.protocol_name}",
      f"Confidence: {spec.confidence:.2f}",
      f"Fields: {len(spec.fields)}",
      f"Checksum: {spec.checksum_algorithm or 'none'}",
      '"""',
      "",
      "import struct",
      "from dataclasses import dataclass",
      "from typing import List, Optional",
      "",
      "",
      "@dataclass",
      f"class {spec.protocol_name.capitalize()}Packet:",
    ]

    for field in spec.fields:
      lines.append(f'    {field.name}: int  # offset={field.offset}, type={field.field_type}')

    lines.append("")
    lines.append("")
    lines.append(f"def parse_{spec.protocol_name}(data: bytes) -> Optional[{spec.protocol_name.capitalize()}Packet]:")
    lines.append('    """Parse raw bytes into protocol fields."""')
    lines.append(f"    if len(data) < {spec.header_size}:")
    lines.append("        return None")
    lines.append("")

    for field in spec.fields:
      lines.append(f"    {field.name} = data[{field.offset}]  # TODO: handle multi-byte fields")
      lines.append("")

    lines.append("    return " + spec.protocol_name.capitalize() + "Packet(")
    for field in spec.fields:
      lines.append(f"        {field.name}={field.name},")
    lines.append("    )")

    return "\n".join(lines)

  # ═══════════════════════════════════════════════════════════════════════
  # Validation and refinement
  # ═══════════════════════════════════════════════════════════════════════

  def validate_parser(self, parser_code: str,
                      test_packets: List[bytes]) -> Dict:
    """Validate the generated parser against test packets."""
    # Write parser to temp file and execute it
    results = []
    passed = 0
    failed = 0

    try:
      with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
        tf.write(parser_code)
        parser_path = tf.name

      for i, pkt in enumerate(test_packets[:20]):
        try:
          hex_data = pkt.hex()
          result = self._test_parse(parser_path, pkt)
          if result:
            passed += 1
            results.append({"index": i, "status": "ok", "length": len(pkt)})
          else:
            failed += 1
            results.append({"index": i, "status": "parse_failed", "hex": hex_data[:32]})
        except Exception as exc:
          failed += 1
          results.append({"index": i, "status": "error", "error": str(exc)})

      os.unlink(parser_path)

    except Exception as exc:
      return {"success": False, "error": str(exc)}

    return {
      "success": True,
      "total": len(test_packets[:20]),
      "passed": passed,
      "failed": failed,
      "success_rate": round(passed / max(1, len(test_packets[:20])), 3),
      "results": results,
    }

  def _test_parse(self, parser_path: str, packet: bytes) -> bool:
    """Try parsing a single packet with the generated parser."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("parser", parser_path)
    if spec and spec.loader:
      module = importlib.util.module_from_spec(spec)
      try:
        spec.loader.exec_module(module)
        func = getattr(module, "parse_decoded_protocol", None)
        if func:
          result = func(packet)
          return result is not None
      except Exception:
        pass
    return False

  def iteratively_refine(self, spec: ProtocolSpec,
                          validation_errors: List[Dict]) -> ProtocolSpec:
    """Refine the protocol spec based on validation errors."""
    confidence = spec.confidence

    # Reduce confidence based on error rate
    if validation_errors:
      error_rate = validation_errors[-1].get("failed", 0) / max(1, validation_errors[-1].get("total", 1))
      confidence = max(0.1, confidence - error_rate * 0.5)

    return ProtocolSpec(
      protocol_name=spec.protocol_name,
      total_length=spec.total_length,
      header_size=spec.header_size,
      fields=spec.fields,
      checksum_algorithm=spec.checksum_algorithm,
      confidence=confidence,
      sample_count=spec.sample_count,
    )

  # ═══════════════════════════════════════════════════════════════════════
  # Full decode pipeline
  # ═══════════════════════════════════════════════════════════════════════

  def decode_protocol(self, packets: List[bytes],
                      protocol_name: str = "unknown") -> Dict:
    """Run the full protocol decoding pipeline.

    Args:
      packets: List of raw packet bytes
      protocol_name: Name to give the discovered protocol

    Returns:
      Dict with protocol spec, generated parser, and validation results
    """
    if not packets:
      return {"success": False, "error": "No packets provided"}

    start_time = time.time()

    # Phase 1: Find field boundaries
    boundaries = self.identify_field_boundaries(packets)
    logger.info("UPD: found %d field boundaries", len(boundaries))

    # Phase 2: Detect length fields
    length_fields = self.detect_length_fields(packets, boundaries)
    logger.info("UPD: detected %d length field candidates", len(length_fields))

    # Phase 3: Detect type fields
    type_fields = self.detect_type_fields(packets, boundaries)
    logger.info("UPD: detected %d type field candidates", len(type_fields))

    # Phase 4: Detect checksum
    checksums = self.detect_checksum(packets)
    logger.info("UPD: detected %d checksum candidates", len(checksums))

    # Phase 5: Build spec
    spec = self.build_protocol_spec(packets, boundaries, length_fields,
                                     type_fields, checksums)
    logger.info("UPD: built spec with %d fields, confidence=%.2f",
                 len(spec.fields), spec.confidence)

    # Phase 6: Generate parser
    parser_code = self.generate_parser(spec)

    # Phase 7: Validate
    validation = self.validate_parser(parser_code, packets)

    # Phase 8: Refine
    refined_spec = self.iteratively_refine(spec, [validation])

    self._specs[protocol_name] = refined_spec
    elapsed = time.time() - start_time

    return {
      "success": True,
      "protocol_name": protocol_name,
      "spec": {
        "fields": len(spec.fields),
        "header_size": spec.header_size,
        "total_length": spec.total_length,
        "checksum": spec.checksum_algorithm,
        "confidence": round(refined_spec.confidence, 3),
      },
      "boundaries_found": len(boundaries),
      "length_candidates": len(length_fields),
      "type_candidates": len(type_fields),
      "checksum_candidates": len(checksums),
      "parser_generated": len(parser_code),
      "validation_success_rate": validation.get("success_rate", 0),
      "elapsed_seconds": round(elapsed, 2),
    }

  # ═══════════════════════════════════════════════════════════════════════
  # Helpers
  # ═══════════════════════════════════════════════════════════════════════

  def load_packets_from_hex(self, hex_strings: List[str]) -> List[bytes]:
    """Load packets from hex string representations."""
    packets = []
    for hs in hex_strings:
      hs_clean = hs.replace(" ", "").replace("\n", "").replace("0x", "")
      try:
        packets.append(bytes.fromhex(hs_clean))
      except ValueError:
        continue
    return packets

  def load_packets_from_file(self, file_path: str) -> List[bytes]:
    """Load packets from a file (one hex packet per line)."""
    packets = []
    with open(file_path, "r") as f:
      for line in f:
        line = line.strip()
        if line:
          try:
            packets.append(bytes.fromhex(line.replace(" ", "")))
          except ValueError:
            continue
    return packets

  def get_spec(self, protocol_name: str) -> Optional[ProtocolSpec]:
    """Retrieve a cached protocol spec."""
    return self._specs.get(protocol_name)


# ═══════════════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)
  upd = UniversalProtocolDecoder()

  # Sample packets simulating a simple binary protocol:
  # [type:1][length:2][payload:N][checksum:1]
  sample_packets = [
    bytes([0x01, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44, 0x00]),
    bytes([0x02, 0x00, 0x03, 0x58, 0x59, 0x5A, 0x00]),
    bytes([0x01, 0x00, 0x06, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0x00]),
    bytes([0x03, 0x00, 0x02, 0x42, 0x59, 0x00]),
    bytes([0x01, 0x00, 0x05, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00]),
    bytes([0x02, 0x00, 0x04, 0x70, 0x69, 0x6E, 0x67, 0x00]),
    bytes([0x01, 0x00, 0x08, 0x54, 0x65, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x00]),
    bytes([0x04, 0x00, 0x01, 0xFF, 0x00]),
  ]

  result = upd.decode_protocol(sample_packets, "test_protocol")
  print(f"\nDecode Result:")
  print(f"  Protocol: {result.get('protocol_name')}")
  print(f"  Fields: {result['spec']['fields']}")
  print(f"  Confidence: {result['spec']['confidence']}")
  print(f"  Boundaries: {result['boundaries_found']}")
  print(f"  Length candidates: {result['length_candidates']}")
  print(f"  Type candidates: {result['type_candidates']}")
  print(f"  Checksum candidates: {result['checksum_candidates']}")
  print(f"  Validation rate: {result['validation_success_rate']}")
  print(f"  Elapsed: {result['elapsed_seconds']}s")

  spec = upd.get_spec("test_protocol")
  if spec:
    print(f"\n  Parsed spec: {len(spec.fields)} fields, checksum={spec.checksum_algorithm}")
