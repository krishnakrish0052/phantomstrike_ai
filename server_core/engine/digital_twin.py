"""
server_core/engine/digital_twin.py

Digital Twin Engine — Passive Target Replication.

Builds a complete digital replica of a target environment from PASSIVE
data alone, sending zero packets to the target. Correlates OSINT, social,
technical, infrastructure, and physical intelligence sources to construct:

  - Network Topology      — subnets, hosts, gateways, exposed services
  - Security Stack        — firewalls, WAFs, IDS/IPS, EDR, AV
  - Technology Stack      — OS, frameworks, databases, middleware
  - Employee Map          — key personnel, roles, reporting lines
  - Physical Layout       — offices, DCs, satellite imagery correlates
  - Defense Gaps          — missing patches, misconfigurations, weak points
  - Attack Surface        — consolidated entry points with risk scores

Every inference carries a confidence score and an evidence trail. The
model continuously refines as new reconnaissance data confirms or denies
earlier hypotheses.

Classes:
  DigitalTwinEngine     — main orchestrator and model builder
  TwinModel             — the complete digital replica
  Inference             — a single concluded fact with evidence
  ConfidenceTier        — confidence level enum
  DataSourceAdapter     — base for ingesting heterogeneous intel sources
  CorrelationEngine     — cross-source fact correlation
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Source reliability weights (0.0–1.0)
_SOURCE_RELIABILITY: Dict[str, float] = {
  "shodan":             0.85,
  "censys":             0.85,
  "dns":                0.90,
  "whois":              0.80,
  "certificate_logs":   0.95,  # crt.sh — highly reliable
  "linkedin":           0.55,
  "twitter":            0.40,
  "github":             0.70,
  "stackoverflow":      0.45,
  "job_postings":       0.50,
  "sec_filings":        0.85,
  "satellite_imagery":  0.75,
  "street_view":        0.70,
  "wayback_machine":    0.65,
  "dns_history":        0.75,
  "bgp":                0.90,
  "pastebin":           0.30,
  "darknet":            0.25,
  "manual_confirmation": 1.00,
}

# Default confidence thresholds
_CONFIRMED_THRESHOLD = 0.85
_LIKELY_THRESHOLD = 0.65
_POSSIBLE_THRESHOLD = 0.40
_SPECULATIVE_THRESHOLD = 0.20


# ── Enums ──────────────────────────────────────────────────────────────────────


class ConfidenceTier(Enum):
  """Confidence tier for an inference."""
  CONFIRMED = auto()     # >= 0.85, multiple independent sources agree
  LIKELY = auto()         # >= 0.65, strong signal, some corroboration
  POSSIBLE = auto()       # >= 0.40, plausible but unverified
  SPECULATIVE = auto()    # >= 0.20, weak signal, needs investigation
  UNVERIFIED = auto()     # < 0.20, single low-reliability source


class InferenceDomain(Enum):
  """Domain an inference belongs to."""
  NETWORK_TOPOLOGY = "network_topology"
  SECURITY_STACK = "security_stack"
  TECHNOLOGY_STACK = "technology_stack"
  EMPLOYEE_MAP = "employee_map"
  PHYSICAL_LAYOUT = "physical_layout"
  DEFENSE_GAPS = "defense_gaps"
  ATTACK_SURFACE = "attack_surface"


# ── Data classes ───────────────────────────────────────────────────────────────


@dataclass
class Inference:
  """A single concluded fact with evidence trail and confidence."""
  inference_id: str = ""
  domain: InferenceDomain = InferenceDomain.TECHNOLOGY_STACK
  fact: str = ""                         # human-readable conclusion
  fact_type: str = ""                    # e.g. "os_version", "open_port", "employee_role"
  value: Any = None                      # structured value
  confidence: float = 0.0
  tier: ConfidenceTier = ConfidenceTier.UNVERIFIED
  sources: List[str] = field(default_factory=list)     # source names that contributed
  evidence: List[Dict[str, Any]] = field(default_factory=list)  # raw evidence snippets
  contradicting: List[Dict[str, Any]] = field(default_factory=list)  # evidence against
  first_seen: str = ""
  last_updated: str = ""
  validated: bool = False                # confirmed by active recon or manual review

  def __post_init__(self):
    if not self.inference_id:
      self.inference_id = f"inf_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    if not self.first_seen:
      self.first_seen = now
    if not self.last_updated:
      self.last_updated = now
    if not self.tier or self.tier == ConfidenceTier.UNVERIFIED:
      self.tier = self._compute_tier()

  def _compute_tier(self) -> ConfidenceTier:
    if self.confidence >= _CONFIRMED_THRESHOLD:
      return ConfidenceTier.CONFIRMED
    elif self.confidence >= _LIKELY_THRESHOLD:
      return ConfidenceTier.LIKELY
    elif self.confidence >= _POSSIBLE_THRESHOLD:
      return ConfidenceTier.POSSIBLE
    elif self.confidence >= _SPECULATIVE_THRESHOLD:
      return ConfidenceTier.SPECULATIVE
    return ConfidenceTier.UNVERIFIED

  def add_evidence(self, source: str, data: Any, reliability: Optional[float] = None) -> None:
    """Add a piece of supporting evidence, updating confidence."""
    src_reliability = reliability or _SOURCE_RELIABILITY.get(source, 0.5)
    self.evidence.append({
      "source": source,
      "data": data,
      "reliability": src_reliability,
      "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    if source not in self.sources:
      self.sources.append(source)
    self._recompute_confidence()
    self.tier = self._compute_tier()
    self.last_updated = datetime.now(timezone.utc).isoformat()

  def add_contradiction(self, source: str, data: Any, reliability: Optional[float] = None) -> None:
    """Add evidence that contradicts this inference."""
    src_reliability = reliability or _SOURCE_RELIABILITY.get(source, 0.5)
    self.contradicting.append({
      "source": source,
      "data": data,
      "reliability": src_reliability,
      "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    self._recompute_confidence()
    self.tier = self._compute_tier()
    self.last_updated = datetime.now(timezone.utc).isoformat()

  def _recompute_confidence(self) -> None:
    """Bayesian-like confidence update from evidence and contradictions."""
    if not self.evidence:
      self.confidence = 0.0
      return

    # Supporting evidence: combine reliabilities (diminishing returns per source)
    seen_sources: Set[str] = set()
    support_score = 0.0
    for ev in sorted(self.evidence, key=lambda e: e["reliability"], reverse=True):
      src = ev["source"]
      rel = ev["reliability"]
      if src in seen_sources:
        rel *= 0.3  # same source, diminishing returns
      else:
        seen_sources.add(src)
      support_score += rel * (1.0 - support_score)  # bounded sigmoid-ish accumulation

    # Contradicting evidence: subtract weighted reliability
    contra_score = 0.0
    seen_contra: Set[str] = set()
    for ev in sorted(self.contradicting, key=lambda e: e["reliability"], reverse=True):
      src = ev["source"]
      rel = ev["reliability"]
      if src in seen_contra:
        rel *= 0.3
      else:
        seen_contra.add(src)
      contra_score += rel * (1.0 - contra_score)

    # Net confidence: support minus contradiction penalty
    self.confidence = round(max(0.0, min(0.99, support_score - contra_score * 0.5)), 3)


@dataclass
class HostNode:
  """A single host in the network topology."""
  host_id: str = ""
  ip_address: str = ""
  hostname: str = ""
  fqdn: str = ""
  os: str = ""
  os_version: str = ""
  open_ports: List[int] = field(default_factory=list)
  services: Dict[int, str] = field(default_factory=dict)
  role: str = ""               # web, db, mail, dns, lb, etc.
  is_gateway: bool = False
  is_exposed: bool = False     # publicly accessible
  cloud_provider: str = ""
  cloud_region: str = ""
  tags: List[str] = field(default_factory=list)
  confidence: float = 0.0


@dataclass
class NetworkTopology:
  """Reconstructed network layout."""
  subnets: List[str] = field(default_factory=list)
  hosts: List[HostNode] = field(default_factory=list)
  gateways: List[str] = field(default_factory=list)
  dns_servers: List[str] = field(default_factory=list)
  mail_servers: List[str] = field(default_factory=list)
  cdn_providers: List[str] = field(default_factory=list)
  cloud_providers: List[str] = field(default_factory=list)
  as_numbers: List[int] = field(default_factory=list)
  bgp_prefixes: List[str] = field(default_factory=list)
  external_services: Dict[str, List[int]] = field(default_factory=dict)  # domain -> ports
  confidence: float = 0.0


@dataclass
class SecurityStack:
  """Reconstructed security posture."""
  waf_provider: str = ""
  waf_confidence: float = 0.0
  firewall_vendors: List[str] = field(default_factory=list)
  ids_ips: List[str] = field(default_factory=list)
  edr_solutions: List[str] = field(default_factory=list)
  antivirus: List[str] = field(default_factory=list)
  siem: List[str] = field(default_factory=list)
  email_security: List[str] = field(default_factory=list)
  dlp_solutions: List[str] = field(default_factory=list)
  auth_providers: List[str] = field(default_factory=list)  # Okta, Azure AD, etc.
  cert_authorities: List[str] = field(default_factory=list)
  tls_versions: List[str] = field(default_factory=list)
  security_policies: List[str] = field(default_factory=list)  # CSP, HSTS, etc.
  headers_observed: Dict[str, str] = field(default_factory=dict)
  confidence: float = 0.0


@dataclass
class TechnologyStack:
  """Reconstructed technology stack."""
  web_servers: List[str] = field(default_factory=list)
  app_servers: List[str] = field(default_factory=list)
  databases: List[str] = field(default_factory=list)
  caching: List[str] = field(default_factory=list)
  cms: List[str] = field(default_factory=list)
  frameworks: List[str] = field(default_factory=list)
  languages: List[str] = field(default_factory=list)
  javascript_libraries: List[str] = field(default_factory=list)
  css_frameworks: List[str] = field(default_factory=list)
  analytics: List[str] = field(default_factory=list)
  cdns: List[str] = field(default_factory=list)
  cloud_services: List[str] = field(default_factory=list)
  container_orchestration: List[str] = field(default_factory=list)
  ci_cd: List[str] = field(default_factory=list)
  monitoring: List[str] = field(default_factory=list)
  version_hints: Dict[str, str] = field(default_factory=dict)  # tech -> version
  confidence: float = 0.0


@dataclass
class Employee:
  """A single identified employee or role."""
  name: str = ""
  title: str = ""
  department: str = ""
  email: str = ""
  linkedin_url: str = ""
  github_username: str = ""
  twitter_handle: str = ""
  seniority: str = ""          # executive, senior, mid, junior
  technical_role: bool = False
  security_role: bool = False
  admin_access: bool = False
  public_profile: bool = False
  findings: List[str] = field(default_factory=list)  # interesting facts
  confidence: float = 0.0


@dataclass
class EmployeeMap:
  """Reconstructed organisational structure."""
  employees: List[Employee] = field(default_factory=list)
  departments: List[str] = field(default_factory=list)
  key_personnel: List[str] = field(default_factory=list)  # CISO, CTO, IT admins
  reporting_structure: Dict[str, List[str]] = field(default_factory=dict)  # manager -> reports
  email_format: str = ""         # first.last@, first@, flast@
  tech_stack_owners: Dict[str, str] = field(default_factory=dict)  # tech -> person
  confidence: float = 0.0


@dataclass
class PhysicalLocation:
  """A physical site."""
  location_id: str = ""
  address: str = ""
  city: str = ""
  state: str = ""
  country: str = ""
  postal_code: str = ""
  latitude: float = 0.0
  longitude: float = 0.0
  site_type: str = ""            # headquarters, data_center, branch_office, remote
  building_size_sqft: int = 0
  floor_count: int = 0
  has_on_site_security: bool = False
  has_public_access: bool = False
  satellite_image_url: str = ""
  street_view_url: str = ""
  nearby_landmarks: List[str] = field(default_factory=list)
  confidence: float = 0.0


@dataclass
class PhysicalLayout:
  """Reconstructed physical presence."""
  locations: List[PhysicalLocation] = field(default_factory=list)
  primary_hq: Optional[PhysicalLocation] = None
  data_centers: List[PhysicalLocation] = field(default_factory=list)
  total_employees_estimated: int = 0
  office_countries: List[str] = field(default_factory=list)
  confidence: float = 0.0


@dataclass
class DefenseGap:
  """An identified weakness or vulnerability in the target's defenses."""
  gap_id: str = ""
  category: str = ""             # missing_patch, misconfiguration, exposed_service, credential_leak, etc.
  severity: str = ""             # critical, high, medium, low, info
  description: str = ""
  affected_system: str = ""
  cvss_score: float = 0.0
  exploitability: str = ""       # easy, moderate, hard, theoretical
  evidence_sources: List[str] = field(default_factory=list)
  remediation: str = ""
  confidence: float = 0.0


@dataclass
class AttackSurfaceEntry:
  """A single entry point in the attack surface."""
  entry_id: str = ""
  entry_type: str = ""           # web_app, api, vpn, ssh, rdp, email, dns, cloud, physical, social
  target: str = ""               # URL, IP:port, email address, physical address
  protocol: str = ""
  port: int = 0
  service: str = ""
  risk_score: float = 0.0        # 0-100
  exploitability: str = ""
  known_vulnerabilities: List[str] = field(default_factory=list)
  authentication_required: bool = False
  exposed_since: str = ""
  confidence: float = 0.0


@dataclass
class TwinModel:
  """Complete digital replica of the target."""
  model_id: str = ""
  target_identifier: str = ""    # domain, IP range, or organisation name
  created_at: str = ""
  last_updated: str = ""
  version: int = 1
  network_topology: NetworkTopology = field(default_factory=NetworkTopology)
  security_stack: SecurityStack = field(default_factory=SecurityStack)
  technology_stack: TechnologyStack = field(default_factory=TechnologyStack)
  employee_map: EmployeeMap = field(default_factory=EmployeeMap)
  physical_layout: PhysicalLayout = field(default_factory=PhysicalLayout)
  defense_gaps: List[DefenseGap] = field(default_factory=list)
  attack_surface: List[AttackSurfaceEntry] = field(default_factory=list)
  all_inferences: List[Inference] = field(default_factory=list)
  overall_confidence: float = 0.0
  data_sources_used: List[str] = field(default_factory=list)
  refinement_count: int = 0

  def __post_init__(self):
    if not self.model_id:
      self.model_id = f"dt_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    if not self.created_at:
      self.created_at = now
    if not self.last_updated:
      self.last_updated = now

  def get_inferences_by_domain(self, domain: InferenceDomain) -> List[Inference]:
    """Return all inferences for a given domain."""
    return [i for i in self.all_inferences if i.domain == domain]

  def get_confirmed_facts(self) -> List[Inference]:
    """Return all inferences at CONFIRMED tier."""
    return [i for i in self.all_inferences if i.tier == ConfidenceTier.CONFIRMED]

  def get_high_value_targets(self) -> List[AttackSurfaceEntry]:
    """Return attack surface entries sorted by risk score (descending)."""
    return sorted(self.attack_surface, key=lambda e: e.risk_score, reverse=True)

  def to_dict(self) -> Dict[str, Any]:
    """Serialise the twin model to a dictionary (for JSON export)."""
    def _serialise(obj):
      if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
      if isinstance(obj, Enum):
        return obj.value
      if isinstance(obj, (datetime,)):
        return obj.isoformat()
      if isinstance(obj, list):
        return [_serialise(i) for i in obj]
      if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
      return obj
    return _serialise(self)


# ── Correlation Engine ─────────────────────────────────────────────────────────


class CorrelationEngine:
  """Cross-source fact correlation and inference synthesis.

  Takes raw observations from disparate data sources and attempts to
  correlate them into coherent inferences. Uses heuristics like:
    - IP/hostname matching across sources
    - Temporal proximity of observations
    - Technology version consistency
    - Employee name/role co-occurrence
  """

  def __init__(self):
    self._observations: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

  def ingest(self, source: str, observations: List[Dict[str, Any]]) -> None:
    """Ingest raw observations from a data source.

    Args:
      source: Source name (e.g. 'shodan', 'linkedin').
      observations: List of observation dicts.
    """
    for obs in observations:
      obs["_source"] = source
      obs["_ingested_at"] = datetime.now(timezone.utc).isoformat()
      # Index by a compound key for fast lookup
      key = self._observation_key(obs)
      self._observations[key].append(obs)

    logger.debug("correlation: ingested %d observations from %s",
                  len(observations), source)

  def correlate_ip(self, ip_address: str) -> List[Inference]:
    """Correlate all observations about a specific IP address."""
    inferences: List[Inference] = []
    related = []

    for key, obs_list in self._observations.items():
      for obs in obs_list:
        if obs.get("ip") == ip_address or obs.get("ip_address") == ip_address:
          related.append(obs)

    if not related:
      return inferences

    # Cluster observations by type
    by_type: Dict[str, List[Dict]] = defaultdict(list)
    for obs in related:
      obs_type = obs.get("type", obs.get("observation_type", "unknown"))
      by_type[obs_type].append(obs)

    # Synthesise inferences per type cluster
    for obs_type, obs_list in by_type.items():
      if obs_type in ("open_port", "port", "service"):
        inferences.extend(self._infer_services(ip_address, obs_list))
      elif obs_type in ("banner", "version", "technology"):
        inferences.extend(self._infer_technology(ip_address, obs_list))
      elif obs_type in ("hostname", "dns", "fqdn"):
        inferences.extend(self._infer_hostname(ip_address, obs_list))
      elif obs_type in ("os", "operating_system"):
        inferences.extend(self._infer_os(ip_address, obs_list))
      else:
        inferences.append(self._generic_inference(ip_address, obs_type, obs_list))

    return inferences

  def correlate_domain(self, domain: str) -> List[Inference]:
    """Correlate all observations about a specific domain."""
    inferences: List[Inference] = []
    related = []

    domain_lower = domain.lower()
    for key, obs_list in self._observations.items():
      for obs in obs_list:
        obs_domain = obs.get("domain", obs.get("hostname", obs.get("fqdn", ""))).lower()
        if domain_lower in obs_domain or obs_domain in domain_lower:
          related.append(obs)

    if not related:
      return inferences

    # DNS records
    dns_obs = [o for o in related if o.get("type") in ("dns", "dns_record", "a_record", "cname")]
    if dns_obs:
      inferences.extend(self._infer_dns(domain, dns_obs))

    # Certificate observations
    cert_obs = [o for o in related if o.get("type") in ("certificate", "tls_cert", "ssl_cert")]
    if cert_obs:
      inferences.extend(self._infer_certificates(domain, cert_obs))

    # Technology observations
    tech_obs = [o for o in related if o.get("type") in ("technology", "tech_stack", "header")]
    if tech_obs:
      inferences.extend(self._infer_technology(domain, tech_obs))

    return inferences

  def correlate_employee(self, name: str) -> List[Inference]:
    """Correlate observations about a specific employee."""
    inferences: List[Inference] = []
    name_lower = name.lower()
    related = []

    for key, obs_list in self._observations.items():
      for obs in obs_list:
        obs_name = obs.get("name", obs.get("full_name", obs.get("display_name", ""))).lower()
        if name_lower in obs_name:
          related.append(obs)

    if not related:
      return inferences

    # Build employee profile inference
    titles = set()
    departments = set()
    emails = set()
    githubs = set()
    sources = []
    evidence = []

    for obs in related:
      sources.append(obs.get("_source", "unknown"))
      evidence.append(obs)
      if obs.get("title"):
        titles.add(obs["title"])
      if obs.get("department"):
        departments.add(obs["department"])
      if obs.get("email"):
        emails.add(obs["email"])
      if obs.get("github") or obs.get("github_username"):
        githubs.add(obs.get("github") or obs.get("github_username"))

    inf = Inference(
      domain=InferenceDomain.EMPLOYEE_MAP,
      fact=f"Employee: {name}, Titles: {list(titles)}, Departments: {list(departments)}",
      fact_type="employee_profile",
      value={
        "name": name,
        "titles": list(titles),
        "departments": list(departments),
        "emails": list(emails),
        "github_usernames": list(githubs),
      },
      sources=list(set(sources)),
      evidence=evidence,
    )
    inferences.append(inf)
    return inferences

  def _observation_key(self, obs: Dict[str, Any]) -> str:
    """Derive a stable key for indexing an observation."""
    parts = []
    for k in ("ip", "ip_address", "domain", "hostname", "email", "name"):
      if obs.get(k):
        parts.append(f"{k}={obs[k]}")
    if not parts:
      parts.append(f"hash={hashlib.md5(json.dumps(obs, sort_keys=True, default=str).encode()).hexdigest()[:8]}")
    return "|".join(parts)

  def _infer_services(self, ip_address: str, obs_list: List[Dict]) -> List[Inference]:
    """Infer services running on an IP from port observations."""
    inferences = []
    ports_info = []
    for obs in obs_list:
      port = obs.get("port", obs.get("port_number", 0))
      service = obs.get("service", obs.get("service_name", "unknown"))
      ports_info.append({"port": port, "service": service, "source": obs.get("_source")})

    for pi in ports_info:
      inf = Inference(
        domain=InferenceDomain.NETWORK_TOPOLOGY,
        fact=f"{ip_address}:{pi['port']} runs {pi['service']}",
        fact_type="open_service",
        value={"ip": ip_address, "port": pi["port"], "service": pi["service"]},
        sources=[pi["source"]],
      )
      inf.add_evidence(pi["source"], pi)
      inferences.append(inf)
    return inferences

  def _infer_technology(self, identifier: str, obs_list: List[Dict]) -> List[Inference]:
    """Infer technology stack from banner/version observations."""
    inferences = []
    for obs in obs_list:
      tech = obs.get("technology", obs.get("product", obs.get("software", "unknown")))
      version = obs.get("version", "")
      fact = f"{identifier} uses {tech}"
      if version:
        fact += f" v{version}"
      inf = Inference(
        domain=InferenceDomain.TECHNOLOGY_STACK,
        fact=fact,
        fact_type="technology",
        value={"host": identifier, "technology": tech, "version": version},
        sources=[obs.get("_source", "unknown")],
      )
      inf.add_evidence(obs.get("_source", "unknown"), obs)
      inferences.append(inf)
    return inferences

  def _infer_hostname(self, ip_address: str, obs_list: List[Dict]) -> List[Inference]:
    """Infer hostname from DNS/PTR observations."""
    inferences = []
    hostnames = set()
    for obs in obs_list:
      hn = obs.get("hostname", obs.get("fqdn", obs.get("ptr_record", "")))
      if hn:
        hostnames.add(hn)

    if hostnames:
      inf = Inference(
        domain=InferenceDomain.NETWORK_TOPOLOGY,
        fact=f"{ip_address} resolves to {list(hostnames)}",
        fact_type="hostname",
        value={"ip": ip_address, "hostnames": list(hostnames)},
        sources=list(set(o.get("_source", "") for o in obs_list)),
      )
      for obs in obs_list:
        inf.add_evidence(obs.get("_source", ""), obs)
      inferences.append(inf)
    return inferences

  def _infer_os(self, ip_address: str, obs_list: List[Dict]) -> List[Inference]:
    """Infer operating system from OS detection observations."""
    inferences = []
    os_names = set()
    for obs in obs_list:
      os_name = obs.get("os", obs.get("operating_system", obs.get("os_name", "")))
      if os_name:
        os_names.add(os_name)

    if os_names:
      inf = Inference(
        domain=InferenceDomain.TECHNOLOGY_STACK,
        fact=f"{ip_address} runs {list(os_names)}",
        fact_type="operating_system",
        value={"ip": ip_address, "os": list(os_names)},
        sources=list(set(o.get("_source", "") for o in obs_list)),
      )
      for obs in obs_list:
        inf.add_evidence(obs.get("_source", ""), obs)
      inferences.append(inf)
    return inferences

  def _infer_dns(self, domain: str, obs_list: List[Dict]) -> List[Inference]:
    """Infer DNS configuration from DNS observations."""
    inferences = []
    a_records = set()
    cnames = set()
    mx_records = set()
    ns_records = set()
    txt_records = []

    for obs in obs_list:
      record_type = obs.get("record_type", obs.get("type", "")).upper()
      value = obs.get("value", obs.get("data", obs.get("record_data", "")))
      if record_type == "A":
        a_records.add(value)
      elif record_type == "CNAME":
        cnames.add(value)
      elif record_type == "MX":
        mx_records.add(value)
      elif record_type == "NS":
        ns_records.add(value)
      elif record_type == "TXT":
        txt_records.append(value)

    if a_records:
      inf = Inference(
        domain=InferenceDomain.NETWORK_TOPOLOGY,
        fact=f"{domain} A records: {list(a_records)}",
        fact_type="dns_a_record",
        value={"domain": domain, "a_records": list(a_records)},
        sources=list(set(o.get("_source", "") for o in obs_list)),
      )
      for obs in obs_list:
        inf.add_evidence(obs.get("_source", ""), obs)
      inferences.append(inf)

    if mx_records:
      inf = Inference(
        domain=InferenceDomain.NETWORK_TOPOLOGY,
        fact=f"{domain} MX: {list(mx_records)}",
        fact_type="dns_mx_record",
        value={"domain": domain, "mx_records": list(mx_records)},
        sources=list(set(o.get("_source", "") for o in obs_list)),
      )
      for obs in obs_list:
        inf.add_evidence(obs.get("_source", ""), obs)
      inferences.append(inf)

    return inferences

  def _infer_certificates(self, domain: str, obs_list: List[Dict]) -> List[Inference]:
    """Infer certificate details from TLS certificate observations."""
    inferences = []
    sans = set()
    issuers = set()
    for obs in obs_list:
      san_list = obs.get("san", obs.get("subject_alt_names", []))
      if isinstance(san_list, list):
        for san in san_list:
          sans.add(san)
      issuer = obs.get("issuer", obs.get("ca", ""))
      if issuer:
        issuers.add(issuer)

    if sans:
      inf = Inference(
        domain=InferenceDomain.NETWORK_TOPOLOGY,
        fact=f"{domain} cert SANs: {list(sans)[:10]}",
        fact_type="certificate_san",
        value={"domain": domain, "subject_alt_names": list(sans), "issuers": list(issuers)},
        sources=list(set(o.get("_source", "") for o in obs_list)),
      )
      for obs in obs_list:
        inf.add_evidence(obs.get("_source", ""), obs)
      inferences.append(inf)
    return inferences

  def _generic_inference(self, identifier: str, obs_type: str,
                          obs_list: List[Dict]) -> Inference:
    """Create a generic inference from unclassified observations."""
    inf = Inference(
      domain=InferenceDomain.TECHNOLOGY_STACK,
      fact=f"{identifier}: {obs_type} observed ({len(obs_list)} sources)",
      fact_type=obs_type,
      value={"identifier": identifier, "observations": obs_list},
      sources=list(set(o.get("_source", "") for o in obs_list)),
    )
    for obs in obs_list:
      inf.add_evidence(obs.get("_source", ""), obs)
    return inf

  def flush_observations(self) -> None:
    """Clear the observation cache."""
    self._observations.clear()


# ── Data Source Adapters ───────────────────────────────────────────────────────


class DataSourceAdapter:
  """Base class for data source adapters.

  Each adapter normalises raw data from a specific intelligence source
  into a standardised observation format consumable by the CorrelationEngine.
  """

  def __init__(self, source_name: str):
    self.source_name = source_name
    self.reliability = _SOURCE_RELIABILITY.get(source_name, 0.5)

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    """Normalise raw source data into standard observations.

    Subclasses MUST override this.

    Args:
      raw_data: Raw data from the source (JSON, dict, list, etc.).

    Returns:
      List of standardised observation dicts.
    """
    raise NotImplementedError("Subclasses must implement normalise()")


class ShodanAdapter(DataSourceAdapter):
  """Normalise Shodan API results."""

  def __init__(self):
    super().__init__("shodan")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    data = raw_data if isinstance(raw_data, dict) else {}
    matches = data.get("matches", data.get("data", []))

    if isinstance(data, dict) and "ip_str" in data:
      matches = [data]

    for match in matches:
      if not isinstance(match, dict):
        continue
      ip = match.get("ip_str", match.get("ip", ""))
      port = match.get("port", 0)
      obs = {
        "type": "service",
        "ip": ip,
        "port": port,
        "service": match.get("_shodan", {}).get("module", match.get("transport", "unknown")),
        "hostname": next(iter(match.get("hostnames", [])), ""),
        "os": match.get("os", match.get("os_vendor", "")),
        "org": match.get("org", ""),
        "isp": match.get("isp", ""),
        "asn": match.get("asn", ""),
        "banner": match.get("data", "")[:500],
        "timestamp": match.get("timestamp", ""),
        "country": match.get("location", {}).get("country_name", ""),
        "city": match.get("location", {}).get("city", ""),
        "latitude": match.get("location", {}).get("latitude", 0),
        "longitude": match.get("location", {}).get("longitude", 0),
      }
      observations.append(obs)
    return observations


class CensysAdapter(DataSourceAdapter):
  """Normalise Censys API results."""

  def __init__(self):
    super().__init__("censys")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    results = raw_data if isinstance(raw_data, list) else raw_data.get("results", [])

    for res in results:
      if not isinstance(res, dict):
        continue
      obs = {
        "type": "censys_result",
        "ip": res.get("ip", ""),
        "services": res.get("services", []),
        "hostname": res.get("dns", {}).get("reverse_dns", {}).get("names", [None])[0] if res.get("dns") else "",
        "os": res.get("operating_system", {}).get("product", ""),
        "autonomous_system": res.get("autonomous_system", {}),
        "location": res.get("location", {}),
        "last_updated": res.get("last_updated_at", ""),
      }
      observations.append(obs)
    return observations


class CertificateLogsAdapter(DataSourceAdapter):
  """Normalise certificate transparency log results (crt.sh)."""

  def __init__(self):
    super().__init__("certificate_logs")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    entries = raw_data if isinstance(raw_data, list) else []

    for entry in entries:
      if not isinstance(entry, dict):
        continue
      name_value = entry.get("name_value", entry.get("common_name", ""))
      sans = [n.strip() for n in name_value.split("\n") if n.strip()] if name_value else []
      obs = {
        "type": "certificate",
        "domain": entry.get("common_name", sans[0] if sans else ""),
        "san": sans,
        "issuer": entry.get("issuer_name", entry.get("issuer_ca_id", "")),
        "not_before": entry.get("not_before", ""),
        "not_after": entry.get("not_after", ""),
        "serial": entry.get("serial_number", ""),
      }
      observations.append(obs)
    return observations


class LinkedInAdapter(DataSourceAdapter):
  """Normalise LinkedIn profile data."""

  def __init__(self):
    super().__init__("linkedin")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    profiles = raw_data if isinstance(raw_data, list) else raw_data.get("profiles", raw_data.get("results", []))

    for profile in profiles:
      if not isinstance(profile, dict):
        continue
      obs = {
        "type": "linkedin_profile",
        "name": profile.get("name", profile.get("full_name", "")),
        "title": profile.get("title", profile.get("headline", "")),
        "company": profile.get("company", profile.get("current_company", {}).get("name", "")),
        "department": profile.get("department", ""),
        "location": profile.get("location", ""),
        "skills": profile.get("skills", []),
        "summary": profile.get("summary", profile.get("about", ""))[:1000],
        "email": profile.get("email", ""),
        "public_profile": profile.get("public_url", profile.get("url", "")),
        "connections": profile.get("connections_count", 0),
      }
      observations.append(obs)
    return observations


class GitHubAdapter(DataSourceAdapter):
  """Normalise GitHub profile and repository data."""

  def __init__(self):
    super().__init__("github")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    items = raw_data if isinstance(raw_data, list) else raw_data.get("items", raw_data.get("results", []))

    for item in items:
      if not isinstance(item, dict):
        continue
      obs_type = "github_repo" if item.get("full_name") else "github_profile"
      obs = {
        "type": obs_type,
        "username": item.get("owner", {}).get("login", item.get("login", "")),
        "name": item.get("name", item.get("full_name", "")),
        "description": item.get("description", "")[:500],
        "language": item.get("language", ""),
        "topics": item.get("topics", []),
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "url": item.get("html_url", item.get("url", "")),
        "created_at": item.get("created_at", ""),
        "updated_at": item.get("updated_at", ""),
      }
      observations.append(obs)
    return observations


class JobPostingsAdapter(DataSourceAdapter):
  """Normalise job posting data."""

  def __init__(self):
    super().__init__("job_postings")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    postings = raw_data if isinstance(raw_data, list) else raw_data.get("jobs", raw_data.get("results", []))

    tech_keywords = re.compile(
      r'(aws|azure|gcp|kubernetes|docker|terraform|ansible|jenkins|gitlab|'
      r'python|java|javascript|react|angular|golang|rust|'
      r'elasticsearch|kafka|redis|mongodb|postgresql|mysql|oracle|'
      r'splunk|elk|prometheus|grafana|datadog|'
      r'firewall|waf|ids|ips|siem|soc|cisco|palo alto|fortinet|'
      r'okta|active directory|ldap|saml|oauth)',
      re.IGNORECASE,
    )

    for posting in postings:
      if not isinstance(posting, dict):
        continue
      title = posting.get("title", "")
      description = posting.get("description", posting.get("body", ""))
      technologies = tech_keywords.findall(f"{title} {description}")
      obs = {
        "type": "job_posting",
        "title": title,
        "department": posting.get("department", ""),
        "location": posting.get("location", ""),
        "technologies": list(set(t.lower() for t in technologies)),
        "seniority": posting.get("seniority", posting.get("experience_level", "")),
        "company": posting.get("company", posting.get("employer", "")),
        "url": posting.get("url", ""),
        "posted_at": posting.get("posted_at", posting.get("date", "")),
      }
      observations.append(obs)
    return observations


class WhoisAdapter(DataSourceAdapter):
  """Normalise WHOIS lookup results."""

  def __init__(self):
    super().__init__("whois")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    data = raw_data if isinstance(raw_data, dict) else {}

    obs = {
      "type": "whois",
      "domain": data.get("domain_name", data.get("domain", "")),
      "registrar": data.get("registrar", ""),
      "creation_date": data.get("creation_date", data.get("created", "")),
      "expiration_date": data.get("expiration_date", data.get("expires", "")),
      "name_servers": data.get("name_servers", data.get("nservers", [])),
      "registrant_name": data.get("registrant_name", data.get("name", "")),
      "registrant_org": data.get("registrant_organization", data.get("org", "")),
      "registrant_email": data.get("registrant_email", data.get("email", "")),
      "registrant_phone": data.get("registrant_phone", data.get("phone", "")),
      "registrant_address": data.get("registrant_address", data.get("address", "")),
      "country": data.get("registrant_country", data.get("country", "")),
      "admin_email": data.get("admin_email", ""),
      "tech_email": data.get("tech_email", ""),
    }
    observations.append(obs)
    return observations


class PhysicalAdapter(DataSourceAdapter):
  """Normalise satellite imagery and street view metadata."""

  def __init__(self):
    super().__init__("satellite_imagery")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    locations = raw_data if isinstance(raw_data, list) else raw_data.get("locations", raw_data.get("results", []))

    for loc in locations:
      if not isinstance(loc, dict):
        continue
      obs = {
        "type": "physical_location",
        "address": loc.get("address", loc.get("formatted_address", "")),
        "city": loc.get("city", ""),
        "state": loc.get("state", loc.get("administrative_area_level_1", "")),
        "country": loc.get("country", ""),
        "postal_code": loc.get("postal_code", loc.get("postal_code_suffix", "")),
        "latitude": loc.get("latitude", loc.get("lat", 0)),
        "longitude": loc.get("longitude", loc.get("lng", 0)),
        "site_type": loc.get("site_type", loc.get("type", "office")),
        "building_name": loc.get("building_name", ""),
        "building_size_sqft": loc.get("building_size", loc.get("floor_area", 0)),
        "floor_count": loc.get("floors", loc.get("floor_count", 0)),
        "image_date": loc.get("image_date", loc.get("captured_at", "")),
        "source": loc.get("source", "satellite"),
      }
      observations.append(obs)
    return observations


class SecurityFilingsAdapter(DataSourceAdapter):
  """Normalise SEC EDGAR filings."""

  def __init__(self):
    super().__init__("sec_filings")

  def normalise(self, raw_data: Any) -> List[Dict[str, Any]]:
    observations = []
    filings = raw_data if isinstance(raw_data, list) else raw_data.get("filings", raw_data.get("results", []))

    risk_keywords = re.compile(
      r'(cyber\s*security|data\s*breach|incident\s*response|'
      r'business\s*continuity|disaster\s*recovery|'
      r'information\s*security|privacy|compliance|'
      r'third.party\s*risk|supply\s*chain|cloud\s*provider)',
      re.IGNORECASE,
    )

    for filing in filings:
      if not isinstance(filing, dict):
        continue
      text = filing.get("description", filing.get("body", filing.get("text", "")))
      risks = risk_keywords.findall(text)
      obs = {
        "type": "sec_filing",
        "company": filing.get("company", filing.get("company_name", "")),
        "cik": filing.get("cik", ""),
        "filing_type": filing.get("filing_type", filing.get("form", "")),
        "filing_date": filing.get("filing_date", filing.get("date", "")),
        "risk_areas": list(set(r.lower().replace(" ", "_") for r in risks)),
        "url": filing.get("url", ""),
      }
      observations.append(obs)
    return observations


# ── Adapter registry ───────────────────────────────────────────────────────────

_ADAPTER_REGISTRY: Dict[str, type] = {
  "shodan": ShodanAdapter,
  "censys": CensysAdapter,
  "certificate_logs": CertificateLogsAdapter,
  "linkedin": LinkedInAdapter,
  "github": GitHubAdapter,
  "job_postings": JobPostingsAdapter,
  "whois": WhoisAdapter,
  "satellite_imagery": PhysicalAdapter,
  "street_view": PhysicalAdapter,
  "sec_filings": SecurityFilingsAdapter,
}


# ── Digital Twin Engine ────────────────────────────────────────────────────────


class DigitalTwinEngine:
  """Passive target replication engine.

  Builds a complete digital replica of a target environment from PASSIVE
  data alone — zero packets sent to the target. Correlates intelligence
  from OSINT, social media, technical code repositories, infrastructure
  disclosures, and physical imagery to construct a multi-domain model.

  Usage:
    engine = DigitalTwinEngine()
    twin = engine.create_twin(target_identifier="example.com")

    # Ingest passive data from various sources
    engine.ingest("shodan", shodan_json)
    engine.ingest("certificate_logs", crtsh_json)
    engine.ingest("linkedin", linkedin_profiles)
    engine.ingest("github", github_repos)

    # Build and refine the model
    twin = engine.build_model()
    twin = engine.refine_model()  # after more data arrives

    # Export
    report = engine.export_twin(twin, format="json")
    attack_surface = engine.compute_attack_surface(twin)
    defense_gaps = engine.identify_defense_gaps(twin)
  """

  def __init__(self, db=None):
    """Initialise the Digital Twin Engine.

    Args:
      db: PhantomStrikeDB instance for persistence (optional).
    """
    self._db = db
    self._correlator = CorrelationEngine()
    self._adapters: Dict[str, DataSourceAdapter] = {}
    self._models: Dict[str, TwinModel] = {}
    self._inference_counter: int = 0
    logger.info("digital_twin: engine initialised with %d adapters available",
                 len(_ADAPTER_REGISTRY))

  # ── Data Ingestion ─────────────────────────────────────────────────────────

  def ingest(self, source: str, raw_data: Any,
              target_identifier: Optional[str] = None) -> int:
    """Ingest raw intelligence data from a named source.

    Automatically selects the correct adapter to normalise the data,
    then feeds observations into the correlation engine.

    Args:
      source: Source name (e.g. 'shodan', 'linkedin', 'github').
      raw_data: Raw data from the source.
      target_identifier: Optional target to scope observations against.

    Returns:
      Number of observations ingested.
    """
    # Resolve adapter
    if source not in self._adapters:
      adapter_cls = _ADAPTER_REGISTRY.get(source)
      if adapter_cls is None:
        logger.warning("digital_twin: no adapter for source '%s', using generic", source)
        self._adapters[source] = DataSourceAdapter(source)
      else:
        self._adapters[source] = adapter_cls()

    adapter = self._adapters[source]

    try:
      observations = adapter.normalise(raw_data)
    except Exception as exc:
      logger.error("digital_twin: failed to normalise data from %s: %s", source, exc)
      return 0

    if not observations:
      logger.debug("digital_twin: no observations extracted from %s", source)
      return 0

    # Tag observations with target if provided
    if target_identifier:
      for obs in observations:
        obs["_target"] = target_identifier

    self._correlator.ingest(source, observations)
    logger.info("digital_twin: ingested %d observations from %s (reliability=%.2f)",
                 len(observations), source, adapter.reliability)
    return len(observations)

  # ── Model Building ─────────────────────────────────────────────────────────

  def create_twin(self, target_identifier: str) -> TwinModel:
    """Initialise a new digital twin for a target.

    Args:
      target_identifier: Domain, IP range, or organisation name.

    Returns:
      A fresh TwinModel ready for data ingestion and building.
    """
    model = TwinModel(target_identifier=target_identifier)
    self._models[model.model_id] = model
    logger.info("digital_twin: created model %s for target '%s'",
                 model.model_id, target_identifier)
    return model

  def build_model(self, model_id: Optional[str] = None,
                   target_identifier: Optional[str] = None) -> TwinModel:
    """Construct the complete digital twin from all ingested data.

    Runs correlations across all domains, synthesises inferences
    into structured sub-models, and computes overall confidence.

    Args:
      model_id: Existing model ID to update, or None to create new.
      target_identifier: Target for a new model if model_id not given.

    Returns:
      The fully constructed TwinModel.
    """
    if model_id and model_id in self._models:
      model = self._models[model_id]
    elif target_identifier:
      model = self.create_twin(target_identifier)
    else:
      raise ValueError("Either model_id or target_identifier is required")

    if not model.target_identifier:
      raise ValueError("Model must have a target_identifier")

    t0 = time.monotonic()

    # Build each domain
    model.network_topology = self._build_network_topology(model.target_identifier)
    model.security_stack = self._build_security_stack(model.target_identifier)
    model.technology_stack = self._build_technology_stack(model.target_identifier)
    model.employee_map = self._build_employee_map(model.target_identifier)
    model.physical_layout = self._build_physical_layout(model.target_identifier)

    # Correlate cross-domain insights
    self._cross_correlate(model)

    # Compute attack surface and defense gaps
    model.attack_surface = self.compute_attack_surface(model)
    model.defense_gaps = self.identify_defense_gaps(model)

    # Aggregate all inferences
    model.all_inferences = self._collect_all_inferences(model)

    # Compute overall confidence
    model.overall_confidence = self._compute_overall_confidence(model)

    model.last_updated = datetime.now(timezone.utc).isoformat()
    model.version += 1

    build_time = (time.monotonic() - t0) * 1000
    logger.info("digital_twin: model %s built in %.0f ms (%.0f%% confidence, %d domains)",
                 model.model_id, build_time,
                 model.overall_confidence * 100, 5)
    return model

  def _build_network_topology(self, target: str) -> NetworkTopology:
    """Build network topology from correlated observations."""
    topo = NetworkTopology()

    # Extract IP observations
    ip_inferences: List[Inference] = self._correlator.correlate_ip(target) if self._looks_like_ip(target) else []
    domain_inferences: List[Inference] = self._correlator.correlate_domain(target)

    all_infs = ip_inferences + domain_inferences

    for inf in all_infs:
      val = inf.value or {}
      if inf.fact_type == "dns_a_record":
        for ip in val.get("a_records", []):
          if ":" not in ip:  # IPv4 only for now
            topo.hosts.append(HostNode(
              host_id=f"host_{hashlib.md5(ip.encode()).hexdigest()[:8]}",
              ip_address=ip,
              fqdn=val.get("domain", target),
              confidence=inf.confidence,
            ))
      elif inf.fact_type == "open_service":
        ip = val.get("ip", "")
        port = val.get("port", 0)
        service = val.get("service", "")
        # Find or create host
        host = next((h for h in topo.hosts if h.ip_address == ip), None)
        if host is None:
          host = HostNode(
            host_id=f"host_{hashlib.md5(ip.encode()).hexdigest()[:8]}",
            ip_address=ip,
            confidence=inf.confidence,
          )
          topo.hosts.append(host)
        if port not in host.open_ports:
          host.open_ports.append(port)
        host.services[port] = service
        host.is_exposed = True
        topo.external_services.setdefault(target, []).append(port)
      elif inf.fact_type == "dns_mx_record":
        topo.mail_servers.extend(val.get("mx_records", []))
      elif inf.fact_type == "hostname":
        hostnames = val.get("hostnames", [])
        for hn in hostnames:
          if "ns" in hn.lower() or "dns" in hn.lower():
            topo.dns_servers.append(hn)

    # Deduplicate
    topo.external_services[target] = sorted(set(topo.external_services.get(target, [])))
    topo.dns_servers = sorted(set(topo.dns_servers))
    topo.mail_servers = sorted(set(topo.mail_servers))

    # Confidence
    if topo.hosts:
      topo.confidence = round(
        sum(h.confidence for h in topo.hosts) / len(topo.hosts), 3
      )
    return topo

  def _build_security_stack(self, target: str) -> SecurityStack:
    """Build security stack profile from observations."""
    sec = SecurityStack()

    # Common WAF/security header patterns
    waf_headers = {
      "x-cdn": "CDN",
      "cf-ray": "Cloudflare",
      "x-amz-cf-id": "AWS CloudFront",
      "x-sucuri-id": "Sucuri",
      "x-akamai-transformed": "Akamai",
      "server": "",
      "x-powered-by": "",
      "x-aspnet-version": "",
    }

    # Security policy headers
    policy_headers = {
      "content-security-policy": "CSP",
      "strict-transport-security": "HSTS",
      "x-content-type-options": "X-Content-Type-Options",
      "x-frame-options": "X-Frame-Options",
      "x-xss-protection": "X-XSS-Protection",
      "referrer-policy": "Referrer-Policy",
      "permissions-policy": "Permissions-Policy",
    }

    # Scrape domain inferences for security signals
    domain_infs = self._correlator.correlate_domain(target)
    for inf in domain_infs:
      val = inf.value or {}
      if inf.fact_type == "certificate":
        issuers = val.get("issuers", [])
        if isinstance(issuers, list):
          sec.cert_authorities.extend(issuers)
      elif inf.fact_type == "technology":
        tech = str(val.get("technology", "")).lower()
        if "waf" in tech or "firewall" in tech:
          sec.waf_provider = val.get("technology", "")
          sec.waf_confidence = inf.confidence

    sec.cert_authorities = list(set(sec.cert_authorities))
    sec.confidence = 0.3  # baseline — most security data needs active probes
    return sec

  def _build_technology_stack(self, target: str) -> TechnologyStack:
    """Build technology stack profile from observations."""
    tech = TechnologyStack()

    domain_infs = self._correlator.correlate_domain(target)

    web_servers = set()
    databases = set()
    frameworks = set()
    languages = set()
    cms = set()
    cdns = set()

    for inf in domain_infs:
      val = inf.value or {}
      if inf.fact_type == "technology":
        t = str(val.get("technology", "")).lower()

        # Web servers
        for ws in ("apache", "nginx", "iis", "tomcat", "caddy", "lighttpd", "traefik", "envoy"):
          if ws in t:
            web_servers.add(ws)
        # Databases
        for db in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch", "oracle", "mssql", "mariadb"):
          if db in t:
            databases.add(db)
        # Frameworks
        for fw in ("django", "flask", "rails", "laravel", "spring", "express", "fastapi", "next.js", "nuxt"):
          if fw in t:
            frameworks.add(fw)
        # Languages
        for lang in ("python", "java", "javascript", "php", "ruby", "go", "rust", "c#", "typescript"):
          if lang in t:
            languages.add(lang)
        # CMS
        for c in ("wordpress", "drupal", "joomla", "shopify", "magento", "wix", "squarespace"):
          if c in t:
            cms.add(c)
        # CDN
        for cdn in ("cloudflare", "cloudfront", "akamai", "fastly", "cdn77", "bunnycdn", "keycdn"):
          if cdn in t:
            cdns.add(cdn)

      # Version hints
      version = val.get("version", "")
      if version:
        tech_name = val.get("technology", "")
        tech.version_hints[tech_name] = str(version)

    tech.web_servers = sorted(web_servers)
    tech.databases = sorted(databases)
    tech.frameworks = sorted(frameworks)
    tech.languages = sorted(languages)
    tech.cms = sorted(cms)
    tech.cdns = sorted(cdns)

    # Confidence
    total_items = (len(web_servers) + len(databases) + len(frameworks) +
                   len(languages) + len(cms) + len(cdns))
    if total_items > 0:
      confidences = [inf.confidence for inf in domain_infs]
      tech.confidence = round(sum(confidences) / max(len(confidences), 1), 3)

    return tech

  def _build_employee_map(self, target: str) -> EmployeeMap:
    """Build employee map from LinkedIn, GitHub, and job posting data."""
    emp_map = EmployeeMap()

    # Extract all employee-related observations
    all_obs: List[Dict[str, Any]] = []
    for key, obs_list in self._correlator._observations.items():
      for obs in obs_list:
        if obs.get("type") in ("linkedin_profile", "github_profile"):
          all_obs.append(obs)

    # Group by name
    by_name: Dict[str, List[Dict]] = defaultdict(list)
    for obs in all_obs:
      name = obs.get("name", obs.get("username", "")).strip()
      if name:
        by_name[name.lower()].append(obs)

    for name_key, obs_list in by_name.items():
      # Merge observations into employee profile
      titles = set()
      departments = set()
      emails = set()
      githubs = set()
      linkedin_urls = set()
      for obs in obs_list:
        if obs.get("title"):
          titles.add(obs["title"])
        if obs.get("department"):
          departments.add(obs["department"])
        if obs.get("email"):
          emails.add(obs["email"])
        if obs.get("username") and obs.get("type") == "github_profile":
          githubs.add(obs["username"])
        if obs.get("public_profile"):
          linkedin_urls.add(obs["public_profile"])

      primary_title = list(titles)[0] if titles else ""
      is_tech = any(kw in primary_title.lower() for kw in
                     ("engineer", "developer", "devops", "sre", "architect",
                      "security", "admin", "it ", "cto", "cio"))
      is_security = any(kw in primary_title.lower() for kw in
                         ("security", "ciso", "infosec", "cyber", "incident", "soc"))

      emp = Employee(
        name=name_key.title(),
        title=primary_title,
        department=list(departments)[0] if departments else "",
        email=list(emails)[0] if emails else "",
        linkedin_url=list(linkedin_urls)[0] if linkedin_urls else "",
        github_username=list(githubs)[0] if githubs else "",
        technical_role=is_tech,
        security_role=is_security,
        public_profile=True,
        confidence=min(0.9, len(obs_list) * 0.3),
      )
      emp_map.employees.append(emp)

    # Identify key personnel
    for emp in emp_map.employees:
      if emp.security_role or any(t in emp.title.lower() for t in
                                    ("cto", "cio", "ciso", "vp of engineering",
                                     "head of", "director of security")):
        emp_map.key_personnel.append(emp.name)

    # Infer email format
    emp_map.email_format = self._infer_email_format(emp_map.employees)

    emp_map.confidence = min(0.8, len(emp_map.employees) * 0.05)
    return emp_map

  def _infer_email_format(self, employees: List[Employee]) -> str:
    """Infer corporate email format from known employee names/emails."""
    if not employees:
      return ""
    for emp in employees:
      if emp.email and emp.name:
        local = emp.email.split("@")[0] if "@" in emp.email else ""
        name_parts = emp.name.lower().split()
        if not name_parts:
          continue
        if local == f"{name_parts[0]}.{name_parts[-1]}":
          return "first.last@domain"
        elif local == f"{name_parts[0]}{name_parts[-1]}":
          return "firstlast@domain"
        elif local == f"{name_parts[0][0]}{name_parts[-1]}":
          return "flast@domain"
        elif local == name_parts[0]:
          return "first@domain"
    return "unknown"

  def _build_physical_layout(self, target: str) -> PhysicalLayout:
    """Build physical layout from WHOIS, job postings, and satellite data."""
    layout = PhysicalLayout()
    locations: Dict[str, PhysicalLocation] = {}

    # Extract location observations
    for key, obs_list in self._correlator._observations.items():
      for obs in obs_list:
        if obs.get("type") in ("whois", "physical_location", "job_posting"):
          country = obs.get("country", "")
          city = obs.get("city", "")
          addr = obs.get("address", "")
          lat = obs.get("latitude", 0)
          lng = obs.get("longitude", 0)

          if not city and not country and not addr:
            continue

          loc_key = f"{addr or city}_{country}".strip("_")
          if loc_key not in locations:
            locations[loc_key] = PhysicalLocation(
              location_id=f"loc_{hashlib.md5(loc_key.encode()).hexdigest()[:8]}",
              address=addr,
              city=city,
              country=country,
              latitude=float(lat) if lat else 0,
              longitude=float(lng) if lng else 0,
              site_type=obs.get("site_type", "office"),
              building_size_sqft=obs.get("building_size_sqft", 0),
              floor_count=obs.get("floor_count", 0),
              confidence=0.5,
            )

    layout.locations = list(locations.values())

    # Identify headquarters (usually the first/primary location)
    for loc in layout.locations:
      if loc.site_type in ("headquarters", "hq") or "hq" in loc.address.lower():
        layout.primary_hq = loc
        break
    if layout.primary_hq is None and layout.locations:
      layout.primary_hq = layout.locations[0]

    # Separate data centers
    layout.data_centers = [l for l in layout.locations if l.site_type == "data_center"]

    layout.office_countries = sorted(set(l.country for l in layout.locations if l.country))

    layout.confidence = min(0.8, len(layout.locations) * 0.15)
    return layout

  # ── Attack Surface Computation ─────────────────────────────────────────────

  def compute_attack_surface(self, model: TwinModel) -> List[AttackSurfaceEntry]:
    """Compute the consolidated attack surface from the digital twin.

    Aggregates all exposed services, web applications, APIs, VPN endpoints,
    email gateways, cloud assets, and social vectors into a ranked list.

    Args:
      model: The constructed digital twin model.

    Returns:
      List of AttackSurfaceEntry sorted by risk_score descending.
    """
    entries: List[AttackSurfaceEntry] = []
    seen: Set[str] = set()

    # Network-based entries
    for host in model.network_topology.hosts:
      for port in host.open_ports:
        service = host.services.get(port, "unknown")
        key = f"{host.ip_address}:{port}"
        if key in seen:
          continue
        seen.add(key)

        risk = self._score_service_risk(port, service, host, model)
        entries.append(AttackSurfaceEntry(
          entry_id=f"as_{hashlib.md5(key.encode()).hexdigest()[:8]}",
          entry_type="network_service",
          target=f"{host.ip_address}:{port}",
          protocol="tcp",
          port=port,
          service=service,
          risk_score=risk,
          exploitability="easy" if port in (80, 443, 8080, 8443) else "moderate",
          confidence=host.confidence,
        ))

    # Web application entries (from technology stack)
    for domain, ports in model.network_topology.external_services.items():
      for port in ports:
        key = f"web:{domain}:{port}"
        if key in seen:
          continue
        seen.add(key)

        tech_risk = 50.0
        if model.technology_stack.cms:
          tech_risk += 10.0  # CMS = larger attack surface
        if not model.security_stack.waf_provider:
          tech_risk += 15.0  # No WAF = higher risk

        entries.append(AttackSurfaceEntry(
          entry_id=f"as_{hashlib.md5(key.encode()).hexdigest()[:8]}",
          entry_type="web_app",
          target=f"{domain}:{port}",
          protocol="https" if port == 443 else "http",
          port=port,
          service="web",
          risk_score=min(100.0, tech_risk),
          exploitability="easy",
          confidence=0.7,
        ))

    # Email-based entries
    for mx in model.network_topology.mail_servers:
      key = f"mail:{mx}"
      if key in seen:
        continue
      seen.add(key)
      entries.append(AttackSurfaceEntry(
        entry_id=f"as_{hashlib.md5(key.encode()).hexdigest()[:8]}",
        entry_type="email",
        target=mx,
        protocol="smtp",
        port=25,
        service="smtp",
        risk_score=40.0,
        exploitability="moderate",
        confidence=0.6,
      ))

    # Social engineering entries (from employee map)
    for emp in model.employee_map.employees[:10]:  # top 10 by confidence
      if emp.security_role or emp.technical_role:
        key = f"social:{emp.email or emp.name}"
        if key in seen:
          continue
        seen.add(key)
        entries.append(AttackSurfaceEntry(
          entry_id=f"as_{hashlib.md5(key.encode()).hexdigest()[:8]}",
          entry_type="social",
          target=emp.email or emp.linkedin_url or emp.name,
          protocol="",
          port=0,
          service="human",
          risk_score=60.0 if emp.security_role else 35.0,
          exploitability="easy",
          confidence=emp.confidence,
        ))

    return sorted(entries, key=lambda e: e.risk_score, reverse=True)

  def _score_service_risk(self, port: int, service: str, host: HostNode,
                           model: TwinModel) -> float:
    """Score the risk of an exposed service."""
    base_risk = 30.0

    # High-risk ports
    high_risk_ports = {21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 1521,
                       3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017, 11211}
    if port in high_risk_ports:
      base_risk += 25.0

    # Authentication services
    if port in (22, 3389, 5900):
      base_risk += 15.0

    # Database services are high value
    if service in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch",
                   "oracle", "mssql", "cassandra"):
      base_risk += 20.0

    # Industrial protocols
    if service in ("modbus", "dnp3", "s7comm", "bacnet", "ethernet-ip", "profinet"):
      base_risk += 35.0

    # Exposed hosts are higher risk
    if host.is_exposed:
      base_risk += 10.0

    # No WAF increases risk
    if not model.security_stack.waf_provider:
      base_risk += 5.0

    return min(100.0, base_risk)

  # ── Defense Gap Identification ─────────────────────────────────────────────

  def identify_defense_gaps(self, model: TwinModel) -> List[DefenseGap]:
    """Identify defense gaps and weaknesses from the digital twin.

    Analyses the constructed model for missing security controls,
    exposed dangerous services, outdated technology, and other
    exploitable weaknesses.

    Args:
      model: The constructed digital twin model.

    Returns:
      List of DefenseGap objects.
    """
    gaps: List[DefenseGap] = []

    # Gap: No WAF detected
    if not model.security_stack.waf_provider:
      gaps.append(DefenseGap(
        gap_id=f"gap_{uuid.uuid4().hex[:8]}",
        category="missing_control",
        severity="high",
        description="No Web Application Firewall detected for web services",
        affected_system=model.target_identifier,
        exploitability="easy",
        evidence_sources=["passive_recon"],
        remediation="Deploy a WAF (Cloudflare, AWS WAF, ModSecurity) in front of web applications",
        confidence=0.7,
      ))

    # Gap: Exposed high-risk services
    for host in model.network_topology.hosts:
      dangerous_ports = {22, 3389, 3306, 5432, 6379, 27017, 11211}
      for port in host.open_ports:
        if port in dangerous_ports:
          service = host.services.get(port, "unknown")
          gaps.append(DefenseGap(
            gap_id=f"gap_{uuid.uuid4().hex[:8]}",
            category="exposed_service",
            severity="high" if port in (22, 3389) else "medium",
            description=f"Potentially sensitive service {service} exposed on {host.ip_address}:{port}",
            affected_system=f"{host.ip_address}:{port}",
            exploitability="easy" if port == 3306 else "moderate",
            evidence_sources=["shodan", "passive_recon"],
            remediation=f"Restrict access to {service} using firewall rules or move behind VPN",
            confidence=host.confidence,
          ))

    # Gap: No SPF/DMARC/DKIM (inferred from DNS)
    mx_count = len(model.network_topology.mail_servers)
    if mx_count > 0:
      # We can't verify without active checks, but flag as possible
      gaps.append(DefenseGap(
        gap_id=f"gap_{uuid.uuid4().hex[:8]}",
        category="missing_control",
        severity="medium",
        description=f"Email servers detected ({mx_count} MX records) — SPF/DMARC/DKIM status unknown (requires active DNS check)",
        affected_system="email",
        exploitability="moderate",
        evidence_sources=["dns"],
        remediation="Implement SPF, DKIM, and DMARC to prevent email spoofing",
        confidence=0.5,
      ))

    # Gap: Technology with known vulnerabilities (heuristic)
    for tech_name, version in model.technology_stack.version_hints.items():
      gaps.append(DefenseGap(
        gap_id=f"gap_{uuid.uuid4().hex[:8]}",
        category="known_vulnerabilities",
        severity="info",
        description=f"Technology {tech_name} v{version} detected — should be checked against CVE database",
        affected_system=f"{tech_name}:{version}",
        exploitability="unknown",
        evidence_sources=["passive_recon"],
        remediation=f"Verify {tech_name} version and patch any known CVEs",
        confidence=0.4,
      ))

    # Gap: Social engineering surface
    exposed_employees = [e for e in model.employee_map.employees if e.public_profile]
    if len(exposed_employees) > 5:
      gaps.append(DefenseGap(
        gap_id=f"gap_{uuid.uuid4().hex[:8]}",
        category="social_engineering",
        severity="medium",
        description=f"{len(exposed_employees)} employees with public professional profiles — increased phishing/social engineering risk",
        affected_system="human",
        exploitability="easy",
        evidence_sources=["linkedin", "github"],
        remediation="Security awareness training, limit public profile information",
        confidence=0.6,
      ))

    return gaps

  # ── Cross-Domain Correlation ───────────────────────────────────────────────

  def _cross_correlate(self, model: TwinModel) -> None:
    """Perform cross-domain correlations for richer insights.

    Examples:
      - Job posting tech stack vs. observed technology
      - Employee locations vs. physical office locations
      - GitHub repos vs. production technology stack
    """
    # Compare job posting technologies with observed tech stack
    job_techs: Set[str] = set()
    for key, obs_list in self._correlator._observations.items():
      for obs in obs_list:
        if obs.get("type") == "job_posting":
          for t in obs.get("technologies", []):
            job_techs.add(t.lower())

    observed_techs: Set[str] = set()
    observed_techs.update(model.technology_stack.web_servers)
    observed_techs.update(model.technology_stack.databases)
    observed_techs.update(model.technology_stack.frameworks)
    observed_techs.update(model.technology_stack.languages)

    # Technologies in job postings but not yet observed
    unseen = job_techs - observed_techs
    if unseen:
      inf = Inference(
        domain=InferenceDomain.TECHNOLOGY_STACK,
        fact=f"Technologies from job postings not yet observed: {sorted(unseen)}",
        fact_type="inferred_technology",
        value={"inferred_technologies": sorted(unseen)},
        sources=["job_postings"],
      )
      for tech_name in unseen:
        inf.add_evidence("job_postings", {"technology": tech_name, "inferred": True})
      model.all_inferences.append(inf)

      # Add to tech stack as inferred
      for tech_name in unseen:
        if tech_name in ("aws", "azure", "gcp"):
          model.technology_stack.cloud_services.append(tech_name)
        elif tech_name in ("kubernetes", "docker", "rancher", "openshift", "nomad"):
          model.technology_stack.container_orchestration.append(tech_name)
        elif tech_name in ("jenkins", "gitlab", "github actions", "circleci", "travis"):
          model.technology_stack.ci_cd.append(tech_name)

  # ── Continuous Refinement ──────────────────────────────────────────────────

  def refine_model(self, model_id: str,
                   new_data: Optional[Dict[str, Any]] = None) -> TwinModel:
    """Refine an existing digital twin with new data.

    When new reconnaissance data confirms or denies earlier inferences,
    this method updates confidences, removes contradicted facts, and
    adds newly discovered information.

    Args:
      model_id: The model to refine.
      new_data: Optional dict of source -> raw_data to ingest before refining.

    Returns:
      The updated TwinModel.
    """
    if model_id not in self._models:
      raise ValueError(f"Model '{model_id}' not found")

    # Ingest new data if provided
    if new_data:
      for source, raw in new_data.items():
        self.ingest(source, raw, target_identifier=self._models[model_id].target_identifier)

    # Rebuild from all accumulated observations
    model = self.build_model(model_id=model_id)
    model.refinement_count += 1

    logger.info("digital_twin: model %s refined (round %d, %.0f%% confidence)",
                 model.model_id, model.refinement_count,
                 model.overall_confidence * 100)
    return model

  def confirm_inference(self, model_id: str, inference_id: str,
                         confirmed: bool = True,
                         source: str = "manual_confirmation") -> bool:
    """Manually confirm or deny an inference, updating confidence.

    Args:
      model_id: The model containing the inference.
      inference_id: The inference to confirm/deny.
      confirmed: True to confirm, False to deny.
      source: Label for the confirmation source.

    Returns:
      True if the inference was found and updated.
    """
    if model_id not in self._models:
      return False

    model = self._models[model_id]
    for inf in model.all_inferences:
      if inf.inference_id == inference_id:
        if confirmed:
          inf.add_evidence(source, {"confirmed": True},
                            reliability=_SOURCE_RELIABILITY.get(source, 1.0))
          inf.validated = True
        else:
          inf.add_contradiction(source, {"confirmed": False},
                                 reliability=_SOURCE_RELIABILITY.get(source, 1.0))
        return True

    return False

  # ── Export ─────────────────────────────────────────────────────────────────

  def export_twin(self, model: TwinModel, export_format: str = "json") -> str:
    """Export the digital twin model in the requested format.

    Args:
      model: The TwinModel to export.
      export_format: 'json' or 'markdown'.

    Returns:
      Formatted string representation.
    """
    if export_format == "json":
      return json.dumps(model.to_dict(), indent=2, default=str)

    elif export_format == "markdown":
      return self._export_markdown(model)

    return json.dumps(model.to_dict(), indent=2, default=str)

  def _export_markdown(self, model: TwinModel) -> str:
    """Generate a markdown intelligence report."""
    lines = [
      f"# Digital Twin Report: {model.target_identifier}",
      f"",
      f"**Model ID**: {model.model_id}  ",
      f"**Overall Confidence**: {model.overall_confidence:.0%}  ",
      f"**Last Updated**: {model.last_updated}  ",
      f"**Data Sources**: {', '.join(model.data_sources_used) or 'none'}  ",
      f"**Refinements**: {model.refinement_count}  ",
      f"",
      f"## Network Topology (confidence: {model.network_topology.confidence:.0%})",
      f"",
    ]

    if model.network_topology.hosts:
      lines.append("| Host | IP | Ports | Services | Exposed |")
      lines.append("|------|----|-------|----------|---------|")
      for host in model.network_topology.hosts:
        svc_str = ", ".join(f"{p}:{s}" for p, s in host.services.items())
        lines.append(f"| {host.hostname or '?'} | {host.ip_address} | {host.open_ports} | {svc_str} | {host.is_exposed} |")
    else:
      lines.append("_No hosts identified yet._")
    lines.append("")

    lines.append(f"## Security Stack (confidence: {model.security_stack.confidence:.0%})")
    lines.append(f"- WAF: {model.security_stack.waf_provider or 'None detected'}")
    lines.append(f"- TLS Versions: {model.security_stack.tls_versions or 'Unknown'}")
    lines.append(f"- Certificate Authorities: {', '.join(model.security_stack.cert_authorities) or 'Unknown'}")
    lines.append("")

    lines.append(f"## Technology Stack (confidence: {model.technology_stack.confidence:.0%})")
    ts = model.technology_stack
    lines.append(f"- Web Servers: {', '.join(ts.web_servers) or 'Unknown'}")
    lines.append(f"- Databases: {', '.join(ts.databases) or 'Unknown'}")
    lines.append(f"- Frameworks: {', '.join(ts.frameworks) or 'Unknown'}")
    lines.append(f"- Languages: {', '.join(ts.languages) or 'Unknown'}")
    lines.append(f"- CMS: {', '.join(ts.cms) or 'None'}")
    lines.append(f"- CDNs: {', '.join(ts.cdns) or 'None'}")
    if ts.version_hints:
      lines.append(f"- Versions: {json.dumps(ts.version_hints)}")
    lines.append("")

    lines.append(f"## Employee Map (confidence: {model.employee_map.confidence:.0%})")
    lines.append(f"- Employees identified: {len(model.employee_map.employees)}")
    lines.append(f"- Key personnel: {', '.join(model.employee_map.key_personnel) or 'None'}")
    lines.append(f"- Email format: {model.employee_map.email_format or 'Unknown'}")
    lines.append("")

    lines.append(f"## Physical Layout (confidence: {model.physical_layout.confidence:.0%})")
    for loc in model.physical_layout.locations:
      lines.append(f"- {loc.city}, {loc.country} — {loc.site_type} ({loc.address})")
    lines.append("")

    lines.append(f"## Attack Surface (top 10 by risk)")
    lines.append("| Target | Type | Risk Score | Exploitability |")
    lines.append("|--------|------|------------|----------------|")
    for entry in model.attack_surface[:10]:
      lines.append(f"| {entry.target} | {entry.entry_type} | {entry.risk_score:.0f} | {entry.exploitability} |")
    lines.append("")

    lines.append(f"## Defense Gaps")
    for gap in model.defense_gaps:
      lines.append(f"- [{gap.severity.upper()}] {gap.description} ({gap.confidence:.0%} confidence)")
    lines.append("")

    lines.append(f"## Inference Summary")
    lines.append(f"- CONFIRMED: {len([i for i in model.all_inferences if i.tier == ConfidenceTier.CONFIRMED])}")
    lines.append(f"- LIKELY: {len([i for i in model.all_inferences if i.tier == ConfidenceTier.LIKELY])}")
    lines.append(f"- POSSIBLE: {len([i for i in model.all_inferences if i.tier == ConfidenceTier.POSSIBLE])}")
    lines.append(f"- SPECULATIVE: {len([i for i in model.all_inferences if i.tier == ConfidenceTier.SPECULATIVE])}")
    lines.append(f"- UNVERIFIED: {len([i for i in model.all_inferences if i.tier == ConfidenceTier.UNVERIFIED])}")

    return "\n".join(lines)

  # ── Helpers ────────────────────────────────────────────────────────────────

  def _looks_like_ip(self, value: str) -> bool:
    """Check if a string looks like an IP address."""
    import re as _re
    return bool(_re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))

  def _collect_all_inferences(self, model: TwinModel) -> List[Inference]:
    """Collect inferences from all sub-models into a unified list."""
    return model.all_inferences  # populated during build

  def _compute_overall_confidence(self, model: TwinModel) -> float:
    """Compute aggregate confidence across all domains."""
    confidences = [
      model.network_topology.confidence,
      model.security_stack.confidence,
      model.technology_stack.confidence,
      model.employee_map.confidence,
      model.physical_layout.confidence,
    ]
    valid = [c for c in confidences if c > 0]
    if not valid:
      return 0.1
    return round(sum(valid) / len(valid), 3)

  def get_model(self, model_id: str) -> Optional[TwinModel]:
    """Retrieve a model by ID."""
    return self._models.get(model_id)

  def list_models(self) -> List[Dict[str, Any]]:
    """List all digital twin models."""
    return [
      {
        "model_id": m.model_id,
        "target": m.target_identifier,
        "confidence": m.overall_confidence,
        "version": m.version,
        "last_updated": m.last_updated,
        "refinements": m.refinement_count,
      }
      for m in self._models.values()
    ]

  def get_stats(self) -> Dict[str, Any]:
    """Return engine statistics."""
    return {
      "models_count": len(self._models),
      "adapters_loaded": list(self._adapters.keys()),
      "sources_available": list(_ADAPTER_REGISTRY.keys()),
      "observation_cache_size": sum(len(v) for v in self._correlator._observations.values()),
    }

  def reset(self) -> None:
    """Reset the engine state (clear all models and observations)."""
    self._models.clear()
    self._correlator.flush_observations()
    logger.info("digital_twin: engine reset")
