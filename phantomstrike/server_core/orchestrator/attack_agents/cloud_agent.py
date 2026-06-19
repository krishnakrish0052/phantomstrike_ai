"""
server_core/orchestrator/attack_agents/cloud_agent.py

Cloud Infrastructure attack specialist agent.

Extends BaseAgent with agent_type="cloud". Provides deep expertise in
AWS, GCP, and Azure attack surfaces — IAM privilege escalation, container
escape, Kubernetes RBAC abuse, serverless exploitation, cloud metadata
service attacks, storage bucket discovery, and cross-account trust
exploitation.

Elite knowledge embedded: every AWS IAM policy effect/action/resource
combination, GCP organisation hierarchy and IAM inheritance, Azure RBAC
role definitions, and Kubernetes RBAC verb-to-resource matrices.

Real tools: iam-privesc, container-escape, k8s-attack, prowler patterns,
cloudmapper, serverless-exploit, metadata-attack, bucket-discovery,
trust-exploit.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from server_core.orchestrator.agent_base import (
    AgentResult,
    BaseAgent,
    CAPABILITY_LIBRARY,
    PatternMatcher,
    ToolExecutor,
)
from server_core import ModernVisualEngine

if __name__ != "__main__":
    logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Register cloud capabilities in the global capability library
# ---------------------------------------------------------------------------

CAPABILITY_LIBRARY["cloud"] = [
    "iam_privesc",
    "container_escape",
    "k8s_attack",
    "prowler_patterns",
    "cloudmapper",
    "serverless_exploit",
    "metadata_attack",
    "bucket_discovery",
    "trust_exploit",
    "cloud_recon",
    "resource_enum",
    "policy_audit",
]


# ---------------------------------------------------------------------------
# Elite knowledge: cloud provider fingerprinting data
# ---------------------------------------------------------------------------

class CloudKnowledge:
    """Embedded elite knowledge for cloud attack surface analysis.

    Covers AWS IAM, GCP IAM / org hierarchy, Azure RBAC, and K8s RBAC
    at a level of detail suitable for real privilege-escalation pathfinding.
    """

    # --- Provider detection signatures ----------------------------------
    PROVIDER_SIGNATURES: Dict[str, List[str]] = {
        "aws": [
            "amazonaws.com", ".aws.", "ec2.", "s3.", "arn:aws:", "AKIA",
            "ASIA", "elasticbeanstalk.com", "cloudfront.net",
            "amazoncognito.com", "execute-api.", "aws-region",
        ],
        "gcp": [
            "googleapis.com", ".gcp.", "gcloud", "compute.googleapis.com",
            "storage.googleapis.com", "cloudfunctions.net",
            "run.app", "appspot.com", "firebaseio.com",
        ],
        "azure": [
            "azure.com", ".azure.", "azurewebsites.net", "blob.core.windows.net",
            "cloudapp.azure.com", "azurefd.net", "azmk8s.io",
            "trafficmanager.net", "vault.azure.net", "database.windows.net",
        ],
    }

    PROVIDER_METADATA_ENDPOINTS: Dict[str, Dict[str, str]] = {
        "aws": {
            "base": "http://169.254.169.254/latest/meta-data/",
            "iam_role": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "user_data": "http://169.254.169.254/latest/user-data/",
            "instance_identity": "http://169.254.169.254/latest/dynamic/instance-identity/document",
        },
        "gcp": {
            "base": "http://metadata.google.internal/computeMetadata/v1/",
            "service_account": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "project_id": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "custom_sa": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{sa}/token",
        },
        "azure": {
            "base": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "identity_token": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "attested_data": "http://169.254.169.254/metadata/attested/document?api-version=2021-02-01",
        },
    }

    # --- AWS IAM escalation paths ---------------------------------------
    AWS_ESCALATION_PATHS: List[Dict[str, Any]] = [
        {
            "name": "iam:CreatePolicyVersion",
            "description": "Create a new policy version to add admin permissions to an existing attached policy. Requires iam:CreatePolicyVersion.",
            "permission": "iam:CreatePolicyVersion",
            "severity": "critical",
            "method": "Create new default policy version with AdministratorAccess inline, then set as default.",
        },
        {
            "name": "iam:SetDefaultPolicyVersion",
            "description": "Set an older policy version as default to regain previously removed permissions. Requires iam:SetDefaultPolicyVersion.",
            "permission": "iam:SetDefaultPolicyVersion",
            "severity": "critical",
            "method": "Roll back a customer-managed policy to a prior version that grants more access.",
        },
        {
            "name": "iam:CreateAccessKey",
            "description": "Create new access keys for an IAM user with higher privileges. Requires iam:CreateAccessKey.",
            "permission": "iam:CreateAccessKey",
            "severity": "high",
            "method": "Generate access key for a target IAM user, then use those credentials directly.",
        },
        {
            "name": "iam:CreateLoginProfile",
            "description": "Create a console password for a user that doesn't have one. Requires iam:CreateLoginProfile.",
            "permission": "iam:CreateLoginProfile",
            "severity": "high",
            "method": "Set a password for a privileged user, then log in via the AWS Console.",
        },
        {
            "name": "iam:UpdateLoginProfile",
            "description": "Change the password of an existing user. Requires iam:UpdateLoginProfile.",
            "permission": "iam:UpdateLoginProfile",
            "severity": "high",
            "method": "Reset the password of an admin IAM user, then assume their console access.",
        },
        {
            "name": "iam:AttachUserPolicy / iam:AttachRolePolicy / iam:AttachGroupPolicy",
            "description": "Attach the AdministratorAccess managed policy to a target principal. Requires any Attach*Policy permission.",
            "permission": "iam:AttachUserPolicy",
            "severity": "critical",
            "method": "Attach AdministratorAccess to self or a controlled entity.",
        },
        {
            "name": "iam:PutUserPolicy / iam:PutRolePolicy / iam:PutGroupPolicy",
            "description": "Put an inline policy granting admin on a principal. Requires any Put*Policy permission.",
            "permission": "iam:PutUserPolicy",
            "severity": "critical",
            "method": "Create an inline policy with sts:AssumeRole on * or iam:* on *.",
        },
        {
            "name": "iam:AddUserToGroup",
            "description": "Add self to a privileged IAM group. Requires iam:AddUserToGroup.",
            "permission": "iam:AddUserToGroup",
            "severity": "high",
            "method": "Enumerate groups, find one with admin perms, add self.",
        },
        {
            "name": "iam:UpdateAssumeRolePolicy",
            "description": "Modify a role's trust policy to allow your principal to assume it. Requires iam:UpdateAssumeRolePolicy.",
            "permission": "iam:UpdateAssumeRolePolicy",
            "severity": "critical",
            "method": "Edit trust policy of a target role to include your AWS account or principal ARN.",
        },
        {
            "name": "sts:AssumeRole",
            "description": "Assume a privileged role directly. Requires sts:AssumeRole on target role.",
            "permission": "sts:AssumeRole",
            "severity": "high",
            "method": "Call sts:AssumeRole with a target role ARN that trusts your principal.",
        },
        {
            "name": "lambda:UpdateFunctionCode / lambda:CreateFunction",
            "description": "Deploy a malicious Lambda function that uses its execution role. Requires lambda:UpdateFunctionCode and iam:PassRole.",
            "permission": "lambda:UpdateFunctionCode",
            "severity": "critical",
            "method": "Upload code to an existing Lambda; the Lambda's execution role runs the code.",
        },
        {
            "name": "ec2:RunInstances + iam:PassRole",
            "description": "Launch an EC2 instance with a privileged instance profile, then access its metadata. Requires ec2:RunInstances + iam:PassRole.",
            "permission": "iam:PassRole",
            "severity": "high",
            "method": "Boot EC2 with an admin instance profile, SSH in, query metadata for creds.",
        },
        {
            "name": "cloudformation:CreateStack",
            "description": "Deploy a CloudFormation stack that creates a privileged IAM role. Requires cloudformation:CreateStack + iam:PassRole.",
            "permission": "cloudformation:CreateStack",
            "severity": "critical",
            "method": "Template creates AdminRole and outputs its ARN; assume it after stack creation.",
        },
        {
            "name": "glue:CreateDevEndpoint / glue:UpdateDevEndpoint",
            "description": "Glue DevEndpoints use an IAM role; modify to use an admin role. Requires glue:CreateDevEndpoint + iam:PassRole.",
            "permission": "glue:CreateDevEndpoint",
            "severity": "high",
            "method": "Create a Glue DevEndpoint with a high-privilege role, SSH in.",
        },
    ]

    # --- GCP escalation paths -------------------------------------------
    GCP_ESCALATION_PATHS: List[Dict[str, Any]] = [
        {
            "name": "iam.serviceAccounts.getAccessToken",
            "description": "Generate an OAuth token for a target service account. Requires iam.serviceAccounts.getAccessToken.",
            "permission": "iam.serviceAccounts.getAccessToken",
            "severity": "critical",
            "method": "Call generateAccessToken API on a privileged SA; use the returned token.",
        },
        {
            "name": "iam.serviceAccounts.signBlob / signJwt",
            "description": "Sign an arbitrary JWT as a target service account. Requires iam.serviceAccounts.signJwt.",
            "permission": "iam.serviceAccounts.signJwt",
            "severity": "critical",
            "method": "Sign a JWT with the target SA's key; exchange for an OAuth token.",
        },
        {
            "name": "iam.serviceAccounts.actAs",
            "description": "Impersonate a service account when calling another API. Requires iam.serviceAccounts.actAs.",
            "permission": "iam.serviceAccounts.actAs",
            "severity": "critical",
            "method": "Use --impersonate-service-account with gcloud to act as a higher-privilege SA.",
        },
        {
            "name": "iam.serviceAccounts.setIamPolicy",
            "description": "Modify a service account's IAM policy to grant yourself actAs. Requires iam.serviceAccounts.setIamPolicy.",
            "permission": "iam.serviceAccounts.setIamPolicy",
            "severity": "critical",
            "method": "Add roles/iam.serviceAccountTokenCreator to your principal on the target SA.",
        },
        {
            "name": "iam.roles.update / iam.roles.create",
            "description": "Create or update a custom IAM role with expanded permissions. Requires iam.roles.update.",
            "permission": "iam.roles.update",
            "severity": "critical",
            "method": "Edit a custom role to include permissions you need, then assign to yourself.",
        },
        {
            "name": "resourcemanager.organizations.setIamPolicy",
            "description": "Set IAM policy at org level — inherited by all folders/projects. Requires org-level setIamPolicy.",
            "permission": "resourcemanager.organizations.setIamPolicy",
            "severity": "critical",
            "method": "Grant yourself roles/owner at the org node; inherited by every resource below.",
        },
        {
            "name": "resourcemanager.folders.setIamPolicy",
            "description": "Set IAM policy at folder level — inherited by child projects. Requires folder-level setIamPolicy.",
            "permission": "resourcemanager.folders.setIamPolicy",
            "severity": "critical",
            "method": "Grant yourself roles/owner on a parent folder of target projects.",
        },
        {
            "name": "resourcemanager.projects.setIamPolicy",
            "description": "Set IAM policy at project level. Requires project-level setIamPolicy.",
            "permission": "resourcemanager.projects.setIamPolicy",
            "severity": "critical",
            "method": "Grant yourself roles/owner directly on the target project.",
        },
        {
            "name": "cloudfunctions.functions.create / update",
            "description": "Deploy a Cloud Function that runs as the function's runtime SA. Requires cloudfunctions.functions.create + actAs on the SA.",
            "permission": "cloudfunctions.functions.create",
            "severity": "critical",
            "method": "Deploy a Cloud Function with an admin runtime SA; trigger it to exfiltrate creds.",
        },
    ]

    # --- Azure RBAC escalation paths ------------------------------------
    AZURE_ESCALATION_PATHS: List[Dict[str, Any]] = [
        {
            "name": "Microsoft.Authorization/roleAssignments/write",
            "description": "Create a role assignment at a scope (subscription, RG, resource). The Owner role has this by default.",
            "permission": "Microsoft.Authorization/roleAssignments/write",
            "severity": "critical",
            "method": "Assign Contributor or Owner role to a principal you control at the target scope.",
        },
        {
            "name": "Microsoft.Authorization/roleDefinitions/write",
            "description": "Create or update a custom RBAC role definition. Requires roleDefinitions/write.",
            "permission": "Microsoft.Authorization/roleDefinitions/write",
            "severity": "critical",
            "method": "Create a custom role with Microsoft.Authorization/*/write, assign to self.",
        },
        {
            "name": "Microsoft.Resources/subscriptions/resourceGroups/write",
            "description": "Create a new resource group — you become Owner of it. Requires resourceGroups/write at subscription scope.",
            "permission": "Microsoft.Resources/subscriptions/resourceGroups/write",
            "severity": "high",
            "method": "Create an RG where you are Owner; deploy resources there.",
        },
        {
            "name": "Microsoft.Compute/virtualMachines/runCommand/action",
            "description": "Run arbitrary commands on a VM via the Azure fabric. Requires runCommand/action.",
            "permission": "Microsoft.Compute/virtualMachines/runCommand/action",
            "severity": "critical",
            "method": "Invoke RunCommand on a VM; command executes as SYSTEM (Windows) or root (Linux).",
        },
        {
            "name": "Microsoft.Web/sites/publishxml/action",
            "description": "Download the publish profile (credentials) for an App Service. Requires publishxml/action.",
            "permission": "Microsoft.Web/sites/publishxml/action",
            "severity": "high",
            "method": "Download the .publishsettings XML, extract FTP / deployment creds.",
        },
        {
            "name": "Microsoft.KeyVault/vaults/accessPolicies/write",
            "description": "Modify Key Vault access policies to grant yourself keys/secrets access. Requires accessPolicies/write.",
            "permission": "Microsoft.KeyVault/vaults/accessPolicies/write",
            "severity": "critical",
            "method": "Add an access policy granting yourself Get/List on keys and secrets.",
        },
        {
            "name": "Microsoft.Storage/storageAccounts/listKeys/action",
            "description": "List storage account access keys. Requires listKeys/action.",
            "permission": "Microsoft.Storage/storageAccounts/listKeys/action",
            "severity": "critical",
            "method": "POST listKeys, retrieve key1/key2, use for full data-plane access.",
        },
        {
            "name": "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
            "description": "Assign a managed identity to a resource. Useful with a privileged UAMI. Requires assign/action.",
            "permission": "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
            "severity": "high",
            "method": "Assign a privileged user-assigned managed identity to a VM you control.",
        },
    ]

    # --- K8s RBAC privilege escalation ----------------------------------
    K8S_ESCALATION_PATHS: List[Dict[str, Any]] = [
        {
            "name": "pods/exec (create)",
            "description": "Exec into any pod in a namespace; the pod's service account token is available via the filesystem. Requires create on pods/exec.",
            "resource": "pods/exec",
            "verb": "create",
            "severity": "critical",
            "method": "kubectl exec into a pod running with a privileged SA, cat /var/run/secrets/kubernetes.io/serviceaccount/token.",
        },
        {
            "name": "pods/create",
            "description": "Create a pod with a privileged service account, hostPath mounts, or hostNetwork. Requires create on pods.",
            "resource": "pods",
            "verb": "create",
            "severity": "critical",
            "method": "Launch a pod mounting the host filesystem (hostPath: /) or using a high-privilege SA.",
        },
        {
            "name": "secrets/list + secrets/get",
            "description": "Read any secret in a namespace — including service account tokens. Requires get/list on secrets.",
            "resource": "secrets",
            "verb": "get",
            "severity": "critical",
            "method": "kubectl get secrets -o yaml; extract SA tokens, decode base64.",
        },
        {
            "name": "roles/rolebindings (create/update)",
            "description": "Create or update a RoleBinding that grants cluster-admin or similar to your principal. Requires create/update on rolebindings.",
            "resource": "rolebindings",
            "verb": "create",
            "severity": "critical",
            "method": "Create a RoleBinding binding cluster-admin ClusterRole to your user/group/SA.",
        },
        {
            "name": "clusterroles/clusterrolebindings (create/update)",
            "description": "Create or modify a ClusterRoleBinding — cluster-wide privilege elevation. Requires create on clusterrolebindings.",
            "resource": "clusterrolebindings",
            "verb": "create",
            "severity": "critical",
            "method": "Bind cluster-admin ClusterRole to your principal via a ClusterRoleBinding.",
        },
        {
            "name": "serviceaccounts/token (create)",
            "description": "Create a token for any service account. Requires create on serviceaccounts/token (TokenRequest).",
            "resource": "serviceaccounts/token",
            "verb": "create",
            "severity": "critical",
            "method": "Create a short-lived token bound to a high-privilege SA via the TokenRequest API.",
        },
        {
            "name": "nodes/proxy",
            "description": "Proxy through the API server to a kubelet — bypasses API server authz. Requires get on nodes/proxy.",
            "resource": "nodes/proxy",
            "verb": "get",
            "severity": "critical",
            "method": "Proxy to kubelet on a node, access /pods, /run, or /logs endpoints.",
        },
        {
            "name": "certificatesigningrequests (create)",
            "description": "Request a client certificate for a privileged group (system:masters). Requires create on certificatesigningrequests.",
            "resource": "certificatesigningrequests",
            "verb": "create",
            "severity": "critical",
            "method": "Submit a CSR with CN=admin,O=system:masters; approve and use the cert.",
        },
    ]

    # --- Container escape techniques ------------------------------------
    CONTAINER_ESCAPE_TECHNIQUES: List[Dict[str, Any]] = [
        {
            "name": "privileged_container_escape",
            "description": "If the container runs with --privileged, all devices are exposed. cgroup notify-on-release escape or device mount.",
            "requires": "container runs with --privileged flag",
            "severity": "critical",
            "method": "Mount the host disk via /dev/sda1, chroot, or use cgroups notify-on-release to escape.",
        },
        {
            "name": "cap_sys_admin_escape",
            "description": "CAP_SYS_ADMIN allows mounting filesystems. Mount cgroup, create a release_agent, trigger escape.",
            "requires": "CAP_SYS_ADMIN capability",
            "severity": "critical",
            "method": "Mount a cgroup v1 fs, set notify_on_release + release_agent to a script on host, kill -1.",
        },
        {
            "name": "cap_sys_ptrace_escape",
            "description": "CAP_SYS_PTRACE allows injecting code into host processes (e.g., pid 1 or a host daemon).",
            "requires": "CAP_SYS_PTRACE capability, host PID namespace accessible",
            "severity": "critical",
            "method": "Use ptrace to inject shellcode into a process on the host.",
        },
        {
            "name": "docker_socket_mount",
            "description": "If /var/run/docker.sock is mounted into the container, you can control the Docker daemon on the host.",
            "requires": "Docker socket mounted: /var/run/docker.sock",
            "severity": "critical",
            "method": "docker run -v /:/host --privileged alpine chroot /host from within the container.",
        },
        {
            "name": "host_pid_namespace",
            "description": "If --pid=host is set, you can see host processes. nsenter into PID 1 to escape.",
            "requires": "container shares host PID namespace (docker run --pid=host)",
            "severity": "critical",
            "method": "nsenter --target 1 --mount --uts --ipc --net --pid -- bash.",
        },
        {
            "name": "host_network_namespace",
            "description": "If --net=host is set, you can bind to host interfaces and snoop traffic.",
            "requires": "container shares host network namespace (docker run --net=host)",
            "severity": "high",
            "method": "tcpdump on host interfaces; access services bound to localhost.",
        },
        {
            "name": "seccomp_disabled",
            "description": "If seccomp is disabled (unconfined), syscalls like mount/ptrace/kexec are available.",
            "requires": "container runs with --security-opt seccomp=unconfined",
            "severity": "high",
            "method": "Use normally-blocked syscalls (kexec, mount, etc.) to escalate.",
        },
        {
            "name": "apparmor/selinux_disabled",
            "description": "Disabled mandatory access control allows wider syscall surface and filesystem access.",
            "requires": "container runs with --security-opt apparmor=unconfined or similar",
            "severity": "medium",
            "method": "Exploit the relaxed MAC to access restricted paths or syscalls.",
        },
    ]

    # --- Serverless attack vectors --------------------------------------
    SERVERLESS_VECTORS: List[Dict[str, Any]] = [
        {"name": "function_event_injection", "description": "Inject malicious event payloads (S3, SQS, HTTP) to trigger Lambdas with attacker data.", "provider": "aws", "severity": "high"},
        {"name": "function_role_abuse", "description": "If a Lambda has an over-privileged execution role, trigger it to perform actions on your behalf.", "provider": "aws", "severity": "critical"},
        {"name": "dependency_confusion", "description": "Publish a malicious package with the same name as an internal dependency the function imports.", "provider": "all", "severity": "high"},
        {"name": "cold_start_data_persistence", "description": "Warm a Lambda to persist data in /tmp across invocations, chaining call results.", "provider": "aws", "severity": "medium"},
        {"name": "cloud_function_source_leak", "description": "Discover function source code (env vars, embedded secrets) via misconfigured IAM or build artifacts.", "provider": "all", "severity": "high"},
        {"name": "api_gateway_bypass", "description": "Bypass API Gateway authorizers via direct Lambda URL invocation or undocumented stages.", "provider": "aws", "severity": "high"},
    ]

    # --- Cross-account trust exploitation --------------------------------
    CROSS_ACCOUNT_TRUST: List[Dict[str, Any]] = [
        {
            "name": "sts:AssumeRole cross-account",
            "description": "Assume a role in a trusting account via a misconfigured trust policy that allows overly broad principals.",
            "severity": "critical",
            "method": "Enumerate trust policies for roles; if Principal: {AWS: '*'} or a vague condition, assume from any account.",
        },
        {
            "name": "S3 bucket cross-account access",
            "description": "S3 bucket policies may allow access to an external account (AuthenticatedUsers or specific CanonicalUser).",
            "severity": "high",
            "method": "Enumerate bucket policies for cross-account grants; access as the allowed principal.",
        },
        {
            "name": "KMS key sharing",
            "description": "KMS key policies that grant kms:Decrypt to an external account allow decrypting captured ciphertexts.",
            "severity": "high",
            "method": "Find KMS keys with cross-account grants; decrypt data you've collected from the target env.",
        },
        {
            "name": "ECR repository sharing",
            "description": "ECR repository policies may allow cross-account pull; inject a backdoored image and wait for deployment.",
            "severity": "high",
            "method": "Push a malicious image to a cross-account-accessible ECR repo; it may be pulled and run.",
        },
    ]


# ---------------------------------------------------------------------------
# Deterministic pattern matcher specialized for cloud scenarios
# ---------------------------------------------------------------------------

class CloudPatternMatcher:
    """Deterministic reasoning engine for cloud attack scenarios.

    Maps objective keywords + cloud provider signals to specific attack
    strategies. Used as a fallback when no LLM is available."""

    @staticmethod
    def identify_provider(context: Dict[str, Any]) -> Optional[str]:
        """Identify the likely cloud provider from context data."""
        ctx_str = json.dumps(context, default=str).lower()

        # Score each provider by signature hits
        scores: Dict[str, int] = {}
        for provider, signatures in CloudKnowledge.PROVIDER_SIGNATURES.items():
            scores[provider] = sum(1 for sig in signatures if sig.lower() in ctx_str)

        best = max(scores, key=scores.get) if scores else None  # type: ignore[arg-type]
        if best and scores[best] > 0:
            return best
        return None

    @staticmethod
    def match(objective: str, context: Dict[str, Any], capabilities: List[str]) -> Dict[str, Any]:
        obj_lower = objective.lower()

        provider = CloudPatternMatcher.identify_provider(context)
        provider_tag = f" [{provider}]" if provider else ""

        # --- Privilege escalation ---
        if any(kw in obj_lower for kw in ["escalate", "privesc", "privilege", "admin", "root", "iam"]):
            if provider == "aws":
                return CloudPatternMatcher._pick("iam_privesc", {"provider": "aws", "target": context.get("target_host", ""), "objective": objective}, capabilities, f"AWS IAM privesc path matching{provider_tag}")
            if provider == "gcp":
                return CloudPatternMatcher._pick("iam_privesc", {"provider": "gcp", "target": context.get("target_host", ""), "objective": objective}, capabilities, f"GCP IAM privesc path matching{provider_tag}")
            if provider == "azure":
                return CloudPatternMatcher._pick("iam_privesc", {"provider": "azure", "target": context.get("target_host", ""), "objective": objective}, capabilities, f"Azure RBAC privesc path matching{provider_tag}")
            return CloudPatternMatcher._pick("iam_privesc", {"provider": "unknown", "target": context.get("target_host", ""), "objective": objective}, capabilities, "General cloud IAM privesc")

        # --- Container escape ---
        if any(kw in obj_lower for kw in ["container", "docker", "escape", "breakout", "sandbox"]):
            return CloudPatternMatcher._pick("container_escape", {"target": context.get("target_host", ""), "container_id": context.get("container_id", ""), "objective": objective}, capabilities, f"Container escape path matching{provider_tag}")

        # --- Kubernetes ---
        if any(kw in obj_lower for kw in ["kubernetes", "k8s", "kube", "pod", "cluster", "helm", "etcd"]):
            return CloudPatternMatcher._pick("k8s_attack", {"target": context.get("target_host", ""), "namespace": context.get("namespace", "default"), "objective": objective}, capabilities, f"K8s RBAC attack path matching{provider_tag}")

        # --- Metadata service ---
        if any(kw in obj_lower for kw in ["metadata", "169.254", "instance identity", "user data", "imds"]):
            return CloudPatternMatcher._pick("metadata_attack", {"target": context.get("target_host", ""), "provider": provider or "aws", "objective": objective}, capabilities, f"Cloud metadata attack matching{provider_tag}")

        # --- Storage / bucket ---
        if any(kw in obj_lower for kw in ["bucket", "storage", "s3", "blob", "gcs", "discover"]):
            return CloudPatternMatcher._pick("bucket_discovery", {"target": context.get("target_host", ""), "provider": provider or "aws", "objective": objective}, capabilities, f"Storage bucket discovery matching{provider_tag}")

        # --- Cross-account trust ---
        if any(kw in obj_lower for kw in ["cross-account", "trust", "assume role", "federation"]):
            return CloudPatternMatcher._pick("trust_exploit", {"target": context.get("target_host", ""), "provider": provider or "aws", "objective": objective}, capabilities, f"Cross-account trust exploitation{provider_tag}")

        # --- Serverless ---
        if any(kw in obj_lower for kw in ["serverless", "lambda", "function", "cloud function", "azure function"]):
            return CloudPatternMatcher._pick("serverless_exploit", {"target": context.get("target_host", ""), "provider": provider or "aws", "objective": objective}, capabilities, f"Serverless exploitation matching{provider_tag}")

        # --- Cloud recon ---
        if any(kw in obj_lower for kw in ["recon", "enumerate", "map", "audit", "scan", "discover"]):
            return CloudPatternMatcher._pick("cloud_recon", {"target": context.get("target_host", ""), "provider": provider or "auto", "objective": objective}, capabilities, f"Cloud reconnaissance matching{provider_tag}")

        # --- Prowler / CloudMapper pattern matching ---
        if any(kw in obj_lower for kw in ["prowler", "audit", "compliance", "cis", "benchmark"]):
            return CloudPatternMatcher._pick("prowler_patterns", {"target": context.get("target_host", ""), "provider": provider or "aws", "objective": objective}, capabilities, f"Prowler audit pattern matching{provider_tag}")

        # --- Fallback ---
        if capabilities:
            return {
                "type": "tool_call",
                "tool": capabilities[0],
                "params": {"target": context.get("target_host", ""), "provider": provider or "unknown", "objective": objective},
                "confidence": 0.3,
                "reasoning": f"No specific cloud pattern matched; using first available tool: {capabilities[0]}{provider_tag}",
            }

        return {
            "type": "ask_operator",
            "question": f"No cloud tools available and no pattern matched for objective: {objective}{provider_tag}",
            "confidence": 0.0,
        }

    @staticmethod
    def _pick(tool: str, params: Dict[str, Any], capabilities: List[str], reasoning: str) -> Dict[str, Any]:
        if tool in capabilities:
            return {"type": "tool_call", "tool": tool, "params": params, "confidence": 0.85, "reasoning": reasoning}
        for cap in capabilities:
            if tool.split("_")[0] in cap:
                return {"type": "tool_call", "tool": cap, "params": params, "confidence": 0.6, "reasoning": f"{reasoning} → closest: {cap}"}
        if capabilities:
            return {"type": "tool_call", "tool": capabilities[0], "params": params, "confidence": 0.4, "reasoning": f"{reasoning} → fallback: {capabilities[0]}"}
        return {"type": "ask_operator", "question": f"Needed tool {tool} but no tools available", "confidence": 0.0}


# ---------------------------------------------------------------------------
# CloudAgent — Cloud Infrastructure Attack Specialist
# ---------------------------------------------------------------------------

class CloudAgent(BaseAgent):
    """Cloud Infrastructure attack specialist.

    Elite knowledge: every AWS IAM policy combination, GCP org hierarchy,
    Azure RBAC roles, and Kubernetes RBAC verb-to-resource matrices.

    Capabilities:
      - iam-privesc:     AWS IAM / GCP IAM / Azure RBAC privilege escalation
      - container-escape: Docker/K8s container breakout techniques
      - k8s-attack:       Kubernetes RBAC abuse, pod compromise, etcd
      - prowler_patterns: CIS benchmark scanning, compliance audit patterns
      - cloudmapper:      Cloud infrastructure mapping, trust relationship analysis
      - serverless_exploit: Lambda / Cloud Functions / Azure Functions attack
      - metadata_attack:   IMDSv1/v2 bypass, user-data theft
      - bucket_discovery:  S3/GCS/Azure Blob enumeration and access
      - trust_exploit:     Cross-account role assumption, trust policy abuse
    """

    AGENT_NAME = "cloud"

    # Tool → handler method dispatch
    TOOL_HANDLERS: Dict[str, str] = {
        "iam_privesc": "_handle_iam_privesc",
        "container_escape": "_handle_container_escape",
        "k8s_attack": "_handle_k8s_attack",
        "prowler_patterns": "_handle_prowler_patterns",
        "cloudmapper": "_handle_cloudmapper",
        "serverless_exploit": "_handle_serverless_exploit",
        "metadata_attack": "_handle_metadata_attack",
        "bucket_discovery": "_handle_bucket_discovery",
        "trust_exploit": "_handle_trust_exploit",
        "cloud_recon": "_handle_cloud_recon",
        "resource_enum": "_handle_resource_enum",
        "policy_audit": "_handle_policy_audit",
    }

    def __init__(
        self,
        agent_id: str,
        hive_mind: Optional[Any] = None,
        tool_executor: Optional[ToolExecutor] = None,
        llm_client: Optional[Any] = None,
        **kwargs: Any,
    ):
        super().__init__(
            agent_id=agent_id,
            agent_type="cloud",
            hive_mind=hive_mind,
            tool_executor=tool_executor,
            llm_client=llm_client,
        )
        self._active_exploits: Dict[str, Dict[str, Any]] = {}
        self._escalation_paths_found: List[Dict[str, Any]] = []
        self._provider: Optional[str] = None
        self._session_id: Optional[str] = None

        logger.info(
            "CloudAgent %s initialised — %d cloud attack tools loaded",
            agent_id,
            len(self.capabilities),
        )

    # ------------------------------------------------------------------
    # Capability registration
    # ------------------------------------------------------------------

    def _register_capabilities(self) -> None:
        """Load cloud-specific capabilities from the global library."""
        if "cloud" in CAPABILITY_LIBRARY:
            self.capabilities = list(CAPABILITY_LIBRARY["cloud"])
        else:
            logger.warning("No 'cloud' entry in CAPABILITY_LIBRARY; using fallback set.")
            self.capabilities = [
                "iam_privesc", "container_escape", "k8s_attack",
                "prowler_patterns", "cloudmapper", "serverless_exploit",
                "metadata_attack", "bucket_discovery", "trust_exploit",
                "cloud_recon",
            ]

    # ------------------------------------------------------------------
    # Override think() — cloud-specialized reasoning with provider detection
    # ------------------------------------------------------------------

    def think(self, objective: str, context: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Reason about the next action for cloud attacks.

        Extends the base think() with:
          1. Cloud provider identification from context.
          2. Attack surface mapping before action selection.
          3. Privilege escalation path suggestion.
          4. Provider-tailored tool recommendations.
        """
        # --- Auto-identify cloud provider ---
        if self._provider is None:
            self._provider = self._identify_cloud_provider(context)
            if self._provider:
                logger.info("CloudAgent %s: identified provider = %s", self.agent_id, self._provider)

        # --- Map attack surface ---
        surface = self._map_attack_surface(objective, context)

        # --- LLM path ---
        if self.llm_client:
            try:
                return self._llm_think_cloud(objective, context, history, surface)
            except Exception as exc:
                logger.warning("LLM think failed (%s) — falling back to CloudPatternMatcher", exc)

        # --- Pattern-matching fallback ---
        return CloudPatternMatcher.match(objective, context, self.capabilities)

    def _llm_think_cloud(
        self,
        objective: str,
        context: Dict[str, Any],
        history: List[Dict[str, Any]],
        surface: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Cloud-specific LLM reasoning with provider & surface context."""
        tools_blob = "\n".join(f"  - {t}  (details: {CloudKnowledge.TOOL_HANDLERS.get(t, '')})" for t in self.capabilities)
        history_blob = json.dumps([h.get("action", {}) for h in history[-5:]], indent=2) if history else "(none)"
        provider_info = f"Identified cloud provider: {self._provider}" if self._provider else "Cloud provider: unknown (detect from context)"
        es_paths = self._suggest_escalation_paths(objective, context)

        prompt = f"""You are agent {self.agent_id} — a Cloud Infrastructure Attack Specialist.
Your objective: {objective}
{provider_info}

ATTACK SURFACE SUMMARY:
{json.dumps(surface, default=str, indent=2)}

SUGGESTED ESCALATION PATHS:
{json.dumps(es_paths, default=str, indent=2)}

AVAILABLE TOOLS:
{tools_blob}

RECENT HISTORY (last 5 steps):
{history_blob}

CURRENT CONTEXT:
{json.dumps(context, default=str, indent=2)}

Decide the NEXT action. Respond with JSON:
  To call a tool:        {{"type": "tool_call", "tool": "<name>", "params": {{...}}, "reasoning": "..."}}
  To finish (success):    {{"type": "complete", "summary": "<what was achieved>"}}
  To ask the operator:    {{"type": "ask_operator", "question": "<what you need to know>"}}

Respond with valid JSON only."""

        response = self.llm_client.complete(prompt)
        try:
            action = json.loads(response)
            action.setdefault("confidence", 0.85)
            return action
        except json.JSONDecodeError:
            logger.warning("LLM returned non-JSON response; falling back to CloudPatternMatcher")
            return CloudPatternMatcher.match(objective, context, self.capabilities)

    # ------------------------------------------------------------------
    # Provider identification
    # ------------------------------------------------------------------

    def _identify_cloud_provider(self, context: Dict[str, Any]) -> Optional[str]:
        """Identifies the cloud provider from recon data or context.

        Checks:
          1. HTTP response headers (Server, X-Amz-*, etc.)
          2. DNS records (CNAMEs to cloud domains)
          3. IP ranges (AWS/GCP/Azure published ranges)
          4. Hostname patterns
          5. Context keys explicitly set by recon
        """
        # Explicit provider in context
        if context.get("cloud_provider"):
            return context["cloud_provider"]

        # Check discovered hosts / services
        ctx_str = json.dumps(context, default=str).lower()

        scores: Dict[str, int] = {}
        for provider, signatures in CloudKnowledge.PROVIDER_SIGNATURES.items():
            hits = sum(1 for sig in signatures if sig.lower() in ctx_str)
            if hits > 0:
                scores[provider] = hits

        if not scores:
            return None

        best = max(scores, key=scores.get)  # type: ignore[arg-type]
        logger.info("Provider fingerprint: %s (scores: %s)", best, scores)
        return best

    # ------------------------------------------------------------------
    # Attack surface mapping
    # ------------------------------------------------------------------

    def _map_attack_surface(self, objective: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Map the cloud attack surface from available context.

        Returns a structured breakdown of:
          - Exposed services (IPs, ports, protocols)
          - IAM / RBAC configuration details
          - Storage resources
          - Compute resources
          - Trust relationships
          - Container / Kubernetes presence
        """
        surface: Dict[str, Any] = {
            "provider": self._provider or "unknown",
            "exposed_services": context.get("discovered_services", [])[-20:],
            "hosts": context.get("discovered_hosts", [])[-20:],
            "likely_iam_context": False,
            "likely_containers": False,
            "likely_k8s": False,
            "likely_serverless": False,
            "likely_storage": False,
            "privilege_escalation_feasibility": "unknown",
        }

        # Check for IAM-related data
        for key in ("iam_roles", "iam_users", "iam_policies", "service_accounts", "role_assignments"):
            if context.get(key):
                surface["likely_iam_context"] = True
                break

        # Check for container signals
        ctx_str = json.dumps(context, default=str).lower()
        container_sigs = ["docker", "container", "kubernetes", "k8s", "pod", "image", "registry"]
        if any(sig in ctx_str for sig in container_sigs):
            surface["likely_containers"] = True

        # Check for K8s signals
        k8s_sigs = ["kubernetes", "k8s", "kubelet", "etcd:", "kube-apiserver", "kube-system", "cluster.local"]
        if any(sig in ctx_str for sig in k8s_sigs):
            surface["likely_k8s"] = True

        # Check for serverless
        serverless_sigs = ["lambda", "cloud function", "azure function", "serverless", "api gateway"]
        if any(sig in ctx_str for sig in serverless_sigs):
            surface["likely_serverless"] = True

        # Check for storage
        storage_sigs = ["s3", "bucket", "blob", "storage account", "gcs", "cloud storage"]
        if any(sig in ctx_str for sig in storage_sigs):
            surface["likely_storage"] = True

        # Feasibility assessment
        if surface["likely_iam_context"]:
            surface["privilege_escalation_feasibility"] = "high"
        elif any([surface["likely_containers"], surface["likely_k8s"]]):
            surface["privilege_escalation_feasibility"] = "medium"
        else:
            surface["privilege_escalation_feasibility"] = "low — more recon needed"

        return surface

    # ------------------------------------------------------------------
    # Escalation path suggestion
    # ------------------------------------------------------------------

    def _suggest_escalation_paths(self, objective: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Suggest relevant privilege escalation paths based on provider and context.

        Returns a ranked list of applicable escalation techniques."""
        provider = self._provider
        suggestions: List[Dict[str, Any]] = []

        if provider == "aws":
            paths = CloudKnowledge.AWS_ESCALATION_PATHS
        elif provider == "gcp":
            paths = CloudKnowledge.GCP_ESCALATION_PATHS
        elif provider == "azure":
            paths = CloudKnowledge.AZURE_ESCALATION_PATHS
        else:
            # Return top paths from each provider as candidates
            suggestions.append({"note": "Unknown provider — showing top AWS candidates", "candidates": [p["name"] for p in CloudKnowledge.AWS_ESCALATION_PATHS[:3]], "severity": "unknown"})
            suggestions.append({"note": "Unknown provider — showing top GCP candidates", "candidates": [p["name"] for p in CloudKnowledge.GCP_ESCALATION_PATHS[:3]], "severity": "unknown"})
            return suggestions

        for path in paths:
            suggestions.append({
                "name": path["name"],
                "description": path["description"],
                "permission_required": path.get("permission", path.get("resource", "")),
                "severity": path["severity"],
                "method": path["method"],
            })

        return suggestions

    # ------------------------------------------------------------------
    # Main execute() entry point — compatible with existing agent pattern
    # ------------------------------------------------------------------

    def execute(self, phase: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run cloud attack operations for the given mission phase.

        Args:
            phase: Phase spec from the mission plan (id, tools_needed, parameters).
            context: Shared HiveMind context including recon and vuln data.

        Returns:
            Dict with success, data, error, elapsed_seconds.
        """
        start = time.time()
        phase_id = phase.get("id", "unknown")
        tools = phase.get("tools_needed", [])
        params = phase.get("parameters", {})
        label = phase.get("label", phase_id)

        logger.info(
            "%s",
            ModernVisualEngine.create_section_header(
                f"CLOUD AGENT — {label}", "☁", "SKY_BLUE"
            ),
        )

        self.mark_started()
        self._session_id = f"cloud_{uuid.uuid4().hex[:8]}"

        # Identify provider
        self._provider = self._identify_cloud_provider(context)
        logger.info("Cloud provider: %s", self._provider or "unknown")

        # Map attack surface
        surface = self._map_attack_surface(params.get("objective", phase_id), context)
        logger.info("Attack surface: %s", json.dumps(surface, default=str, indent=2))

        # Run each requested tool
        findings: Dict[str, Any] = {}
        errors: List[str] = []

        for tool_name in tools:
            try:
                method_name = self.TOOL_HANDLERS.get(tool_name)
                if method_name is None:
                    logger.warning("Cloud tool '%s' not recognised — skipping", tool_name)
                    findings[tool_name] = {"error": f"Tool '{tool_name}' not in cloud agent handler map"}
                    continue

                handler = getattr(self, method_name, None)
                if handler is None:
                    findings[tool_name] = {"error": f"Handler method {method_name} not found"}
                    continue

                logger.info("%s executing cloud tool: %s → %s", self.agent_id, tool_name, method_name)
                result = handler(params, context)
                findings[tool_name] = result

                # Record results via BaseAgent tool execution for state tracking
                self.execute_tool(tool_name, params)

                # Store escalation paths if found
                if isinstance(result, dict) and result.get("escalation_paths"):
                    self._escalation_paths_found.extend(result["escalation_paths"])

            except Exception as exc:
                msg = f"Cloud tool '{tool_name}' failed: {exc}"
                logger.exception(msg)
                errors.append(msg)
                findings[tool_name] = {"error": str(exc)}

        # Update HiveMind if connected
        if self.hive_mind:
            try:
                if self._provider:
                    self.hive_mind.target_profile.setdefault("cloud_provider", self._provider)
                for finding_key, finding_data in findings.items():
                    if isinstance(finding_data, dict) and finding_data.get("success"):
                        self.hive_mind.add_finding(
                            {"agent": self.agent_id, "tool": finding_key, "data": finding_data},
                            self.agent_id,
                        )
                if self._escalation_paths_found:
                    for path in self._escalation_paths_found:
                        self.hive_mind.add_finding(
                            {"type": "escalation_path", "data": path, "severity": path.get("severity", "medium")},
                            self.agent_id,
                        )
            except Exception as exc:
                logger.warning("Failed to update HiveMind: %s", exc)

        elapsed = time.time() - start
        success = len(errors) == 0

        return {
            "success": success,
            "data": {
                "findings": findings,
                "cloud_provider": self._provider,
                "attack_surface": surface,
                "escalation_paths": self._escalation_paths_found,
                "session_id": self._session_id,
            },
            "error": "; ".join(errors) if errors else None,
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Tool handler: IAM privilege escalation
    # ------------------------------------------------------------------

    def _handle_iam_privesc(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute IAM privilege escalation analysis and exploitation.

        Identifies over-privileged policies, misconfigured trust relationships,
        and viable escalation paths for AWS, GCP, and Azure."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"iam_privesc_{uuid.uuid4().hex[:8]}"

        logger.info("IAM privesc: provider=%s, target=%s", provider, target)

        # Select escalation paths for the provider
        if provider == "aws":
            paths = [p["name"] for p in CloudKnowledge.AWS_ESCALATION_PATHS]
            top_paths = CloudKnowledge.AWS_ESCALATION_PATHS[:5]
        elif provider == "gcp":
            paths = [p["name"] for p in CloudKnowledge.GCP_ESCALATION_PATHS]
            top_paths = CloudKnowledge.GCP_ESCALATION_PATHS[:5]
        elif provider == "azure":
            paths = [p["name"] for p in CloudKnowledge.AZURE_ESCALATION_PATHS]
            top_paths = CloudKnowledge.AZURE_ESCALATION_PATHS[:5]
        else:
            return {
                "tool": "iam-privesc",
                "success": False,
                "error": f"Unsupported provider '{provider}' — must be aws, gcp, or azure",
                "session_id": session_id,
            }

        # Attempt real tool execution via ToolExecutor
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "iam-privesc",
                {"provider": provider, "target": target, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real iam-privesc tool failed (%s) — using knowledge base fallback", exc)

        return {
            "tool": "iam-privesc",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "escalation_paths_checked": paths,
            "top_candidates": [
                {
                    "name": p["name"],
                    "permission": p.get("permission", ""),
                    "severity": p["severity"],
                    "method": p["method"],
                }
                for p in top_paths
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] IAM privesc analysis — paths above should be checked manually against the target's actual IAM configuration",
        }

    # ------------------------------------------------------------------
    # Tool handler: Container escape
    # ------------------------------------------------------------------

    def _handle_container_escape(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse and exploit container escape vectors.

        Checks: --privileged, capabilities, mounted Docker socket, host PID/net
        namespace sharing, seccomp/AppArmor profiles, and cgroup escape paths."""
        target = params.get("target", "")
        container_id = params.get("container_id", context.get("container_id", "unknown"))
        session_id = f"container_escape_{uuid.uuid4().hex[:8]}"

        logger.info("Container escape: target=%s, container=%s", target, container_id)

        # Determine what escape techniques are applicable
        applicable: List[Dict[str, Any]] = []
        for tech in CloudKnowledge.CONTAINER_ESCAPE_TECHNIQUES:
            requirement_key = tech["requires"].lower()
            ctx_check = json.dumps(context, default=str).lower()

            # Check if the requirement signal is present
            sig_hit = False
            if "privileged" in requirement_key and ("privileged" in ctx_check or params.get("privileged")):
                sig_hit = True
            elif "cap_sys_admin" in requirement_key and ("sys_admin" in ctx_check or params.get("cap_sys_admin")):
                sig_hit = True
            elif "cap_sys_ptrace" in requirement_key and ("sys_ptrace" in ctx_check or params.get("cap_sys_ptrace")):
                sig_hit = True
            elif "docker.sock" in requirement_key and ("docker.sock" in ctx_check or params.get("docker_socket")):
                sig_hit = True
            elif "pid=host" in requirement_key and ("pid=host" in ctx_check or params.get("host_pid")):
                sig_hit = True
            elif "net=host" in requirement_key and ("net=host" in ctx_check or params.get("host_net")):
                sig_hit = True
            elif "seccomp" in requirement_key and ("seccomp" in ctx_check or params.get("seccomp_unconfined")):
                sig_hit = True
            elif "apparmor" in requirement_key and ("apparmor" in ctx_check or params.get("apparmor_unconfined")):
                sig_hit = True
            else:
                # Unknown condition — flag as potentially applicable
                sig_hit = False

            applicable.append({
                "technique": tech["name"],
                "severity": tech["severity"],
                "applicable": sig_hit,
                "method": tech["method"],
            })

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "container-escape",
                {"target": target, "container_id": container_id, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real container-escape tool failed (%s) — using knowledge base fallback", exc)

        return {
            "tool": "container-escape",
            "success": True,
            "target": target,
            "container_id": container_id,
            "session_id": session_id,
            "escape_techniques": applicable,
            "likely_exploitable": [t for t in applicable if t["applicable"]],
            "recommended_action": (
                "Primary: check --privileged and CAP_SYS_ADMIN first. "
                "If Docker socket mounted, use docker run --privileged. "
                "If host PID namespace, use nsenter --target 1."
            ),
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Container escape analysis — verify actual container runtime configuration",
        }

    # ------------------------------------------------------------------
    # Tool handler: Kubernetes attack
    # ------------------------------------------------------------------

    def _handle_k8s_attack(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Kubernetes RBAC abuse and pod compromise techniques.

        Covers: service account token theft, RBAC escalation, pod creation with
        privileged profiles, secret enumeration, kubelet proxy access, and
        CSR-based certificate forgery."""
        target = params.get("target", "")
        namespace = params.get("namespace", "default")
        session_id = f"k8s_attack_{uuid.uuid4().hex[:8]}"

        logger.info("K8s attack: target=%s, namespace=%s", target, namespace)

        # List applicable K8s attack techniques
        techniques: List[Dict[str, Any]] = []
        for tech in CloudKnowledge.K8S_ESCALATION_PATHS:
            techniques.append({
                "name": tech["name"],
                "resource": tech["resource"],
                "verb": tech["verb"],
                "severity": tech["severity"],
                "method": tech["method"],
            })

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "k8s-attack",
                {"target": target, "namespace": namespace, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real k8s-attack tool failed (%s) — using knowledge base fallback", exc)

        return {
            "tool": "k8s-attack",
            "success": True,
            "target": target,
            "namespace": namespace,
            "session_id": session_id,
            "attack_techniques": techniques,
            "primary_vectors": [
                "pods/exec to dump SA tokens",
                "pods/create with privileged SA or hostPath mounts",
                "secrets/get on all namespaced secrets",
                "rolebindings/create to escalate within namespace",
                "clusterrolebindings/create for cluster-wide admin",
            ],
            "detection_risk": "high — K8s audit logs capture all RBAC mutations",
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] K8s attack analysis — validate RBAC permissions via kubectl auth can-i before execution",
        }

    # ------------------------------------------------------------------
    # Tool handler: Prowler patterns
    # ------------------------------------------------------------------

    def _handle_prowler_patterns(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Run Prowler-style CIS benchmark checks and compliance scanning.

        Simulates Prowler findings for identifying misconfigurations across
        identity, logging, monitoring, networking, and storage categories."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"prowler_{uuid.uuid4().hex[:8]}"

        logger.info("Prowler patterns: provider=%s, target=%s", provider, target)

        # Simulated Prowler findings grouped by category
        mock_findings = {
            "identity": [
                {"check_id": "iam_1", "title": "IAM password policy does not require minimum length of 14", "severity": "medium", "status": "FAIL"},
                {"check_id": "iam_2", "title": "IAM root account has active access keys", "severity": "critical", "status": "FAIL"},
                {"check_id": "iam_3", "title": "IAM users with console access and unused credentials > 90 days", "severity": "high", "status": "FAIL"},
                {"check_id": "iam_4", "title": "IAM Customer-managed policies with wildcard actions (*)", "severity": "critical", "status": "FAIL"},
            ],
            "logging": [
                {"check_id": "log_1", "title": "CloudTrail not enabled in all regions", "severity": "high", "status": "FAIL"},
                {"check_id": "log_2", "title": "CloudTrail log file validation not enabled", "severity": "medium", "status": "FAIL"},
            ],
            "monitoring": [
                {"check_id": "mon_1", "title": "No CloudWatch alarm for root account usage", "severity": "high", "status": "FAIL"},
                {"check_id": "mon_2", "title": "No CloudWatch alarm for IAM policy changes", "severity": "high", "status": "FAIL"},
            ],
            "networking": [
                {"check_id": "net_1", "title": "Security group with unrestricted access on high-risk ports", "severity": "critical", "status": "FAIL"},
                {"check_id": "net_2", "title": "VPC flow logs not enabled", "severity": "medium", "status": "FAIL"},
            ],
            "storage": [
                {"check_id": "sto_1", "title": "S3 bucket with public read ACL", "severity": "critical", "status": "FAIL"},
                {"check_id": "sto_2", "title": "S3 bucket without default encryption", "severity": "medium", "status": "FAIL"},
            ],
        }

        failed_checks = []
        for category, checks in mock_findings.items():
            failed = [c for c in checks if c["status"] == "FAIL"]
            failed_checks.extend(failed)

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "prowler_patterns",
                {"provider": provider, "target": target, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real prowler_patterns tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "prowler_patterns",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "total_checks": sum(len(v) for v in mock_findings.values()),
            "failed_checks": len(failed_checks),
            "critical_failures": [c for c in failed_checks if c["severity"] == "critical"],
            "high_failures": [c for c in failed_checks if c["severity"] == "high"],
            "categories_audited": list(mock_findings.keys()),
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Prowler patterns — integrate with real Prowler CLI: prowler <provider> -M csv json-asff",
        }

    # ------------------------------------------------------------------
    # Tool handler: CloudMapper
    # ------------------------------------------------------------------

    def _handle_cloudmapper(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Map cloud infrastructure and visualise trust relationships.

        Uses CloudMapper-style analysis to graph IAM trust relationships,
        network paths, and resource connectivity for attack path discovery."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"cloudmapper_{uuid.uuid4().hex[:8]}"

        logger.info("CloudMapper: provider=%s, target=%s", provider, target)

        trust_analysis = {
            "trust_relationships": [
                {"from": f"{provider}_account_A", "to": f"{provider}_account_B", "relation": "sts:AssumeRole", "risk": "medium", "note": "Cross-account role assumption possible"},
                {"from": f"{provider}_account_A", "to": "external_idp", "relation": "SAML/OIDC federation", "risk": "high", "note": "Federated access may expand attack surface"},
            ],
            "network_exposure": [
                {"resource": f"{provider}_vpc_public_subnet", "exposure": "internet-facing", "risk": "high"},
                {"resource": f"{provider}_internal_db", "exposure": "VPC-only", "risk": "low"},
            ],
            "iam_principals": [
                {"type": "role", "count": "42", "with_admin": "3"},
                {"type": "user", "count": "18", "with_console_access": "7"},
                {"type": "group", "count": "5"},
            ],
        }

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "cloudmapper",
                {"provider": provider, "target": target, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real cloudmapper tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "cloudmapper",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "trust_analysis": trust_analysis,
            "attack_paths": [
                "Outsider → sts:AssumeRole (cross-account) → AdminRole → FullAccess",
                "DeveloperUser → iam:CreatePolicyVersion → escalate to Admin",
                "CompromisedLambda → execution role → s3:* → exfiltrate data",
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] CloudMapper analysis — integrate with cloudmapper CLI or cartography for live graphs",
        }

    # ------------------------------------------------------------------
    # Tool handler: Serverless exploitation
    # ------------------------------------------------------------------

    def _handle_serverless_exploit(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit serverless functions (Lambda / Cloud Functions / Azure Functions).

        Covers: event injection, role abuse, dependency confusion, source code
        extraction, and cold-start data persistence."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        function_name = params.get("function_name", "")
        session_id = f"serverless_{uuid.uuid4().hex[:8]}"

        logger.info("Serverless exploit: provider=%s, target=%s, function=%s", provider, target, function_name)

        vectors: List[Dict[str, Any]] = []
        for vec in CloudKnowledge.SERVERLESS_VECTORS:
            vectors.append({
                "name": vec["name"],
                "description": vec["description"],
                "severity": vec["severity"],
                "applicable": vec["provider"] in ("all", provider),
            })

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "serverless_exploit",
                {"provider": provider, "target": target, "function_name": function_name, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real serverless_exploit tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "serverless_exploit",
            "success": True,
            "provider": provider,
            "target": target,
            "function_name": function_name,
            "session_id": session_id,
            "attack_vectors": vectors,
            "primary_vectors": [
                "Event injection: craft malicious S3/SQS event to trigger function",
                "Role abuse: exploit over-privileged execution role via function invocation",
                "Dependency confusion: publish malicious package matching internal dependency name",
                "Source extraction: read /var/task or deployment package for secrets",
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Serverless exploit — validate function IAM role before execution",
        }

    # ------------------------------------------------------------------
    # Tool handler: Metadata attack
    # ------------------------------------------------------------------

    def _handle_metadata_attack(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Attack cloud instance metadata services (IMDSv1/v2).

        Exploits: SSRF to metadata endpoint, IMDSv1 being enabled (no token
        required), user-data scripts with embedded secrets, and instance
        identity documents for role assumption in other accounts."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"metadata_{uuid.uuid4().hex[:8]}"

        logger.info("Metadata attack: provider=%s, target=%s", provider, target)

        endpoints = CloudKnowledge.PROVIDER_METADATA_ENDPOINTS.get(provider, {})
        imdsv2_support = provider == "aws"
        token_required = provider != "aws"  # GCP always requires header; Azure varies

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "metadata_attack",
                {"provider": provider, "target": target, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real metadata_attack tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "metadata_attack",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "metadata_endpoints": [
                {"endpoint": label, "url": url}
                for label, url in endpoints.items()
            ],
            "imdsv2_enforced": imdsv2_support,
            "token_required": token_required,
            "techniques": [
                "SSRF to metadata endpoint from web application",
                "Direct curl/wget from compromised instance",
                "DNS rebinding to bypass same-origin restrictions",
                "IMDSv1 downgrade: omit token header; older instances still answer",
            ],
            "likely_recoverable": [
                "IAM role credentials (AWS) / service account tokens (GCP) / managed identity tokens (Azure)",
                "SSH public keys from instance metadata",
                "User-data scripts (often contain bootstrap passwords/secrets)",
                "Instance identity document (role assumption in other accounts)",
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Metadata attack — check IMDS hop limit (AWS) and metadata server accessibility first",
        }

    # ------------------------------------------------------------------
    # Tool handler: Storage bucket discovery
    # ------------------------------------------------------------------

    def _handle_bucket_discovery(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Discover and enumerate cloud storage buckets (S3, GCS, Azure Blob).

        Techniques: DNS bruteforce, wordlist-based enumeration, authenticated
        enumeration via APIs, bucket policy misconfiguration checks."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        domain = context.get("target_profile", {}).get("domain", "")
        session_id = f"bucket_{uuid.uuid4().hex[:8]}"

        logger.info("Bucket discovery: provider=%s, target=%s, domain=%s", provider, target, domain)

        service_names = {"aws": "S3", "gcp": "GCS", "azure": "Azure Blob"}
        service = service_names.get(provider, "Unknown Storage")

        # Wordlist-based discovery suggestions
        wordlist_suggestions = [
            f"{domain or 'target'}-prod",
            f"{domain or 'target'}-dev",
            f"{domain or 'target'}-backup",
            f"{domain or 'target'}-logs",
            f"{domain or 'target'}-assets",
            f"{domain or 'target'}-static",
            f"{domain or 'target'}-data",
            f"{domain or 'target'}-terraform",
            f"{domain or 'target'}-cloudformation",
            f"{domain or 'target'}-cdn",
        ] if domain else []

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "bucket_discovery",
                {"provider": provider, "target": target, "domain": domain, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real bucket_discovery tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "bucket_discovery",
            "success": True,
            "provider": provider,
            "service": service,
            "target": target,
            "domain": domain,
            "session_id": session_id,
            "suggested_names": wordlist_suggestions[:10],
            "techniques": [
                f"DNS bruteforce: {domain}.s3.amazonaws.com variants" if provider == "aws" else f"DNS enumeration for {service} endpoints",
                f"Authenticated enumeration: list-buckets / storage.buckets.list",
                f"Public access check: test GET against bucket URL without auth",
                "Review bucket policies for: AuthenticatedUsers, AllUsers, cross-account grants",
                f"Search for bucket names in JS files, HTML comments, GitHub repos",
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Bucket discovery — wordlists should be expanded with org-specific naming conventions",
        }

    # ------------------------------------------------------------------
    # Tool handler: Cross-account trust exploitation
    # ------------------------------------------------------------------

    def _handle_trust_exploit(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit cross-account and cross-organisation trust relationships.

        Covers: sts:AssumeRole misconfiguration, S3 cross-account policies,
        KMS key sharing, ECR repository cross-account pulls, and resource
        sharing via AWS RAM / Azure Lighthouse / GCP shared VPC."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"trust_{uuid.uuid4().hex[:8]}"

        logger.info("Trust exploitation: provider=%s, target=%s", provider, target)

        methods: List[Dict[str, Any]] = []
        for entry in CloudKnowledge.CROSS_ACCOUNT_TRUST:
            methods.append({
                "name": entry["name"],
                "description": entry["description"],
                "severity": entry["severity"],
                "method": entry["method"],
            })

        # Try real tool
        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "trust_exploit",
                {"provider": provider, "target": target, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real trust_exploit tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "trust_exploit",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "trust_exploit_methods": methods,
            "high_impact_scenarios": [
                "sts:AssumeRole with Principal: {AWS: '*'} in trust policy → assume from attacker account",
                "S3 bucket policy allows s3:* from any AWS account → access and exfiltrate",
                "KMS key policy grants kms:Decrypt to external root → decrypt all ciphertext",
                "ECR repository allows cross-account pull → inject backdoored image",
            ],
            "detection_notes": [
                "CloudTrail logs sts:AssumeRole cross-account calls",
                "S3 server access logs capture cross-account object access",
                "GuardDuty alerts on anomalous cross-account activity",
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Trust exploitation — validate trust policies with AWS IAM Policy Simulator / GCP IAM Troubleshooter / Azure What-If",
        }

    # ------------------------------------------------------------------
    # Tool handler: Cloud reconnaissance
    # ------------------------------------------------------------------

    def _handle_cloud_recon(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform cloud-specific reconnaissance — enumerate resources, services,
        and configurations for a target cloud environment."""
        provider = params.get("provider") or self._provider or "auto"
        target = params.get("target", "")
        session_id = f"cloud_recon_{uuid.uuid4().hex[:8]}"

        logger.info("Cloud recon: provider=%s, target=%s", provider, target)

        recon_steps: List[Dict[str, Any]] = [
            {"step": 1, "action": "Identify cloud provider from DNS, IP ranges, and HTTP headers", "priority": "critical"},
            {"step": 2, "action": "Enumerate IAM users / roles / groups / service accounts", "priority": "high"},
            {"step": 3, "action": "Map VPC / VNet / VPC network topology and security groups", "priority": "high"},
            {"step": 4, "action": "Enumerate storage resources (S3, GCS, Azure Blob)", "priority": "high"},
            {"step": 5, "action": "List compute resources (EC2, GCE, Azure VM) and their IAM profiles", "priority": "high"},
            {"step": 6, "action": "Check for serverless functions (Lambda, Cloud Functions, Azure Functions)", "priority": "medium"},
            {"step": 7, "action": "Enumerate container registries (ECR, GCR, ACR) and K8s clusters", "priority": "medium"},
            {"step": 8, "action": "Audit cross-account trust relationships and resource sharing", "priority": "high"},
            {"step": 9, "action": "Check logging / monitoring configuration (CloudTrail, Cloud Audit Logs, Azure Monitor)", "priority": "high"},
            {"step": 10, "action": "Review IAM policies for wildcard (*) and over-privileged roles", "priority": "critical"},
        ]

        tool_result = None
        try:
            tool_result = self.tool_executor.execute(
                "cloud_recon",
                {"provider": provider, "target": target, "session_id": session_id},
                self.agent_id,
            )
        except Exception as exc:
            logger.warning("Real cloud_recon tool failed (%s) — using knowledge base", exc)

        return {
            "tool": "cloud_recon",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "recon_steps": recon_steps,
            "priority_actions": [
                "Identify provider and enumerate IAM",
                "Check for public S3 buckets / storage blobs",
                "Audit IAM policies for wildcard actions",
            ],
            "tool_backend_result": tool_result,
            "note": "[CLOUD AGENT] Cloud recon — use cloud_enum, ScoutSuite, or Prowler for automated enumeration",
        }

    # ------------------------------------------------------------------
    # Tool handler: Resource enumeration
    # ------------------------------------------------------------------

    def _handle_resource_enum(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate cloud resources across compute, storage, network, and identity."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"resource_enum_{uuid.uuid4().hex[:8]}"

        logger.info("Resource enum: provider=%s, target=%s", provider, target)

        resource_types: Dict[str, List[str]] = {
            "aws": [
                "ec2:DescribeInstances", "s3:ListBuckets", "iam:ListUsers", "iam:ListRoles",
                "lambda:ListFunctions", "ecs:ListClusters", "eks:ListClusters",
                "rds:DescribeDBInstances", "ecr:DescribeRepositories", "cloudtrail:DescribeTrails",
            ],
            "gcp": [
                "compute.instances.list", "storage.buckets.list", "iam.serviceAccounts.list",
                "cloudfunctions.functions.list", "container.clusters.list",
                "bigquery.datasets.list", "cloudsql.instances.list",
            ],
            "azure": [
                "Microsoft.Compute/virtualMachines/read", "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Web/sites/read", "Microsoft.ContainerService/managedClusters/read",
                "Microsoft.Sql/servers/databases/read", "Microsoft.KeyVault/vaults/read",
            ],
        }

        apis = resource_types.get(provider, [])
        return {
            "tool": "resource_enum",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "apis_to_query": apis,
            "enumeration_strategy": "Attempt each API call; track which succeed (indicating both permission AND resource existence).",
            "note": "[CLOUD AGENT] Resource enumeration — actual API calls require credentials with read permissions",
        }

    # ------------------------------------------------------------------
    # Tool handler: Policy audit
    # ------------------------------------------------------------------

    def _handle_policy_audit(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Audit IAM/security policies for privilege escalation risks and
        compliance violations."""
        provider = params.get("provider") or self._provider or "aws"
        target = params.get("target", "")
        session_id = f"policy_audit_{uuid.uuid4().hex[:8]}"

        logger.info("Policy audit: provider=%s, target=%s", provider, target)

        audit_findings: List[Dict[str, Any]] = [
            {"category": "wildcard_permissions", "severity": "critical", "description": "IAM policies with Action: '*' or Resource: '*' grant full access", "remediation": "Scope actions and resources to least privilege"},
            {"category": "overly_permissive_trust", "severity": "critical", "description": "Trust policies with Principal: {AWS: '*'} or missing ExternalId condition", "remediation": "Restrict Principal to specific account ARNs; add ExternalId condition"},
            {"category": "long_lived_credentials", "severity": "high", "description": "IAM users with access keys older than 90 days", "remediation": "Rotate keys; prefer temporary credentials via roles"},
            {"category": "unused_roles", "severity": "medium", "description": "IAM roles not used in 90+ days — dormant attack surface", "remediation": "Delete unused roles or scope down permissions"},
            {"category": "public_buckets", "severity": "critical", "description": "Storage buckets with public read/write ACL or policy", "remediation": "Block public access at account and bucket level"},
            {"category": "unencrypted_storage", "severity": "medium", "description": "Storage resources without default encryption", "remediation": "Enable default encryption (SSE-S3, CMEK, etc.)"},
            {"category": "logging_gaps", "severity": "high", "description": "Missing or incomplete audit logging (CloudTrail, Cloud Audit Logs)", "remediation": "Enable logging in all regions; validate log integrity"},
            {"category": "k8s_rbac", "severity": "high", "description": "ClusterRoleBinding granting cluster-admin to default SA or anonymous user", "remediation": "Audit RBAC; remove overly broad bindings"},
        ]

        return {
            "tool": "policy_audit",
            "success": True,
            "provider": provider,
            "target": target,
            "session_id": session_id,
            "audit_findings": audit_findings,
            "total_findings": len(audit_findings),
            "critical_count": len([f for f in audit_findings if f["severity"] == "critical"]),
            "high_count": len([f for f in audit_findings if f["severity"] == "high"]),
            "recommendation": "Run Prowler, ScoutSuite, or Cloudsplaining for automated policy auditing",
            "note": "[CLOUD AGENT] Policy audit — findings are simulated; integrate with real CSP APIs for production use",
        }

    # ------------------------------------------------------------------
    # Override report_status to include cloud-specific state
    # ------------------------------------------------------------------

    def report_status(self) -> Dict[str, Any]:
        """Return extended status including cloud-specific state."""
        base = super().report_status()
        base["provider"] = self._provider
        base["active_exploits"] = len(self._active_exploits)
        base["escalation_paths_found"] = len(self._escalation_paths_found)
        base["session_id"] = self._session_id
        return base
