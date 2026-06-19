from pathlib import Path
import logging
import shlex
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, request

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_registry_backfill_bp = Blueprint("api_registry_backfill", __name__)


def _params() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _required(params: Dict[str, Any], *names: str) -> Tuple[Any, str]:
    for name in names:
        value = params.get(name)
        if value not in (None, "", []):
            return value, ""
    return "", f"{' or '.join(names)} parameter is required"


def _extend_args(argv: List[str], additional_args: str) -> Tuple[bool, str]:
    if not additional_args:
        return True, ""
    try:
        argv.extend(shlex.split(str(additional_args)))
        return True, ""
    except ValueError as exc:
        return False, f"Invalid additional_args: {exc}"


def _run_tool(tool_name: str, argv: List[str], params: Dict[str, Any], use_cache: bool = False):
    command = shlex.join([str(part) for part in argv if str(part) != ""])
    logger.info("Starting %s: %s", tool_name, command)
    result = execute_command(
        command,
        use_cache=use_cache,
        tool=tool_name,
        endpoint=request.path,
        params=params,
    )
    return jsonify(result)


def _bad(message: str, status: int = 400):
    return jsonify({"success": False, "error": message}), status


@api_registry_backfill_bp.route("/api/tools/file_type", methods=["POST"])
def file_type():
    params = _params()
    file_path, error = _required(params, "file_path", "file")
    if error:
        return _bad(error)
    argv = ["file"]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(file_path))
    return _run_tool("file", argv, params, use_cache=True)


@api_registry_backfill_bp.route("/api/tools/bulk_extractor", methods=["POST"])
def bulk_extractor():
    params = _params()
    input_file, error = _required(params, "input_file", "file_path")
    if error:
        return _bad(error)
    output_dir = str(params.get("output_dir") or "/tmp/bulk_extractor_output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    argv = ["bulk_extractor", "-o", output_dir]
    scanners = params.get("scanners", "")
    if scanners:
        for scanner in str(scanners).split(","):
            scanner = scanner.strip()
            if scanner:
                argv.extend(["-e", scanner])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(input_file))
    return _run_tool("bulk_extractor", argv, params)


@api_registry_backfill_bp.route("/api/tools/photorec", methods=["POST"])
def photorec():
    params = _params()
    input_file, error = _required(params, "input_file", "disk", "image_path")
    if error:
        return _bad(error)
    output_dir = str(params.get("output_dir") or "/tmp/photorec_output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    argv = ["photorec", "/log", "/d", output_dir]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(input_file))
    return _run_tool("photorec", argv, params)


@api_registry_backfill_bp.route("/api/tools/testdisk", methods=["POST"])
def testdisk():
    params = _params()
    disk, error = _required(params, "disk", "image_path", "input_file")
    if error:
        return _bad(error)
    argv = ["testdisk", "/log"]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(disk))
    return _run_tool("testdisk", argv, params)


@api_registry_backfill_bp.route("/api/tools/scalpel", methods=["POST"])
def scalpel():
    params = _params()
    input_file, error = _required(params, "input_file", "file_path")
    if error:
        return _bad(error)
    output_dir = str(params.get("output_dir") or "/tmp/scalpel_output")
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    argv = ["scalpel", "-o", output_dir]
    config = params.get("config", "")
    if config:
        argv.extend(["-c", str(config)])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(input_file))
    return _run_tool("scalpel", argv, params)


@api_registry_backfill_bp.route("/api/tools/stegsolve", methods=["POST"])
def stegsolve():
    params = _params()
    file_path, error = _required(params, "file_path", "cover_file")
    if error:
        return _bad(error)
    argv = ["stegsolve", str(file_path)]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("stegsolve", argv, params)


@api_registry_backfill_bp.route("/api/tools/zsteg", methods=["POST"])
def zsteg():
    params = _params()
    file_path, error = _required(params, "file_path", "cover_file")
    if error:
        return _bad(error)
    argv = ["zsteg"]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(file_path))
    return _run_tool("zsteg", argv, params)


@api_registry_backfill_bp.route("/api/tools/outguess", methods=["POST"])
def outguess():
    params = _params()
    file_path, error = _required(params, "file_path", "cover_file")
    if error:
        return _bad(error)
    action = str(params.get("action") or "extract").lower()
    passphrase = params.get("passphrase", "")
    output_file = str(params.get("output_file") or "/tmp/outguess_output")
    argv = ["outguess"]
    if passphrase:
        argv.extend(["-k", str(passphrase)])
    if action == "extract":
        argv.extend(["-r", str(file_path), output_file])
    elif action == "info":
        argv.extend(["-t", str(file_path)])
    else:
        return _bad("Invalid action. Use: extract or info")
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("outguess", argv, params)


@api_registry_backfill_bp.route("/api/tools/sleuthkit", methods=["POST"])
def sleuthkit():
    params = _params()
    image_path, error = _required(params, "image_path", "input_file")
    if error:
        return _bad(error)
    command = str(params.get("command") or "fls").strip()
    allowed = {"fls", "icat", "mmls", "fsstat", "ils", "istat", "tsk_recover"}
    if command not in allowed:
        return _bad(f"Unsupported sleuthkit command. Use one of: {', '.join(sorted(allowed))}")
    argv = [command]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    argv.append(str(image_path))
    return _run_tool("sleuthkit", argv, params)


@api_registry_backfill_bp.route("/api/tools/wireshark", methods=["POST"])
def wireshark():
    params = _params()
    interface, error = _required(params, "interface")
    if error:
        return _bad(error)
    argv = ["wireshark", "-i", str(interface)]
    duration = int(params.get("duration") or 0)
    if duration > 0:
        argv.extend(["-a", f"duration:{duration}"])
    output_file = params.get("output_file", "")
    if output_file:
        argv.extend(["-w", str(output_file)])
    if params.get("capture_filter"):
        argv.extend(["-f", str(params["capture_filter"])])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("wireshark", argv, params)


@api_registry_backfill_bp.route("/api/tools/tshark", methods=["POST"])
def tshark():
    params = _params()
    interface, error = _required(params, "interface")
    if error:
        return _bad(error)
    argv = ["tshark", "-i", str(interface)]
    duration = int(params.get("duration") or 0)
    if duration > 0:
        argv.extend(["-a", f"duration:{duration}"])
    output_file = params.get("output_file", "")
    if output_file:
        argv.extend(["-w", str(output_file)])
    if params.get("capture_filter"):
        argv.extend(["-f", str(params["capture_filter"])])
    if params.get("display_filter"):
        argv.extend(["-Y", str(params["display_filter"])])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("tshark", argv, params)


@api_registry_backfill_bp.route("/api/tools/tcpdump", methods=["POST"])
def tcpdump():
    params = _params()
    interface, error = _required(params, "interface")
    if error:
        return _bad(error)
    argv = ["tcpdump", "-i", str(interface)]
    count = int(params.get("count") or 0)
    if count > 0:
        argv.extend(["-c", str(count)])
    output_file = params.get("output_file", "")
    if output_file:
        argv.extend(["-w", str(output_file)])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    if params.get("filter"):
        ok, filter_error = _extend_args(argv, str(params["filter"]))
        if not ok:
            return _bad(f"Invalid filter: {filter_error}")
    return _run_tool("tcpdump", argv, params)


@api_registry_backfill_bp.route("/api/tools/kismet", methods=["POST"])
def kismet():
    params = _params()
    interface, error = _required(params, "interface")
    if error:
        return _bad(error)
    argv = ["kismet", "-c", str(interface)]
    log_prefix = params.get("log_prefix", "")
    if log_prefix:
        argv.extend(["--log-prefix", str(log_prefix)])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    duration = int(params.get("duration") or 0)
    if duration > 0:
        argv = ["timeout", f"{duration}s", *argv]
    return _run_tool("kismet", argv, params)


@api_registry_backfill_bp.route("/api/tools/maltego", methods=["POST"])
def maltego():
    params = _params()
    argv = ["maltego"]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("maltego", argv, params)


@api_registry_backfill_bp.route("/api/tools/recon_ng", methods=["POST"])
def recon_ng():
    params = _params()
    domain, error = _required(params, "domain", "target")
    if error:
        return _bad(error)
    module = str(params.get("modules") or "recon/domains-hosts/hackertarget").split(",")[0].strip()
    workspace = str(params.get("workspace") or "phantomstrike")
    recon_cmd = (
        f"workspaces create {workspace}; "
        f"modules load {module}; "
        f"options set SOURCE {domain}; "
        "run; exit"
    )
    argv = ["recon-ng", "--no-version", "--no-analytics", "-x", recon_cmd]
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("recon-ng", argv, params)


@api_registry_backfill_bp.route("/api/tools/evil_winrm", methods=["POST"])
def evil_winrm():
    params = _params()
    target, error = _required(params, "target", "host")
    if error:
        return _bad(error)
    username, error = _required(params, "username", "user")
    if error:
        return _bad(error)
    argv = ["evil-winrm", "-i", str(target), "-u", str(username)]
    if params.get("password"):
        argv.extend(["-p", str(params["password"])])
    if params.get("hash"):
        argv.extend(["-H", str(params["hash"])])
    ok, error = _extend_args(argv, params.get("additional_args", ""))
    if not ok:
        return _bad(error)
    return _run_tool("evil-winrm", argv, params)
