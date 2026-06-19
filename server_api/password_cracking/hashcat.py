from flask import Blueprint, request, jsonify
import logging
import os
import tempfile
from server_core.command_executor import execute_command
from server_core.singletons import ROCKYOU_PATH

import shlex

logger = logging.getLogger(__name__)

api_password_cracking_hashcat_bp = Blueprint("api_password_cracking_hashcat", __name__)

HASHCAT_UTILS = {
    "cap2hccapx",
    "combinator",
    "len",
    "req-exclude",
    "req-include",
}


def _append_shell_args(command: str, additional_args: str) -> str:
    if not additional_args:
        return command
    return f"{command} {' '.join(shlex.quote(part) for part in shlex.split(additional_args))}"


@api_password_cracking_hashcat_bp.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute Hashcat for password cracking with enhanced logging"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        hash_value = params.get("hash", "")
        hash_type = params.get("hash_type", "")
        attack_mode = params.get("attack_mode", "0")
        wordlist = params.get("wordlist", ROCKYOU_PATH)
        mask = params.get("mask", "")
        additional_args = params.get("additional_args", "")

        if not hash_file and not hash_value:
            logger.warning("Hashcat called without hash_file or hash parameter")
            return jsonify({
                "error": "Either hash_file or hash parameter is required"
            }), 400

        if not hash_type:
            logger.warning("Hashcat called without hash_type parameter")
            return jsonify({
                "error": "Hash type parameter is required"
            }), 400

        tmp_file = None
        try:
            # hash_file takes priority; fall back to writing inline hash to a temp file
            if hash_file:
                target = hash_file
            else:
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                tmp.write(hash_value.strip() + "\n")
                tmp.close()
                tmp_file = tmp.name
                target = tmp_file
                logger.info("Wrote inline hash to temp file for hashcat")

            command = f"hashcat -m {shlex.quote(hash_type)} -a {shlex.quote(attack_mode)} {shlex.quote(target)}"

            if attack_mode == "0" and wordlist:
                command += f" {shlex.quote(wordlist)}"
            elif attack_mode == "3" and mask:
                command += f" {shlex.quote(mask)}"

            if additional_args:
                command += f" {shlex.quote(additional_args)}"

            logger.info(f"Starting Hashcat attack: mode {attack_mode}")
            result = execute_command(command, tool="hashcat")
            logger.info("Hashcat attack completed")
            return jsonify(result)
        finally:
            if tmp_file and os.path.exists(tmp_file):
                os.unlink(tmp_file)
    except Exception as e:
        logger.error(f"💥 Error in hashcat endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@api_password_cracking_hashcat_bp.route("/api/tools/hashcat-utils", methods=["POST"])
def hashcat_utils():
    """Execute standalone hashcat utility binaries."""
    try:
        params = request.json or {}
        utility = str(params.get("utility", "cap2hccapx")).strip()
        input_file = params.get("input_file") or params.get("hash_file") or ""
        output_file = params.get("output_file", "")
        left_file = params.get("left_file") or input_file
        right_file = params.get("right_file", "")
        additional_args = params.get("additional_args", "")

        if utility not in HASHCAT_UTILS:
            return jsonify({
                "error": "Unsupported hashcat utility",
                "supported_utilities": sorted(HASHCAT_UTILS),
            }), 400

        if utility == "combinator":
            if not left_file or not right_file:
                return jsonify({
                    "error": "left_file and right_file are required for combinator"
                }), 400
            command = f"{shlex.quote(utility)} {shlex.quote(left_file)} {shlex.quote(right_file)}"
            if output_file:
                command += f" > {shlex.quote(output_file)}"
        else:
            if not input_file:
                return jsonify({
                    "error": "input_file parameter is required"
                }), 400
            command = f"{shlex.quote(utility)} {shlex.quote(input_file)}"
            if output_file:
                command += f" {shlex.quote(output_file)}"

        command = _append_shell_args(command, additional_args)
        result = execute_command(
            command,
            tool="hashcat-utils",
            endpoint="/api/tools/hashcat-utils",
            params=params,
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": f"Invalid additional_args: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Error in hashcat-utils endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
