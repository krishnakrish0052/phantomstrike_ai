import asyncio
from unittest.mock import MagicMock


class _Colors:
    FIRE_RED = ""
    SUCCESS = ""
    ERROR = ""
    CRITICAL = ""
    HIGHLIGHT_YELLOW = ""
    RESET = ""


def _run(coro):
    return asyncio.run(coro)


def _make_mcp():
    registered = {}

    class FakeMCP:
        def tool(self):
            def decorator(fn):
                registered[fn.__name__] = fn
                return fn
            return decorator

    return FakeMCP(), registered


def _register_impacket():
    from mcp_tools.active_directory.impacket_scripts import register_impacket

    mcp, registered = _make_mcp()
    api_client = MagicMock()
    api_client.safe_post.return_value = {"success": True}
    register_impacket(mcp, api_client, MagicMock(), _Colors)
    return registered, api_client


def test_impacket_registers_expected_tools():
    registered, _ = _register_impacket()

    assert {
        "impacket_run",
        "impacket_get_spec",
        "impacket_ad_enum",
        "impacket_remote_exec",
    }.issubset(registered)


def test_impacket_run_posts_to_active_directory_endpoint():
    registered, api_client = _register_impacket()

    _run(
        registered["impacket_run"](
            script="GetADUsers",
            target="corp.local/user:pass",
            options={"dc-ip": "10.0.0.10"},
        )
    )

    endpoint, payload = api_client.safe_post.call_args[0]
    assert endpoint == "api/tool/active_directory/impacket"
    assert payload["script"] == "GetADUsers"
    assert payload["target"] == "corp.local/user:pass"
    assert payload["options"]["dc-ip"] == "10.0.0.10"


def test_impacket_get_spec_posts_to_spec_endpoint():
    registered, api_client = _register_impacket()

    _run(registered["impacket_get_spec"]("psexec"))

    api_client.safe_post.assert_called_once_with(
        "api/tool/active_directory/impacket/spec", {"script": "psexec"}
    )


def test_impacket_ad_enum_posts_generated_options():
    registered, api_client = _register_impacket()

    _run(
        registered["impacket_ad_enum"](
            script="GetNPUsers",
            target="corp.local/",
            dc_ip="10.0.0.10",
            hashes="aad3:8846",
            kerberos=True,
            no_pass=True,
            debug=True,
        )
    )

    endpoint, payload = api_client.safe_post.call_args[0]
    assert endpoint == "api/tool/active_directory/impacket/ad-enum"
    assert payload["script"] == "GetNPUsers"
    assert payload["options"]["dc-ip"] == "10.0.0.10"
    assert payload["options"]["hashes"] == "aad3:8846"
    assert payload["options"]["k"] is True
    assert payload["options"]["no-pass"] is True
    assert payload["options"]["debug"] is True


def test_impacket_remote_exec_posts_generated_options():
    registered, api_client = _register_impacket()

    _run(
        registered["impacket_remote_exec"](
            script="psexec",
            target="corp.local/user:pass@10.0.0.20",
            command="whoami",
            share="ADMIN$",
            shell_type="cmd",
        )
    )

    endpoint, payload = api_client.safe_post.call_args[0]
    assert endpoint == "api/tool/active_directory/impacket/remote-exec"
    assert payload["script"] == "psexec"
    assert payload["options"]["command"] == "whoami"
    assert payload["options"]["share"] == "ADMIN$"
    assert payload["options"]["shell-type"] == "cmd"
