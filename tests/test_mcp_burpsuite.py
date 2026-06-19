import asyncio
from unittest.mock import MagicMock


class _Colors:
    BLOOD_RED = ""
    SUCCESS = ""
    ERROR = ""
    HIGHLIGHT_BLUE = ""
    CRITICAL = ""
    FIRE_RED = ""
    CYBER_ORANGE = ""
    YELLOW = ""
    INFO = ""
    WHITE = ""
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


def _register_burp():
    from mcp_tools.web_scan.burpsuite import register_burpsuite_tool

    mcp, registered = _make_mcp()
    api_client = MagicMock()
    api_client.safe_post.return_value = {"success": True}
    register_burpsuite_tool(mcp, api_client, MagicMock(), _Colors)
    return registered, api_client


def test_burpsuite_scan_uses_existing_alternative_endpoint():
    registered, api_client = _register_burp()

    _run(
        registered["burpsuite_scan"](
            target="https://example.test",
            scan_type="active",
            headless=True,
            project_file="old.burp",
        )
    )

    endpoint, payload = api_client.safe_post.call_args[0]
    assert endpoint == "api/tools/burpsuite-alternative"
    assert payload["target"] == "https://example.test"
    assert payload["scan_type"] == "active"
    assert payload["headless"] is True
    assert payload["max_depth"] == 3
    assert payload["max_pages"] == 50
    assert payload["project_file"] == "old.burp"


def test_burpsuite_scan_falls_back_to_scan_config_then_comprehensive():
    registered, api_client = _register_burp()

    _run(registered["burpsuite_scan"](target="https://example.test", scan_config="spider"))
    _, payload = api_client.safe_post.call_args[0]
    assert payload["scan_type"] == "spider"

    _run(registered["burpsuite_scan"](target="https://example.test"))
    _, payload = api_client.safe_post.call_args[0]
    assert payload["scan_type"] == "comprehensive"


def test_burpsuite_alternative_scan_keeps_alternative_endpoint():
    registered, api_client = _register_burp()

    _run(
        registered["burpsuite_alternative_scan"](
            target="https://example.test",
            scan_type="spider",
            max_depth=2,
            max_pages=5,
        )
    )

    endpoint, payload = api_client.safe_post.call_args[0]
    assert endpoint == "api/tools/burpsuite-alternative"
    assert payload["scan_type"] == "spider"
    assert payload["max_depth"] == 2
    assert payload["max_pages"] == 5
