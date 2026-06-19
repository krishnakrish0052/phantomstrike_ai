from collections import defaultdict
from pathlib import Path

from config import _config
from tool_registry import TOOLS


def test_tool_registry_endpoints_are_unique():
    endpoint_to_tools = defaultdict(list)
    for tool_name, metadata in TOOLS.items():
        endpoint = metadata.get("endpoint")
        if endpoint:
            endpoint_to_tools[endpoint].append(tool_name)

    duplicates = {
        endpoint: names
        for endpoint, names in endpoint_to_tools.items()
        if len(names) > 1
    }

    assert duplicates == {}


def test_runtime_version_matches_v33_docs():
    assert _config["VERSION"] == "3.3.0"


def test_env_example_documents_core_runtime_variables():
    env_example = Path(".env.example")

    assert env_example.exists()
    text = env_example.read_text()
    for key in (
        "PHANTOMSTRIKE_HOST=",
        "PHANTOMSTRIKE_PORT=",
        "PHANTOMSTRIKE_API_TOKEN=",
        "PHANTOMSTRIKE_LLM_PROVIDER=",
        "PHANTOMSTRIKE_LLM_NUM_CTX_ANALYZE=",
        "AWS_REGION=",
        "CF_API_TOKEN=",
        "P2P_IFACE=",
    ):
        assert key in text


def test_registry_alias_routes_are_registered():
    from phantomstrike_server import app

    routes = {rule.rule for rule in app.url_map.iter_rules()}

    for route in (
        "/api/tool/active_directory/impacket/ad-enum",
        "/api/tool/active_directory/impacket/remote-exec",
        "/api/tools/hashcat-utils",
        "/api/tools/volatility3",
    ):
        assert route in routes
