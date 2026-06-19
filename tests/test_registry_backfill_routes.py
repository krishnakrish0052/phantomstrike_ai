from unittest.mock import patch

import pytest

from phantomstrike_server import app


BACKFILL_PATHS = [
    "/api/tools/bulk_extractor",
    "/api/tools/evil_winrm",
    "/api/tools/file_type",
    "/api/tools/kismet",
    "/api/tools/maltego",
    "/api/tools/outguess",
    "/api/tools/photorec",
    "/api/tools/recon_ng",
    "/api/tools/scalpel",
    "/api/tools/sleuthkit",
    "/api/tools/stegsolve",
    "/api/tools/tcpdump",
    "/api/tools/testdisk",
    "/api/tools/tshark",
    "/api/tools/wireshark",
    "/api/tools/zsteg",
]


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_registry_backfill_routes_are_registered(client):
    for path in BACKFILL_PATHS:
        response = client.post(path, json={})
        assert response.status_code != 404, path


def test_file_type_backfill_builds_quoted_command(client):
    with patch(
        "server_api.registry_backfill.execute_command",
        return_value={"success": True, "stdout": "mocked"},
    ) as mock_execute:
        response = client.post(
            "/api/tools/file_type",
            json={"file_path": "/tmp/a file.bin", "additional_args": "--mime"},
        )

    assert response.status_code == 200
    command = mock_execute.call_args[0][0]
    assert command == "file --mime '/tmp/a file.bin'"
    assert mock_execute.call_args.kwargs["tool"] == "file"


def test_evil_winrm_backfill_uses_registry_endpoint(client):
    with patch(
        "server_api.registry_backfill.execute_command",
        return_value={"success": True, "stdout": "mocked"},
    ) as mock_execute:
        response = client.post(
            "/api/tools/evil_winrm",
            json={
                "target": "10.0.0.5",
                "username": "alice",
                "hash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            },
        )

    assert response.status_code == 200
    command = mock_execute.call_args[0][0]
    assert command.startswith("evil-winrm -i 10.0.0.5 -u alice -H ")
    assert mock_execute.call_args.kwargs["endpoint"] == "/api/tools/evil_winrm"
