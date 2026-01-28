import importlib
import sys

from click.testing import CliRunner


def _import_cli_with_aws_sim_plugin(monkeypatch):
    import importlib.metadata

    entry_point = importlib.metadata.EntryPoint(
        name="aws-sim",
        value="morphcloud.cli_plugins.aws_sim:load",
        group="morphcloud.cli_plugins",
    )

    def fake_entry_points(*, group=None, **kwargs):
        if group == "morphcloud.cli_plugins":
            return [entry_point]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)
    sys.modules.pop("morphcloud.cli", None)
    return importlib.import_module("morphcloud.cli")


def test_env_aws_sim_plugin_registers_commands(monkeypatch):
    cli_mod = _import_cli_with_aws_sim_plugin(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["env", "aws-sim", "--help"])
    assert result.exit_code == 0, result.output


def test_env_aws_sim_list_wires_httpx(monkeypatch):
    cli_mod = _import_cli_with_aws_sim_plugin(monkeypatch)

    import morphcloud.cli_plugins.aws_sim as aws_sim_mod

    calls = []

    class StubResponse:
        status_code = 200
        reason_phrase = "OK"
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True}

    class StubClient:
        def __init__(self, *, base_url, headers, timeout):
            calls.append({"base_url": str(base_url), "headers": dict(headers), "timeout": timeout})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def request(self, method, url, json=None):
            calls[-1].update({"method": method, "url": url, "json": json})
            return StubResponse()

    monkeypatch.setattr(aws_sim_mod.httpx, "Client", StubClient)
    monkeypatch.setenv("SIM_AWS_BASE_URL", "https://example.test")
    monkeypatch.setenv("MORPH_API_KEY", "k_test_123")

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["env", "aws-sim", "list"])
    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "base_url": "https://example.test",
            "headers": {"Authorization": "Bearer k_test_123"},
            "timeout": calls[0]["timeout"],
            "method": "GET",
            "url": "/v1/envs",
            "json": None,
        }
    ]
    assert "k_test_123" not in result.output


def test_env_aws_sim_create_sends_body(monkeypatch):
    cli_mod = _import_cli_with_aws_sim_plugin(monkeypatch)

    import morphcloud.cli_plugins.aws_sim as aws_sim_mod

    calls = []

    class StubResponse:
        status_code = 200
        reason_phrase = "OK"
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {"env_id": "awsenv_test"}

    class StubClient:
        def __init__(self, *, base_url, headers, timeout):
            calls.append({"base_url": str(base_url), "headers": dict(headers), "timeout": timeout})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def request(self, method, url, json=None):
            calls[-1].update({"method": method, "url": url, "json": json})
            return StubResponse()

    monkeypatch.setattr(aws_sim_mod.httpx, "Client", StubClient)
    monkeypatch.setenv("SIM_AWS_BASE_URL", "https://example.test")
    monkeypatch.setenv("MORPH_API_KEY", "k_test_123")

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "env",
            "aws-sim",
            "create",
            "--region",
            "us-east-1",
            "--service",
            "s3",
            "--ttl-seconds",
            "3600",
            "--name",
            "test-env",
        ],
    )
    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "base_url": "https://example.test",
            "headers": {"Authorization": "Bearer k_test_123"},
            "timeout": calls[0]["timeout"],
            "method": "POST",
            "url": "/v1/envs",
            "json": {
                "name": "test-env",
                "regions": ["us-east-1"],
                "services": ["s3"],
                "ttl_seconds": 3600,
            },
        }
    ]
    assert "k_test_123" not in result.output


def test_env_aws_sim_restore_sends_snapshot_id(monkeypatch):
    cli_mod = _import_cli_with_aws_sim_plugin(monkeypatch)

    import morphcloud.cli_plugins.aws_sim as aws_sim_mod

    calls = []

    class StubResponse:
        status_code = 200
        reason_phrase = "OK"
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True}

    class StubClient:
        def __init__(self, *, base_url, headers, timeout):
            calls.append({"base_url": str(base_url), "headers": dict(headers), "timeout": timeout})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def request(self, method, url, json=None):
            calls[-1].update({"method": method, "url": url, "json": json})
            return StubResponse()

    monkeypatch.setattr(aws_sim_mod.httpx, "Client", StubClient)
    monkeypatch.setenv("SIM_AWS_BASE_URL", "https://example.test")
    monkeypatch.setenv("MORPH_API_KEY", "k_test_123")

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["env", "aws-sim", "restore", "awsenv_test", "awssnap_test"],
    )
    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "base_url": "https://example.test",
            "headers": {"Authorization": "Bearer k_test_123"},
            "timeout": calls[0]["timeout"],
            "method": "POST",
            "url": "/v1/envs/awsenv_test/restore",
            "json": {"snapshot_id": "awssnap_test"},
        }
    ]
    assert "k_test_123" not in result.output


def test_env_aws_sim_connect_writes_bundle_and_prints_docker_cmd(monkeypatch):
    cli_mod = _import_cli_with_aws_sim_plugin(monkeypatch)

    import morphcloud.cli_plugins.aws_sim as aws_sim_mod

    connect_calls = []

    class StubResponse:
        status_code = 200
        reason_phrase = "OK"
        text = ""

        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    class StubClient:
        def __init__(self, *, base_url, headers, timeout):
            self._headers = dict(headers)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def request(self, method, url, json=None):
            connect_calls.append({"method": method, "url": url, "headers": self._headers, "json": json})
            return StubResponse(
                {
                    "version": "v1",
                    "env_id": "awsenv_test",
                    "instance_id": "morphvm_test",
                    "tunnel_ws_url": "wss://example.test/tunnel",
                    "wg": {
                        "client_address": "10.0.0.2/32",
                        "client_private_key": "base64-private",
                        "server_public_key": "base64-pub",
                        "allowed_ips": ["10.0.0.0/24"],
                        "endpoint_host": "127.0.0.1",
                        "endpoint_port": 51820,
                        "mtu": 1280,
                        "persistent_keepalive": 25,
                    },
                    "dns": {"nameserver": "10.0.0.1"},
                    "tls": {"ca_cert_pem": "pem", "ca_fingerprint_sha256": "fp"},
                    "aws": {"gateway_ip": "10.0.0.3", "regions": ["us-east-1"]},
                    "auth": {
                        "mode": "morph_api_key_bearer",
                        "header_name": "Authorization",
                        "header_value_template": "Bearer ${MORPH_API_KEY}",
                    },
                    "notes": [],
                }
            )

    monkeypatch.setattr(aws_sim_mod.httpx, "Client", StubClient)
    monkeypatch.setenv("SIM_AWS_BASE_URL", "https://example.test")
    monkeypatch.setenv("MORPH_API_KEY", "k_test_123")

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli_mod.cli,
            ["env", "aws-sim", "connect", "awsenv_test", "--output", "bundle.json"],
        )
        assert result.exit_code == 0, result.output
        assert connect_calls == [
            {
                "method": "POST",
                "url": "/v1/envs/awsenv_test/connect",
                "headers": {"Authorization": "Bearer k_test_123"},
                "json": None,
            }
        ]
        assert "bundle.json" in result.output
        assert "docker run" in result.output
        assert "-e MORPH_API_KEY" in result.output
        assert "--cap-add=NET_ADMIN" in result.output
        assert "--device /dev/net/tun" in result.output
        assert aws_sim_mod.SRC_VALID_MARK_SYSCTL in result.output
        assert "k_test_123" not in result.output

