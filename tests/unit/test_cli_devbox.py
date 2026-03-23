import types

import pytest
from click.testing import CliRunner


def test_devbox_group_is_exposed_at_top_level():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["devbox", "--help"])
    assert result.exit_code == 0, result.output


def test_devbox_template_group_is_exposed():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["devbox", "template", "--help"])
    assert result.exit_code == 0, result.output


def test_devbox_template_run_command_is_exposed():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["devbox", "template", "run", "--help"])
    assert result.exit_code == 0, result.output
    assert "--experimental-run-locally" in result.output


def test_devbox_list_json_works_without_network(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.devbox.cli as devbox_cli_mod

    class StubResult:
        def model_dump(self):
            return {"data": [{"id": "devbox_123", "status": "ready"}]}

    class StubDevboxesCore:
        def list_devboxes(self):
            return StubResult()

    stub_devbox_client = types.SimpleNamespace(devboxes_core=StubDevboxesCore())
    stub_client = types.SimpleNamespace(devbox=stub_devbox_client, ssh_hostname="ssh.cloud.morph.so", ssh_port=22)

    monkeypatch.setattr(devbox_cli_mod, "_get_devbox_client", lambda: (stub_client, stub_devbox_client))

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["devbox", "list", "--json"])
    assert result.exit_code == 0, result.output
    assert '"data"' in result.output


def test_devbox_template_run_rejects_malformed_params():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["devbox", "template", "run", "tpl_123", "--param", "BAD"],
    )
    assert result.exit_code != 0
    assert "Workflow params must be provided as key=value." in result.output


def test_template_runner_backend_uses_service_key_when_user_key_missing(monkeypatch):
    import morphcloud.devbox.cli as devbox_cli_mod

    settings = types.SimpleNamespace(
        api_key=None,
        devbox_base_url="https://devbox.example",
        ssh_hostname="ssh.example",
        ssh_port=22,
    )

    monkeypatch.setattr(devbox_cli_mod, "resolve_settings", lambda: settings)
    monkeypatch.setenv("MNW_DEVBOX_SERVICE_API_KEY", "service-key")

    client, devbox_client, anonymous = devbox_cli_mod._get_template_runner_backend()

    assert client is None
    assert anonymous is True
    assert (
        devbox_client._client_wrapper.get_headers()["Authorization"]
        == "Bearer service-key"
    )


def test_template_runner_backend_requires_service_key_when_user_key_missing(monkeypatch):
    import morphcloud.devbox.cli as devbox_cli_mod

    settings = types.SimpleNamespace(
        api_key=None,
        devbox_base_url="https://devbox.example",
        ssh_hostname="ssh.example",
        ssh_port=22,
    )

    monkeypatch.setattr(devbox_cli_mod, "resolve_settings", lambda: settings)
    monkeypatch.delenv("MNW_DEVBOX_SERVICE_API_KEY", raising=False)
    monkeypatch.delenv("MORPH_DEVBOX_SERVICE_API_KEY", raising=False)

    with pytest.raises(Exception, match="MORPH_API_KEY is not set"):
        devbox_cli_mod._get_template_runner_backend()


def test_devbox_template_run_local_mode(tmp_path):
    import morphcloud.cli as cli_mod

    yaml_path = tmp_path / "template.yaml"
    yaml_path.write_text(
        "name: Local Test\n"
        "steps:\n"
        "  - title: Echo\n"
        "    run: printf 'hello from local mode\\n'\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "devbox",
            "template",
            "run",
            str(yaml_path),
            "--experimental-run-locally",
            "--plain",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "hello from local mode" in result.output
    assert "Workflow completed." in result.output


def test_devbox_template_run_local_mode_fetches_alias_yaml(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.devbox.template_local_runner as local_runner_mod

    def fake_fetch(alias: str) -> str:
        assert alias == "opengauss"
        return (
            "name: OpenGauss\n"
            "steps:\n"
            "  - title: Echo\n"
            "    run: printf 'hello from alias fallback\\n'\n"
        )

    monkeypatch.setattr(
        local_runner_mod,
        "_fetch_morph_new_template_yaml",
        fake_fetch,
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "devbox",
            "template",
            "run",
            "opengauss",
            "--experimental-run-locally",
            "--plain",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "hello from alias fallback" in result.output
    assert "Workflow completed." in result.output
