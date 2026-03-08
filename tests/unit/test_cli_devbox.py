import types

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

