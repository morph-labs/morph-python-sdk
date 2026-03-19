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


def test_devbox_template_cache_forwards_workflow_context_and_force(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.devbox.cli as devbox_cli_mod

    captured = {}

    class StubTemplates:
        def cache_template(self, template_id, request=None):
            captured["template_id"] = template_id
            captured["request"] = request
            return types.SimpleNamespace(run_id="run_123")

    stub_devbox_client = types.SimpleNamespace(templates=StubTemplates())
    stub_client = types.SimpleNamespace(
        devbox=stub_devbox_client, ssh_hostname="ssh.cloud.morph.so", ssh_port=22
    )

    monkeypatch.setattr(
        devbox_cli_mod,
        "_get_devbox_client",
        lambda: (stub_client, stub_devbox_client),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "devbox",
            "template",
            "cache",
            "tpl_123",
            "--secret",
            "OPENAI_API_KEY=sk-test",
            "--workflow-context",
            "REPO_URL=https://github.com/morph-labs/frontend-v2",
            "--param",
            "REPO_REF=main",
            "--force",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["template_id"] == "tpl_123"
    request = captured["request"]
    assert request.runtime_secrets == {"OPENAI_API_KEY": "sk-test"}
    assert request.workflow_context == {
        "REPO_URL": "https://github.com/morph-labs/frontend-v2",
        "REPO_REF": "main",
    }
    assert request.force is True


def test_template_cache_request_serializes_workflow_context_and_force():
    from morphcloud.devbox.gen.types import TemplateCacheRequest

    request = TemplateCacheRequest(
        runtime_secrets={"OPENAI_API_KEY": "sk-test"},
        workflow_context={"REPO_URL": "https://github.com/morph-labs/frontend-v2"},
        force=True,
    )

    dumped = (
        request.model_dump(exclude_none=True)
        if hasattr(request, "model_dump")
        else request.dict(exclude_none=True)
    )

    assert dumped == {
        "runtime_secrets": {"OPENAI_API_KEY": "sk-test"},
        "workflow_context": {"REPO_URL": "https://github.com/morph-labs/frontend-v2"},
        "force": True,
    }
