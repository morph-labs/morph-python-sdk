import types

import pytest
from click.testing import CliRunner


def _install_noop_spinner(monkeypatch):
    import morphcloud.cli as cli_mod

    class NoopSpinner:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(cli_mod, "Spinner", NoopSpinner)


def test_secrets_group_is_exposed_at_top_level():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["secrets", "--help"])
    assert result.exit_code == 0


def test_secrets_create_reads_value_from_stdin(monkeypatch):
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)

    create_calls = []

    class StubUser:
        def create_secret(self, *, name, value, description=None, metadata=None):
            create_calls.append(
                {
                    "name": name,
                    "value": value,
                    "description": description,
                    "metadata": metadata,
                }
            )
            return types.SimpleNamespace(name=name, created=0)

    stub_client = types.SimpleNamespace(user=StubUser())
    monkeypatch.setattr(cli_mod, "get_client", lambda: stub_client)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "secrets",
            "create",
            "--name",
            "my_secret",
            "--description",
            "desc",
            "--metadata",
            "k=v",
            "--value-stdin",
        ],
        input="s3cr3t",
    )
    assert result.exit_code == 0, result.output
    assert create_calls == [
        {"name": "my_secret", "value": "s3cr3t", "description": "desc", "metadata": {"k": "v"}}
    ]


def test_secrets_create_rejects_value_and_value_stdin(monkeypatch):
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "secrets",
            "create",
            "--name",
            "my_secret",
            "--value",
            "x",
            "--value-stdin",
        ],
        input="y",
    )
    assert result.exit_code != 0
    assert "Use either --value or --value-stdin, not both." in result.output


@pytest.mark.parametrize(
    "argv",
    [
        ["secrets", "create", "--name", "my_secret"],
        ["user", "secret", "create", "--name", "my_secret"],
    ],
)
def test_secret_create_requires_value_in_non_interactive_mode(monkeypatch, argv):
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, argv)
    assert result.exit_code != 0
    assert "Secret value is required. Provide --value or pipe via --value-stdin." in result.output
