import types

from click.testing import CliRunner


def test_devbox_terminal_group_is_exposed_at_top_level():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["devbox", "terminal", "--help"])
    assert result.exit_code == 0, result.output


def test_devbox_terminal_list_json_works_without_network(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.devbox.cli as devbox_cli_mod
    from morphcloud.devbox.terminals import TerminalListResult

    class StubDevboxesCore:
        def get_devbox(self, devbox_id: str):
            return types.SimpleNamespace(status="ready", metadata={})

    class StubTerminals:
        def list(self, devbox_id: str, *, socket=None):
            return TerminalListResult(
                sessions=[
                    {
                        "name": "sess",
                        "id": "$0",
                        "windows": 1,
                        "clients": 1,
                        "created": "now",
                        "activity": "now",
                    }
                ],
                tmux_installed=True,
            )

    stub_devbox_client = types.SimpleNamespace(
        devboxes_core=StubDevboxesCore(),
        devboxes_actions=types.SimpleNamespace(resume_devbox=lambda devbox_id: None),
        terminals=StubTerminals(),
    )
    stub_client = types.SimpleNamespace(ssh_hostname="ssh.cloud.morph.so", ssh_port=22)

    monkeypatch.setattr(
        devbox_cli_mod, "_get_devbox_client", lambda: (stub_client, stub_devbox_client)
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli, ["devbox", "terminal", "list", "devbox_123", "--json"]
    )
    assert result.exit_code == 0, result.output
    assert '"tmux_installed"' in result.output
    assert '"sessions"' in result.output


def test_devbox_terminal_start_json_works_without_network(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.devbox.cli as devbox_cli_mod
    from morphcloud.devbox.terminals import TerminalStartResult

    class StubDevboxesCore:
        def get_devbox(self, devbox_id: str):
            return types.SimpleNamespace(status="ready", metadata={})

    class StubTerminals:
        def start(self, devbox_id: str, *, name: str, ensure_tmux: bool, detached: bool):
            return TerminalStartResult(
                install={"installed": True, "tmux_version": "3.4"},
                session={
                    "name": name,
                    "id": "$1",
                    "windows": 1,
                    "clients": 0,
                    "created": "now",
                    "activity": "now",
                },
            )

    stub_devbox_client = types.SimpleNamespace(
        devboxes_core=StubDevboxesCore(),
        devboxes_actions=types.SimpleNamespace(resume_devbox=lambda devbox_id: None),
        terminals=StubTerminals(),
    )
    stub_client = types.SimpleNamespace(ssh_hostname="ssh.cloud.morph.so", ssh_port=22)

    monkeypatch.setattr(
        devbox_cli_mod, "_get_devbox_client", lambda: (stub_client, stub_devbox_client)
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["devbox", "terminal", "start", "devbox_123", "--name", "my session", "--json"],
    )
    assert result.exit_code == 0, result.output
    assert '"session"' in result.output


def test_devbox_terminal_connect_requires_tty():
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli, ["devbox", "terminal", "connect", "devbox_123", "sess"]
    )
    assert result.exit_code != 0
    assert "requires an interactive TTY" in result.output


def test_devbox_terminal_connect_builds_attach_command(monkeypatch):
    import morphcloud.devbox.cli as devbox_cli_mod

    captured: dict[str, str] = {}

    class StubDevboxesCore:
        def get_devbox(self, devbox_id: str):
            return types.SimpleNamespace(status="ready", metadata={})

    class StubTmux:
        def tmux_install(self, devbox_id: str):
            return None

    class StubAdmin:
        def get_devbox_ssh_credentials(self, devbox_id: str):
            return types.SimpleNamespace(access_token="user", password="pass")

    class StubSSHWrapper:
        def interactive_shell(self, command=None):
            captured["command"] = command or ""
            return 0

    class StubSSHContext:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __enter__(self):
            return StubSSHWrapper()

        def __exit__(self, exc_type, exc, tb):
            return False

    stub_devbox_client = types.SimpleNamespace(
        devboxes_core=StubDevboxesCore(),
        devboxes_actions=types.SimpleNamespace(resume_devbox=lambda devbox_id: None),
        tmux=StubTmux(),
        admin=StubAdmin(),
    )
    stub_client = types.SimpleNamespace(ssh_hostname="ssh.cloud.morph.so", ssh_port=22)

    monkeypatch.setattr(
        devbox_cli_mod, "_get_devbox_client", lambda: (stub_client, stub_devbox_client)
    )
    monkeypatch.setattr(devbox_cli_mod, "_DevboxSSHContext", StubSSHContext)
    monkeypatch.setattr(devbox_cli_mod.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))

    try:
        devbox_cli_mod.terminal_connect.callback(  # type: ignore[attr-defined]
            devbox_id="devbox_123",
            session="sess",
            initial_command="echo hi",
            timeout=300,
            keepalive=15,
        )
    except SystemExit as exc:
        assert exc.code == 0
    assert captured["command"] == "tmux new-session -A -s 'sess' 'echo hi'"
