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


def test_snapshot_create_passes_ttl_seconds(monkeypatch):
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)

    create_calls = []

    class StubSnapshots:
        def create(self, **kwargs):
            create_calls.append(kwargs)
            return types.SimpleNamespace(
                id="snapshot_123",
                digest=None,
                ttl=types.SimpleNamespace(ttl_seconds=kwargs.get("ttl_seconds")),
            )

    stub_client = types.SimpleNamespace(snapshots=StubSnapshots())
    monkeypatch.setattr(cli_mod, "get_client", lambda: stub_client)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "snapshot",
            "create",
            "--image-id",
            "morphvm-minimal",
            "--vcpus",
            "1",
            "--memory",
            "512",
            "--disk-size",
            "1024",
            "--ttl-seconds",
            "60",
        ],
    )

    assert result.exit_code == 0, result.output
    assert create_calls == [
        {
            "image_id": "morphvm-minimal",
            "vcpus": 1,
            "memory": 512,
            "disk_size": 1024,
            "digest": None,
            "ttl_seconds": 60,
            "metadata": None,
        }
    ]
    assert "TTL: 60 seconds" in result.output


def test_snapshot_set_ttl_uses_none_to_clear(monkeypatch):
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)

    set_ttl_calls = []

    class StubSnapshot:
        def set_ttl(self, ttl_seconds):
            set_ttl_calls.append(ttl_seconds)

    class StubSnapshots:
        def get(self, snapshot_id):
            assert snapshot_id == "snapshot_123"
            return StubSnapshot()

    stub_client = types.SimpleNamespace(snapshots=StubSnapshots())
    monkeypatch.setattr(cli_mod, "get_client", lambda: stub_client)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["snapshot", "set-ttl", "snapshot_123", "--ttl-seconds", "-1"],
    )

    assert result.exit_code == 0, result.output
    assert set_ttl_calls == [None]
    assert "TTL removed for snapshot_123" in result.output


def test_instance_snapshot_passes_ttl_seconds(monkeypatch):
    import morphcloud.api as api_mod
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)

    snapshot_calls = []

    class StubInstance:
        status = api_mod.InstanceStatus.READY

        def snapshot(self, **kwargs):
            snapshot_calls.append(kwargs)
            return types.SimpleNamespace(
                id="snapshot_123",
                digest=kwargs.get("digest"),
                ttl=types.SimpleNamespace(ttl_seconds=kwargs.get("ttl_seconds")),
            )

    class StubInstances:
        def get(self, instance_id):
            assert instance_id == "instance_123"
            return StubInstance()

    stub_client = types.SimpleNamespace(instances=StubInstances())
    monkeypatch.setattr(cli_mod, "get_client", lambda: stub_client)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "instance",
            "snapshot",
            "instance_123",
            "--digest",
            "digest-1",
            "--ttl-seconds",
            "45",
            "--metadata",
            "env=test",
        ],
    )

    assert result.exit_code == 0, result.output
    assert snapshot_calls == [
        {
            "digest": "digest-1",
            "metadata": {"env": "test"},
            "ttl_seconds": 45,
        }
    ]
    assert "TTL: 45 seconds" in result.output


@pytest.mark.parametrize(
    ("argv", "needle"),
    [
        (
            ["snapshot", "create", "--help"],
            "--ttl-seconds",
        ),
        (
            ["snapshot", "set-ttl", "--help"],
            "Snapshot TTL in seconds",
        ),
    ],
)
def test_snapshot_cli_help_mentions_ttl(monkeypatch, argv, needle):
    import morphcloud.cli as cli_mod

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, argv)
    assert result.exit_code == 0, result.output
    assert needle in result.output
