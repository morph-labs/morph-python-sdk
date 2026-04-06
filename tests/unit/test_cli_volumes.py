import types

from click.testing import CliRunner

from morphcloud.volumes.client import (
    VolumeBucket,
    VolumeListing,
    VolumeObject,
    VolumePrefix,
)


def _install_noop_spinner(monkeypatch):
    import morphcloud.volumes.cli as volumes_cli

    class NoopSpinner:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(volumes_cli, "Spinner", NoopSpinner)


def test_volumes_ls_lists_buckets(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.volumes.cli as volumes_cli

    stub_volumes = types.SimpleNamespace(
        list_buckets=lambda: [
            VolumeBucket(name="alpha", created_at="2026-04-01T00:00:00Z"),
            VolumeBucket(name="beta", created_at="2026-04-02T00:00:00Z"),
        ]
    )
    monkeypatch.setattr(
        volumes_cli,
        "get_client",
        lambda: types.SimpleNamespace(volumes=stub_volumes),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["volumes", "ls"])

    assert result.exit_code == 0, result.output
    assert "alpha" in result.output
    assert "beta" in result.output


def test_volumes_mb_creates_bucket(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.volumes.cli as volumes_cli

    _install_noop_spinner(monkeypatch)

    calls = []
    stub_volumes = types.SimpleNamespace(
        create_bucket=lambda bucket: calls.append(bucket),
    )
    monkeypatch.setattr(
        volumes_cli,
        "get_client",
        lambda: types.SimpleNamespace(volumes=stub_volumes),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["volumes", "mb", "demo"])

    assert result.exit_code == 0, result.output
    assert calls == ["demo"]
    assert "s3://demo" in result.output


def test_volumes_cp_uploads_to_bucket_prefix(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod
    import morphcloud.volumes.cli as volumes_cli

    _install_noop_spinner(monkeypatch)

    source = tmp_path / "hello.txt"
    source.write_text("hello volumes", encoding="utf-8")

    put_calls = []
    stub_volumes = types.SimpleNamespace(
        put_object=lambda bucket, key, data, content_type=None: put_calls.append(
            {
                "bucket": bucket,
                "key": key,
                "data": data,
                "content_type": content_type,
            }
        )
    )
    monkeypatch.setattr(
        volumes_cli,
        "get_client",
        lambda: types.SimpleNamespace(volumes=stub_volumes),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["volumes", "cp", str(source), "s3://demo/releases/"],
    )

    assert result.exit_code == 0, result.output
    assert put_calls == [
        {
            "bucket": "demo",
            "key": "releases/hello.txt",
            "data": b"hello volumes",
            "content_type": "text/plain",
        }
    ]
    assert "s3://demo/releases/hello.txt" in result.output


def test_volumes_rm_requires_recursive_for_prefix(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.volumes.cli as volumes_cli

    stub_volumes = types.SimpleNamespace(
        head_object=lambda bucket, key: None,
    )
    monkeypatch.setattr(
        volumes_cli,
        "get_client",
        lambda: types.SimpleNamespace(volumes=stub_volumes),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["volumes", "rm", "demo/assets"])

    assert result.exit_code != 0
    assert "Re-run with --recursive" in result.output


def test_volumes_ls_lists_folder_before_file(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.volumes.cli as volumes_cli

    stub_volumes = types.SimpleNamespace(
        head_object=lambda bucket, key: None,
        list_directory=lambda bucket, prefix="": VolumeListing(
            bucket=bucket,
            prefix=prefix,
            prefixes=[VolumePrefix(name="assets", prefix="assets/")],
            objects=[
                VolumeObject(
                    key="readme.txt",
                    name="readme.txt",
                    size=12,
                    last_modified="2026-04-02T00:00:00Z",
                )
            ],
            key_count=2,
        ),
    )
    monkeypatch.setattr(
        volumes_cli,
        "get_client",
        lambda: types.SimpleNamespace(volumes=stub_volumes),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["volumes", "ls", "demo"])

    assert result.exit_code == 0, result.output
    assert result.output.index("DIR") < result.output.index("FILE")
