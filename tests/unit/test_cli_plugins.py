import json
import types

import click
from click.testing import CliRunner

from morphcloud import config
from morphcloud.api import ApiError
from morphcloud.simple_index.client import PluginCatalogEntry


class FakeSimpleIndexClient:
    def __init__(self):
        self.entries = {
            "intro": PluginCatalogEntry(
                name="intro",
                package_name="morphcloud-intro",
                version_spec="==1.0.0",
                enabled=True,
                entry_point="morphcloud_intro:register_cli",
                command_name="intro",
                visibility="org",
                organization_id="org_1",
                source="org:org_1",
                manifest={
                    "name": "intro",
                    "package_name": "morphcloud-intro",
                    "version": "1.0.0",
                },
            ),
            "disabled": PluginCatalogEntry(
                name="disabled",
                package_name="morphcloud-disabled",
                enabled=False,
                visibility="global",
                source="global",
                manifest={
                    "name": "disabled",
                    "package_name": "morphcloud-disabled",
                    "version": "1.0.0",
                },
            ),
        }
        self.packages = {}
        self.calls = []

    def list_plugins(self):
        return list(self.entries.values())

    def get_plugin(self, name):
        try:
            return self.entries[name]
        except KeyError:
            raise KeyError(name)

    def authenticated_simple_index_url(self):
        return "https://__token__:secret@simple-index.example.test/simple/"

    def redacted_simple_index_url(self):
        return "https://simple-index.example.test/simple/"

    def upsert_plugin(self, name, manifest, *, visibility=None, organization_id=None):
        self.calls.append(("upsert", name, manifest, visibility, organization_id))
        entry = PluginCatalogEntry.from_payload(
            {
                **manifest,
                "name": name,
                "visibility": visibility or manifest.get("visibility"),
                "organization_id": organization_id or manifest.get("organization_id"),
                "source": visibility or manifest.get("visibility"),
            }
        )
        self.entries[name] = entry
        return entry

    def disable_plugin(self, name, *, visibility=None, organization_id=None):
        self.calls.append(("disable", name, visibility, organization_id))
        current = self.get_plugin(name)
        entry = PluginCatalogEntry.from_payload({**current.to_dict(), "enabled": False})
        self.entries[name] = entry
        return entry

    def delete_plugin(self, name, *, visibility=None, organization_id=None):
        self.calls.append(("delete", name, visibility, organization_id))
        self.entries.pop(name, None)

    def upload_package(
        self,
        wheel,
        *,
        project=None,
        allow_overwrite=False,
        visibility=None,
        organization_id=None,
    ):
        self.calls.append(
            (
                "upload",
                str(wheel),
                project,
                allow_overwrite,
                visibility,
                organization_id,
            )
        )
        filename = getattr(wheel, "name", str(wheel))
        self.packages.setdefault(project, set()).add(filename)
        return {
            "project": project,
            "filename": filename,
            "visibility": visibility,
            "organization_id": organization_id,
        }

    def list_packages(self):
        self.calls.append(("list-packages",))
        return {
            "object": "list",
            "data": [
                {
                    "project": project,
                    "files": [{"filename": filename} for filename in sorted(files)],
                }
                for project, files in sorted(self.packages.items())
            ],
        }


def _install_fake_client(monkeypatch, fake):
    import morphcloud.plugins.cli as plugin_cli

    monkeypatch.setattr(
        plugin_cli,
        "get_client",
        lambda: types.SimpleNamespace(
            profile="stage",
            api_key="secret-key",
            simple_index=fake,
        ),
    )


def _install_fake_doctor(monkeypatch, fake, *, api_key="secret-key"):
    import morphcloud.plugins.cli as plugin_cli

    monkeypatch.setattr(
        plugin_cli,
        "_resolve_current_settings",
        lambda: config.ResolvedSettings(
            profile="stage",
            api_key=api_key,
            base_url="https://stage.morph.so/api",
            ssh_hostname="ssh.stage.morph.so",
            ssh_port=22,
            api_host="stage.morph.so",
            service_base_url="https://service.svc.stage.morph.so",
            volumes_base_url="https://volumes.svc.stage.morph.so",
            devbox_base_url="https://devbox.svc.stage.morph.so",
            admin_base_url="https://admin.svc.stage.morph.so",
            db_base_url="https://db.svc.stage.morph.so",
            simple_index_base_url="https://simple-index.example.test",
        ),
    )
    monkeypatch.setattr(
        plugin_cli,
        "_simple_index_client_for_settings",
        lambda settings: fake,
    )


def test_plugin_list_outputs_visible_plugins(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "list"])

    assert result.exit_code == 0, result.output
    assert "intro" in result.output
    assert "disabled" not in result.output
    assert "org:org_1" in result.output


def test_plugin_list_json_can_include_disabled(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli, ["plugin", "list", "--include-disabled", "--json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [item["name"] for item in payload] == ["disabled", "intro"]


def test_plugin_search_filters_visible_plugins(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "search", "intro", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [item["name"] for item in payload] == ["intro"]


def test_plugin_show_and_info_alias(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    show_result = runner.invoke(cli_mod.cli, ["plugin", "show", "intro", "--json"])
    info_result = runner.invoke(cli_mod.cli, ["plugin", "info", "intro", "--json"])

    assert show_result.exit_code == 0, show_result.output
    assert info_result.exit_code == 0, info_result.output
    assert json.loads(show_result.output)["name"] == "intro"
    assert json.loads(info_result.output)["entry_point"] == (
        "morphcloud_intro:register_cli"
    )


def test_plugin_install_uses_authenticated_index_and_verifies(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda requirement, *, index_url, upgrade=False, python_executable=None: calls.append(
            ("install", requirement, index_url, upgrade, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *, entry_point=None, command_name=None, python_executable=None: calls.append(
            ("entry", entry_point, command_name, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda command_name, *, python_executable=None: calls.append(
            ("help", command_name, python_executable)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "intro"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "install",
            "morphcloud-intro==1.0.0",
            "https://__token__:secret@simple-index.example.test/simple/",
            False,
            None,
        ),
        ("entry", "morphcloud_intro:register_cli", "intro", None),
        ("help", "intro", None),
    ]
    assert "secret" not in result.output


def test_plugin_install_forwards_explicit_python_to_installer_and_verify(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda requirement, *, index_url, upgrade=False, python_executable=None: calls.append(
            ("install", requirement, index_url, upgrade, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *, entry_point=None, command_name=None, python_executable=None: calls.append(
            ("entry", entry_point, command_name, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda command_name, *, python_executable=None: calls.append(
            ("help", command_name, python_executable)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["plugin", "install", "intro", "--python", "/tmp/plugin-python"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "install",
            "morphcloud-intro==1.0.0",
            "https://__token__:secret@simple-index.example.test/simple/",
            False,
            "/tmp/plugin-python",
        ),
        ("entry", "morphcloud_intro:register_cli", "intro", "/tmp/plugin-python"),
        ("help", "intro", "/tmp/plugin-python"),
    ]


def test_plugin_install_dry_run_prints_target_python(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["plugin", "install", "intro", "--venv", "/tmp/plugin-venv", "--dry-run"],
    )

    assert result.exit_code == 0, result.output
    assert "Python: /tmp/plugin-venv/bin/python" in result.output


def test_plugin_install_rejects_python_and_venv(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("install", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "install",
            "intro",
            "--python",
            "/tmp/python",
            "--venv",
            "/tmp/venv",
        ],
    )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output
    assert calls == []


def test_plugin_install_upgrade_flag_is_passed_to_installer(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda requirement, *, index_url, upgrade=False, python_executable=None: calls.append(
            ("install", requirement, index_url, upgrade)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *, entry_point=None, command_name=None, python_executable=None: calls.append(
            ("entry", entry_point, command_name)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda command_name, *, python_executable=None: calls.append(
            ("help", command_name)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "intro", "--upgrade"])

    assert result.exit_code == 0, result.output
    assert calls[0] == (
        "install",
        "morphcloud-intro==1.0.0",
        "https://__token__:secret@simple-index.example.test/simple/",
        True,
    )


def test_plugin_install_skip_verify_avoids_post_install_checks(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda requirement, *, index_url, upgrade=False, python_executable=None: calls.append(
            ("install", requirement, index_url, upgrade)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *args, **kwargs: calls.append(("entry", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda *args, **kwargs: calls.append(("help", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "intro", "--skip-verify"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "install",
            "morphcloud-intro==1.0.0",
            "https://__token__:secret@simple-index.example.test/simple/",
            False,
        )
    ]


def test_plugin_install_dry_run_does_not_install_or_print_secret(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("install", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *args, **kwargs: calls.append(("entry", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda *args, **kwargs: calls.append(("help", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "intro", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert calls == []
    assert "Would install plugin 'intro' (morphcloud-intro==1.0.0)." in result.output
    assert "https://simple-index.example.test/simple/" in result.output
    assert "morphcloud intro" in result.output
    assert "secret" not in result.output


def test_plugin_install_artifact_url_prefers_direct_artifact_and_redacts(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url="https://artifacts.example.test/artifact.whl",
        enabled=True,
        entry_point="artifact_plugin:register_cli",
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": "https://artifacts.example.test/artifact.whl",
            "version": "1.0.0",
        },
    )
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_artifact",
        lambda artifact_url, *, upgrade=False, python_executable=None: calls.append(
            ("artifact", artifact_url, upgrade, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("package", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *, entry_point=None, command_name=None, python_executable=None: calls.append(
            ("entry", entry_point, command_name)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda command_name, *, python_executable=None: calls.append(
            ("help", command_name)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "artifact"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "artifact",
            "https://artifacts.example.test/artifact.whl",
            False,
            None,
        ),
        ("entry", "artifact_plugin:register_cli", "artifact"),
        ("help", "artifact"),
    ]
    assert "https://artifacts.example.test/artifact.whl" in result.output


def test_plugin_install_rejects_sensitive_artifact_url_before_pip(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url="https://user:secret@artifacts.example.test/artifact.whl",
        enabled=True,
        entry_point="artifact_plugin:register_cli",
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": "https://user:secret@artifacts.example.test/artifact.whl",
            "version": "1.0.0",
        },
    )
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("package", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *args, **kwargs: calls.append(("entry", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda *args, **kwargs: calls.append(("help", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "artifact"])

    assert result.exit_code != 0
    assert "cannot be installed directly" in result.output
    assert "secret" not in result.output
    assert calls == []


def test_plugin_install_artifact_dry_run_does_not_print_secret_or_index(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url="https://user:secret@artifacts.example.test/artifact.whl",
        enabled=True,
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": "https://user:secret@artifacts.example.test/artifact.whl",
            "version": "1.0.0",
        },
    )
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_artifact",
        lambda *args, **kwargs: calls.append(("artifact", args, kwargs)),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("package", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "artifact", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert calls == []
    assert "Would install plugin 'artifact'" in result.output
    assert (
        "Artifact: https://<redacted>@artifacts.example.test/artifact.whl"
        in result.output
    )
    assert "Package index:" not in result.output
    assert "secret" not in result.output


def test_plugin_install_rejects_disabled_plugin(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("install", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "install", "disabled"])

    assert result.exit_code != 0
    assert "Plugin 'disabled' is disabled." in result.output
    assert calls == []


def test_plugin_uninstall_uses_catalog_package_name(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "uninstall_package",
        lambda package_name, *, python_executable=None: calls.append(
            (package_name, python_executable)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "uninstall", "intro"])

    assert result.exit_code == 0, result.output
    assert calls == [("morphcloud-intro", None)]
    assert "Uninstalled plugin 'intro' (morphcloud-intro)." in result.output


def test_plugin_uninstall_forwards_explicit_venv(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "uninstall_package",
        lambda package_name, *, python_executable=None: calls.append(
            (package_name, python_executable)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["plugin", "uninstall", "intro", "--venv", "/tmp/plugin-venv"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [("morphcloud-intro", "/tmp/plugin-venv/bin/python")]


def test_plugin_uninstall_artifact_plugin_uses_installed_entry_distribution(
    monkeypatch,
):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url="https://artifacts.example.test/artifact.whl",
        enabled=True,
        entry_point="artifact_plugin:register_cli",
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": "https://artifacts.example.test/artifact.whl",
            "version": "1.0.0",
        },
    )
    _install_fake_client(monkeypatch, fake)
    monkeypatch.setattr(
        plugin_cli,
        "_installed_cli_plugins",
        lambda **kwargs: [
            {
                "name": "artifact",
                "entry_point": "artifact_plugin:register_cli",
                "package": "artifact-plugin",
                "version": "1.0.0",
            }
        ],
    )
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "uninstall_package",
        lambda package_name, *, python_executable=None: calls.append(package_name),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "uninstall", "artifact"])

    assert result.exit_code == 0, result.output
    assert calls == ["artifact-plugin"]
    assert "Uninstalled plugin 'artifact' (artifact-plugin)." in result.output


def test_plugin_uninstall_artifact_plugin_uses_target_python_entry_distribution(
    monkeypatch,
):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url="https://artifacts.example.test/artifact.whl",
        enabled=True,
        entry_point="artifact_plugin:register_cli",
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": "https://artifacts.example.test/artifact.whl",
            "version": "1.0.0",
        },
    )
    _install_fake_client(monkeypatch, fake)
    entry_point_calls = []

    def fake_installed_cli_plugins(**kwargs):
        entry_point_calls.append(kwargs)
        return [
            {
                "name": "artifact",
                "entry_point": "artifact_plugin:register_cli",
                "package": "artifact-plugin",
                "version": "1.0.0",
            }
        ]

    monkeypatch.setattr(
        plugin_cli, "_installed_cli_plugins", fake_installed_cli_plugins
    )
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "uninstall_package",
        lambda package_name, *, python_executable=None: calls.append(
            (package_name, python_executable)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["plugin", "uninstall", "artifact", "--python", "/tmp/plugin-python"],
    )

    assert result.exit_code == 0, result.output
    assert entry_point_calls == [{"python_executable": "/tmp/plugin-python"}]
    assert calls == [("artifact-plugin", "/tmp/plugin-python")]


def test_plugin_uninstall_artifact_plugin_requires_identifiable_package(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url="https://artifacts.example.test/artifact.whl",
        enabled=True,
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": "https://artifacts.example.test/artifact.whl",
            "version": "1.0.0",
        },
    )
    _install_fake_client(monkeypatch, fake)
    monkeypatch.setattr(plugin_cli, "_installed_cli_plugins", lambda **kwargs: [])
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "uninstall_package",
        lambda package_name, *, python_executable=None: calls.append(package_name),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "uninstall", "artifact"])

    assert result.exit_code != 0
    assert "does not define package_name" in result.output
    assert "no installed CLI entry point identifies its package" in result.output
    assert calls == []


def test_plugin_upgrade_dry_run_does_not_install(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("install", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "upgrade", "intro", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert calls == []
    assert "Would upgrade plugin 'intro' (morphcloud-intro==1.0.0)." in result.output
    assert "secret" not in result.output


def test_plugin_upgrade_rejects_disabled_plugin(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("install", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "upgrade", "disabled", "--dry-run"])

    assert result.exit_code != 0
    assert "Plugin 'disabled' is disabled." in result.output
    assert calls == []


def test_plugin_upgrade_installs_with_upgrade_and_verifies(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda requirement, *, index_url, upgrade=False, python_executable=None: calls.append(
            ("install", requirement, index_url, upgrade, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *, entry_point=None, command_name=None, python_executable=None: calls.append(
            ("entry", entry_point, command_name)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda command_name, *, python_executable=None: calls.append(
            ("help", command_name)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "upgrade", "intro"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "install",
            "morphcloud-intro==1.0.0",
            "https://__token__:secret@simple-index.example.test/simple/",
            True,
            None,
        ),
        ("entry", "morphcloud_intro:register_cli", "intro"),
        ("help", "intro"),
    ]
    assert "secret" not in result.output


def test_plugin_upgrade_forwards_explicit_python(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda requirement, *, index_url, upgrade=False, python_executable=None: calls.append(
            ("install", requirement, index_url, upgrade, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_entry_point",
        lambda *, entry_point=None, command_name=None, python_executable=None: calls.append(
            ("entry", entry_point, command_name, python_executable)
        ),
    )
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "verify_cli_help",
        lambda command_name, *, python_executable=None: calls.append(
            ("help", command_name, python_executable)
        ),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        ["plugin", "upgrade", "intro", "--python", "/tmp/plugin-python"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "install",
            "morphcloud-intro==1.0.0",
            "https://__token__:secret@simple-index.example.test/simple/",
            True,
            "/tmp/plugin-python",
        ),
        ("entry", "morphcloud_intro:register_cli", "intro", "/tmp/plugin-python"),
        ("help", "intro", "/tmp/plugin-python"),
    ]


def test_plugin_update_alias_uses_upgrade_dry_run(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    calls = []
    monkeypatch.setattr(
        plugin_cli.plugin_installer,
        "install_requirement",
        lambda *args, **kwargs: calls.append(("install", args, kwargs)),
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "update", "intro", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert calls == []
    assert "Would upgrade plugin 'intro' (morphcloud-intro==1.0.0)." in result.output


def test_plugin_lifecycle_commands_forward_scope(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    disable_result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "disable",
            "intro",
            "--visibility",
            "org",
            "--organization-id",
            "org_1",
            "--json",
        ],
    )
    enable_result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "enable",
            "intro",
            "--visibility",
            "org",
            "--organization-id",
            "org_1",
            "--json",
        ],
    )
    delete_result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "delete",
            "intro",
            "--visibility",
            "org",
            "--organization-id",
            "org_1",
            "--yes",
        ],
    )

    assert disable_result.exit_code == 0, disable_result.output
    assert json.loads(disable_result.output)["enabled"] is False
    assert enable_result.exit_code == 0, enable_result.output
    assert json.loads(enable_result.output)["enabled"] is True
    assert delete_result.exit_code == 0, delete_result.output
    assert fake.calls[0] == ("disable", "intro", "org", "org_1")
    assert fake.calls[1][0] == "upsert"
    assert fake.calls[1][1] == "intro"
    assert fake.calls[1][3:] == ("org", "org_1")
    assert fake.calls[2] == ("delete", "intro", "org", "org_1")


def test_plugin_enable_global_scope_does_not_inherit_org_id(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "enable",
            "intro",
            "--visibility",
            "global",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["visibility"] == "global"
    assert "organization_id" not in payload
    assert fake.calls[0][0] == "upsert"
    assert fake.calls[0][3:] == ("global", None)
    assert fake.calls[0][2]["visibility"] == "global"
    assert "organization_id" not in fake.calls[0][2]


def test_plugin_register_builds_manifest(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "demo",
            "--package-name",
            "morphcloud-demo",
            "--version",
            "1.2.3",
            "--entry-point",
            "morphcloud_demo:register_cli",
            "--command-name",
            "demo",
            "--visibility",
            "org",
            "--organization-id",
            "org_1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["name"] == "demo"
    assert payload["package_name"] == "morphcloud-demo"
    assert payload["entry_point"] == "morphcloud_demo:register_cli"
    assert fake.calls[0][0] == "upsert"
    assert fake.calls[0][3:] == ("org", "org_1")


def test_plugin_register_accepts_artifact_url_without_package(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "artifact",
            "--artifact-url",
            "https://artifacts.example.test/artifact.whl",
            "--version",
            "1.2.3",
            "--command-name",
            "artifact",
            "--visibility",
            "global",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["name"] == "artifact"
    assert payload["artifact_url"] == "https://artifacts.example.test/artifact.whl"
    assert payload["command_name"] == "artifact"
    assert "package_name" not in payload
    assert fake.calls[0][0] == "upsert"
    assert fake.calls[0][3:] == ("global", None)


def test_plugin_json_outputs_redact_signed_artifact_urls(monkeypatch):
    import morphcloud.cli as cli_mod

    signed_url = "https://artifacts.example.test/artifact.whl?token=secret-token"
    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url=signed_url,
        version_spec="==1.2.3",
        enabled=True,
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": signed_url,
            "version": "1.2.3",
        },
    )
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    list_result = runner.invoke(cli_mod.cli, ["plugin", "list", "--json"])
    show_result = runner.invoke(cli_mod.cli, ["plugin", "show", "artifact", "--json"])
    register_result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "artifact-copy",
            "--artifact-url",
            signed_url,
            "--version",
            "1.2.3",
            "--visibility",
            "global",
            "--json",
        ],
    )

    for result in [list_result, show_result, register_result]:
        assert result.exit_code == 0, result.output
        assert "secret-token" not in result.output
        assert "artifact.whl?<redacted>" in result.output


def test_plugin_register_requires_org_id_for_org_visibility(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "demo",
            "--package-name",
            "morphcloud-demo",
            "--version",
            "1.2.3",
            "--visibility",
            "org",
        ],
    )

    assert result.exit_code != 0
    assert "--organization-id is required" in result.output
    assert fake.calls == []


def test_plugin_register_requires_org_id_for_org_manifest(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    manifest_path = tmp_path / "plugin_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "demo",
                "package_name": "morphcloud-demo",
                "version": "1.2.3",
                "visibility": "org",
                "organization_id": None,
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "demo",
            "--manifest",
            str(manifest_path),
        ],
    )

    assert result.exit_code != 0
    assert "--organization-id is required" in result.output
    assert fake.calls == []


def test_plugin_register_rejects_org_id_for_global_visibility(monkeypatch):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "demo",
            "--package-name",
            "morphcloud-demo",
            "--version",
            "1.2.3",
            "--visibility",
            "global",
            "--organization-id",
            "org_1",
        ],
    )

    assert result.exit_code != 0
    assert "--organization-id cannot be used" in result.output
    assert fake.calls == []


def test_plugin_register_preserves_disabled_manifest(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    manifest_path = tmp_path / "plugin_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "staged",
                "package_name": "morphcloud-staged",
                "version": "1.2.3",
                "enabled": False,
                "visibility": "org",
                "organization_id": "org_1",
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "register",
            "staged",
            "--manifest",
            str(manifest_path),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["enabled"] is False
    assert fake.calls[0][2]["enabled"] is False
    assert fake.calls[0][3:] == ("org", "org_1")


def test_plugin_publish_uploads_wheel_and_registers_manifest(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "publish",
            "demo",
            "--wheel",
            str(wheel),
            "--entry-point",
            "morphcloud_demo:register_cli",
            "--command-name",
            "demo",
            "--visibility",
            "org",
            "--organization-id",
            "org_1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["package_status"] == "uploaded"
    assert payload["package"]["filename"] == wheel.name
    assert payload["plugin"]["name"] == "demo"
    assert payload["plugin"]["package_name"] == "morphcloud-demo"
    assert payload["plugin"]["version"] == "1.2.3"
    assert payload["plugin"]["version_spec"] == "==1.2.3"
    assert fake.calls[0] == (
        "upload",
        str(wheel),
        "morphcloud-demo",
        False,
        "org",
        "org_1",
    )
    assert fake.calls[1][0] == "upsert"
    assert fake.calls[1][3:] == ("org", "org_1")
    assert fake.calls[1][2]["entry_point"] == "morphcloud_demo:register_cli"
    assert fake.calls[1][2]["command_name"] == "demo"


def test_plugin_publish_can_skip_existing_package(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    def upload_conflict(*args, **kwargs):
        fake.calls.append(("upload-conflict", args, kwargs))
        raise ApiError("conflict", 409, "package already exists")

    fake.upload_package = upload_conflict
    fake.packages["morphcloud-demo"] = {wheel.name}

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "publish",
            "demo",
            "--wheel",
            str(wheel),
            "--visibility",
            "global",
            "--skip-existing-package",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["package_status"] == "skipped_existing"
    assert payload["package"] is None
    assert payload["plugin"]["visibility"] == "global"
    assert fake.calls[0][0] == "upload-conflict"
    assert fake.calls[1] == ("list-packages",)
    assert fake.calls[2][0] == "upsert"
    assert fake.calls[2][3:] == ("global", None)


def test_plugin_publish_rejects_skipped_package_hidden_from_scope(
    monkeypatch, tmp_path
):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    def upload_conflict(*args, **kwargs):
        fake.calls.append(("upload-conflict", args, kwargs))
        raise ApiError("conflict", 409, "package already exists")

    fake.upload_package = upload_conflict

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "publish",
            "demo",
            "--wheel",
            str(wheel),
            "--visibility",
            "org",
            "--organization-id",
            "org_1",
            "--skip-existing-package",
        ],
    )

    assert result.exit_code != 0
    assert "requested scope cannot see" in result.output
    assert fake.calls[0][0] == "upload-conflict"
    assert fake.calls[1] == ("list-packages",)
    assert all(call[0] != "upsert" for call in fake.calls)


def test_plugin_publish_overrides_stale_manifest_install_target(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    manifest = tmp_path / "plugin_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "demo",
                "package": "old-package",
                "package_name": "old-package",
                "version": "0.0.1",
                "version_spec": "==0.0.1",
                "artifact_url": "https://artifacts.example.test/old.whl",
                "visibility": "org",
                "organization_id": "org_1",
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "publish",
            "demo",
            "--wheel",
            str(wheel),
            "--manifest",
            str(manifest),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    plugin = payload["plugin"]
    assert plugin["package"] == "morphcloud-demo"
    assert plugin["package_name"] == "morphcloud-demo"
    assert plugin["version"] == "1.2.3"
    assert plugin["version_spec"] == "==1.2.3"
    assert "artifact_url" not in plugin
    assert fake.calls[0][2] == "morphcloud-demo"
    assert fake.calls[1][2]["package"] == "morphcloud-demo"
    assert fake.calls[1][2]["package_name"] == "morphcloud-demo"
    assert fake.calls[1][2]["version_spec"] == "==1.2.3"
    assert "artifact_url" not in fake.calls[1][2]


def test_plugin_publish_rejects_wheel_package_mismatch(monkeypatch, tmp_path):
    import morphcloud.cli as cli_mod

    fake = FakeSimpleIndexClient()
    _install_fake_client(monkeypatch, fake)
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "plugin",
            "publish",
            "demo",
            "--wheel",
            str(wheel),
            "--package-name",
            "other-package",
            "--visibility",
            "global",
        ],
    )

    assert result.exit_code != 0
    assert "wheel filename package mismatch" in result.output
    assert fake.calls == []


def test_plugin_doctor_reports_catalog_registration_without_secrets(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    fake = FakeSimpleIndexClient()
    _install_fake_doctor(monkeypatch, fake)
    monkeypatch.setattr(
        plugin_cli,
        "_installed_cli_plugins",
        lambda: [
            {
                "name": "intro",
                "entry_point": "morphcloud_intro:register_cli",
                "package": "morphcloud-intro",
                "version": "1.0.0",
            }
        ],
    )
    monkeypatch.setattr(
        plugin_cli,
        "_installed_package_version",
        lambda package_name: "1.0.0" if package_name == "morphcloud-intro" else None,
    )

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["simple_index_url"] == "https://simple-index.example.test/simple/"
    assert payload["auth_configured"] is True
    assert payload["auth_status"] == "configured"
    assert payload["catalog_status"] == "ok"
    assert payload["catalog_error"] is None
    intro = payload["catalog_plugins"][1]
    assert intro["name"] == "intro"
    assert intro["installed"] is True
    assert intro["installed_version"] == "1.0.0"
    assert intro["entry_point_registered"] is True
    assert intro["command_registered"] is True
    disabled = payload["catalog_plugins"][0]
    assert disabled["name"] == "disabled"
    assert disabled["installed"] is False
    assert "secret" not in result.output


def test_plugin_doctor_reports_missing_auth_without_calling_catalog(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    class MissingAuthSimpleIndex(FakeSimpleIndexClient):
        def list_plugins(self):
            raise AssertionError("catalog should not be called without auth")

    fake = MissingAuthSimpleIndex()
    _install_fake_doctor(monkeypatch, fake, api_key=None)
    monkeypatch.setattr(plugin_cli, "_installed_cli_plugins", lambda: [])

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["auth_configured"] is False
    assert payload["auth_status"] == "missing"
    assert payload["catalog_status"] == "skipped"
    assert payload["catalog_plugins"] == []
    assert "MORPH_API_KEY" in payload["catalog_error"]


def test_plugin_doctor_redacts_catalog_errors(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    class ErroringSimpleIndex(FakeSimpleIndexClient):
        def list_plugins(self):
            raise RuntimeError("bad token secret-key")

    fake = ErroringSimpleIndex()
    _install_fake_doctor(monkeypatch, fake)
    monkeypatch.setattr(plugin_cli, "_installed_cli_plugins", lambda: [])

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["catalog_status"] == "error"
    assert payload["catalog_error"] == "bad token <redacted>"
    assert "secret-key" not in result.output


def test_plugin_doctor_redacts_signed_artifact_urls(monkeypatch):
    import morphcloud.cli as cli_mod
    import morphcloud.plugins.cli as plugin_cli

    signed_url = "https://artifacts.example.test/artifact.whl?token=secret-token"
    fake = FakeSimpleIndexClient()
    fake.entries["artifact"] = PluginCatalogEntry(
        name="artifact",
        artifact_url=signed_url,
        enabled=True,
        command_name="artifact",
        visibility="global",
        source="global",
        manifest={
            "name": "artifact",
            "artifact_url": signed_url,
            "version": "1.0.0",
        },
    )
    _install_fake_doctor(monkeypatch, fake)
    monkeypatch.setattr(plugin_cli, "_installed_cli_plugins", lambda: [])

    runner = CliRunner()
    result = runner.invoke(cli_mod.cli, ["plugin", "doctor", "--json"])

    assert result.exit_code == 0, result.output
    assert "secret-token" not in result.output
    payload = json.loads(result.output)
    artifact = next(
        item for item in payload["catalog_plugins"] if item["name"] == "artifact"
    )
    assert artifact["artifact_url"] == (
        "https://artifacts.example.test/artifact.whl?<redacted>"
    )


def test_cli_plugin_entry_point_becomes_callable_from_installed_distribution(
    monkeypatch, tmp_path
):
    import morphcloud.cli as cli_mod

    package_dir = tmp_path / "demo_plugin"
    package_dir.mkdir()
    package_dir.joinpath("__init__.py").write_text(
        "\n".join(
            [
                "import click",
                "",
                "",
                "def register_cli(cli_group):",
                "    @click.command('demo')",
                "    def demo():",
                '        """Demo plugin command."""',
                "        click.echo('demo ok')",
                "",
                "    cli_group.add_command(demo)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    dist_info = tmp_path / "morphcloud_demo_plugin-0.0.1.dist-info"
    dist_info.mkdir()
    dist_info.joinpath("METADATA").write_text(
        "\n".join(
            [
                "Metadata-Version: 2.1",
                "Name: morphcloud-demo-plugin",
                "Version: 0.0.1",
                "",
            ]
        ),
        encoding="utf-8",
    )
    dist_info.joinpath("entry_points.txt").write_text(
        "\n".join(
            [
                "[morphcloud.cli_plugins]",
                "demo = demo_plugin:register_cli",
                "",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.syspath_prepend(str(tmp_path))

    cli = click.Group()
    cli_mod.load_cli_plugins(cli)

    runner = CliRunner()
    help_result = runner.invoke(cli, ["demo", "--help"])
    run_result = runner.invoke(cli, ["demo"])

    assert help_result.exit_code == 0, help_result.output
    assert "Demo plugin command." in help_result.output
    assert run_result.exit_code == 0, run_result.output
    assert "demo ok" in run_result.output
