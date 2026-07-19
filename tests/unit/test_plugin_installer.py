import subprocess

import pytest

from morphcloud.plugins import installer


def test_build_install_command_uses_uv_inside_virtualenv():
    command = installer.build_install_command(
        "morphcloud-intro==1.0.0",
        index_url="https://example.test/simple/",
        env={"VIRTUAL_ENV": "/tmp/venv"},
        which=lambda name: "/usr/bin/uv" if name == "uv" else None,
    )

    assert command == [
        "/usr/bin/uv",
        "pip",
        "install",
        "--python",
        installer.sys.executable,
        "--index-url",
        "https://example.test/simple/",
        "--extra-index-url",
        "https://pypi.org/simple",
        "morphcloud-intro==1.0.0",
    ]


def test_build_install_command_uses_explicit_python_with_uv():
    command = installer.build_install_command(
        "morphcloud-intro==1.0.0",
        index_url="https://example.test/simple/",
        python_executable="/tmp/plugin-venv/bin/python",
        env={"UV_RUN_RECURSION_DEPTH": "1"},
        which=lambda name: "/usr/bin/uv" if name == "uv" else None,
    )

    assert command == [
        "/usr/bin/uv",
        "pip",
        "install",
        "--python",
        "/tmp/plugin-venv/bin/python",
        "--index-url",
        "https://example.test/simple/",
        "--extra-index-url",
        "https://pypi.org/simple",
        "morphcloud-intro==1.0.0",
    ]


def test_build_install_command_resolves_venv_python_with_pip():
    command = installer.build_install_command(
        "morphcloud-intro",
        index_url="https://example.test/simple/",
        venv="/tmp/plugin-venv",
        env={},
        which=lambda name: None,
    )

    assert command[:4] == ["/tmp/plugin-venv/bin/python", "-m", "pip", "install"]


def test_resolve_python_executable_rejects_python_and_venv():
    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.resolve_python_executable(
            python_executable="/tmp/python",
            venv="/tmp/venv",
        )

    assert "mutually exclusive" in str(excinfo.value)


def test_build_install_command_falls_back_to_python_pip_without_uv():
    command = installer.build_install_command(
        "morphcloud-intro",
        index_url="https://example.test/simple/",
        env={},
        which=lambda name: None,
    )

    assert command[:3][-2:] == ["-m", "pip"]
    assert "--index-url" in command
    assert "--extra-index-url" in command
    assert command[-1] == "morphcloud-intro"


def test_build_install_command_can_disable_extra_index():
    command = installer.build_install_command(
        "morphcloud-intro",
        index_url="https://example.test/simple/",
        extra_index_url=None,
        env={},
        which=lambda name: None,
    )

    assert "--index-url" in command
    assert "--extra-index-url" not in command
    assert command[-1] == "morphcloud-intro"


def test_build_install_command_can_disable_extra_index_with_env():
    command = installer.build_install_command(
        "morphcloud-intro",
        index_url="https://example.test/simple/",
        env={"MORPH_PLUGIN_DISABLE_EXTRA_INDEX": "1"},
        which=lambda name: None,
    )

    assert "--index-url" in command
    assert "--extra-index-url" not in command
    assert command[-1] == "morphcloud-intro"


def test_build_install_command_can_use_custom_extra_index_with_env():
    command = installer.build_install_command(
        "morphcloud-intro",
        index_url="https://example.test/simple/",
        env={"MORPH_PLUGIN_EXTRA_INDEX_URL": "https://mirror.example.test/simple/"},
        which=lambda name: None,
    )

    assert command == [
        installer.sys.executable,
        "-m",
        "pip",
        "install",
        "--index-url",
        "https://example.test/simple/",
        "--extra-index-url",
        "https://mirror.example.test/simple/",
        "morphcloud-intro",
    ]


def test_build_artifact_install_command_uses_direct_url_without_index():
    command = installer.build_artifact_install_command(
        "https://artifacts.example.test/morphcloud-demo.whl",
        env={},
        which=lambda name: None,
    )

    assert command[:3][-2:] == ["-m", "pip"]
    assert "--index-url" not in command
    assert command[-1] == "https://artifacts.example.test/morphcloud-demo.whl"


def test_build_artifact_install_command_rejects_sensitive_urls():
    for artifact_url in [
        "https://user:secret@artifacts.example.test/morphcloud-demo.whl",
        "https://artifacts.example.test/morphcloud-demo.whl?token=secret",
        "https://artifacts.example.test/morphcloud-demo.whl#secret",
    ]:
        with pytest.raises(installer.PluginInstallError) as excinfo:
            installer.build_artifact_install_command(
                artifact_url,
                env={},
                which=lambda name: None,
            )
        assert "cannot be installed directly" in str(excinfo.value)
        assert "secret" not in str(excinfo.value)


def test_build_uninstall_command_omits_yes_flag_for_uv():
    command = installer.build_uninstall_command(
        "morphcloud-intro",
        env={"VIRTUAL_ENV": "/tmp/venv"},
        which=lambda name: "/usr/bin/uv" if name == "uv" else None,
    )

    assert command == [
        "/usr/bin/uv",
        "pip",
        "uninstall",
        "--python",
        installer.sys.executable,
        "morphcloud-intro",
    ]


def test_build_uninstall_command_uses_explicit_python_with_uv():
    command = installer.build_uninstall_command(
        "morphcloud-intro",
        python_executable="/tmp/plugin-venv/bin/python",
        env={"UV_RUN_RECURSION_DEPTH": "1"},
        which=lambda name: "/usr/bin/uv" if name == "uv" else None,
    )

    assert command == [
        "/usr/bin/uv",
        "pip",
        "uninstall",
        "--python",
        "/tmp/plugin-venv/bin/python",
        "morphcloud-intro",
    ]


def test_build_uninstall_command_keeps_yes_flag_for_pip():
    command = installer.build_uninstall_command(
        "morphcloud-intro",
        env={},
        which=lambda name: None,
    )

    assert command == [
        installer.sys.executable,
        "-m",
        "pip",
        "uninstall",
        "-y",
        "morphcloud-intro",
    ]


def test_build_install_command_rejects_ambiguous_uv_run(monkeypatch):
    monkeypatch.setattr(installer.sys, "prefix", "/usr")
    monkeypatch.setattr(installer.sys, "base_prefix", "/usr")

    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.build_install_command(
            "morphcloud-intro",
            index_url="https://secret@example.test/simple/",
            env={"UV_RUN_RECURSION_DEPTH": "1"},
            which=lambda name: "/usr/bin/uv" if name == "uv" else None,
        )

    assert "ambiguous uv run environment" in str(excinfo.value)


def test_install_artifact_redacts_url_on_failure():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="using https://artifacts.example.test/demo.whl",
            stderr="failed https://artifacts.example.test/demo.whl",
        )

    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.install_artifact(
            "https://artifacts.example.test/demo.whl",
            env={},
            which=lambda name: None,
            runner=runner,
        )

    message = str(excinfo.value)
    assert "<redacted>" in message


def test_install_requirement_redacts_index_url_on_failure():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="using https://__token__:secret@example.test/simple/",
            stderr="failed https://__token__:secret@example.test/simple/",
        )

    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.install_requirement(
            "morphcloud-intro",
            index_url="https://__token__:secret@example.test/simple/",
            env={},
            which=lambda name: None,
            runner=runner,
        )

    message = str(excinfo.value)
    assert "secret" not in message
    assert "<redacted>" in message


def test_install_requirement_redacts_custom_extra_index_url_on_failure():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="using https://user:extra-secret@example.test/simple/",
            stderr="failed https://user:extra-secret@example.test/simple/",
        )

    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.install_requirement(
            "morphcloud-intro",
            index_url="https://__token__:secret@example.test/simple/",
            extra_index_url="https://user:extra-secret@example.test/simple/",
            env={},
            which=lambda name: None,
            runner=runner,
        )

    message = str(excinfo.value)
    assert "secret" not in message
    assert "extra-secret" not in message
    assert "<redacted>" in message


def test_verify_cli_entry_point_uses_fresh_process_when_cache_misses(monkeypatch):
    monkeypatch.setattr(installer, "resolve_cli_entry_point", lambda **kwargs: None)
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    installer.verify_cli_entry_point(
        entry_point="demo_plugin:register_cli",
        command_name="demo",
        runner=runner,
    )

    command, kwargs = calls[0]
    assert command[0] == installer.sys.executable
    assert command[1] == "-c"
    assert "import importlib.metadata" in command[2]
    assert command[3:] == [
        installer.CLI_ENTRY_POINT_GROUP,
        "demo_plugin:register_cli",
        "demo",
    ]
    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True


def test_verify_cli_entry_point_uses_explicit_python_without_cached_lookup(monkeypatch):
    monkeypatch.setattr(
        installer,
        "resolve_cli_entry_point",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("unexpected cache lookup")
        ),
    )
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    installer.verify_cli_entry_point(
        entry_point="demo_plugin:register_cli",
        command_name="demo",
        python_executable="/tmp/plugin-venv/bin/python",
        runner=runner,
    )

    assert calls[0][0][0] == "/tmp/plugin-venv/bin/python"


def test_verify_cli_help_uses_explicit_python():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    installer.verify_cli_help(
        "demo",
        python_executable="/tmp/plugin-venv/bin/python",
        runner=runner,
    )

    assert calls[0][0][:4] == [
        "/tmp/plugin-venv/bin/python",
        "-m",
        "morphcloud.cli",
        "demo",
    ]


def test_list_cli_plugins_uses_explicit_python():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                '[{"name":"demo","entry_point":"demo_plugin:register_cli",'
                '"package":"demo-plugin","version":"1.0.0"}]'
            ),
            stderr="",
        )

    plugins = installer.list_cli_plugins(
        python_executable="/tmp/plugin-venv/bin/python",
        runner=runner,
    )

    assert calls[0][0][0] == "/tmp/plugin-venv/bin/python"
    assert calls[0][0][3:] == [installer.CLI_ENTRY_POINT_GROUP]
    assert plugins == [
        {
            "name": "demo",
            "entry_point": "demo_plugin:register_cli",
            "package": "demo-plugin",
            "version": "1.0.0",
        }
    ]


def test_list_cli_plugins_rejects_invalid_target_output():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="not-json", stderr="")

    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.list_cli_plugins(
            python_executable="/tmp/plugin-venv/bin/python",
            runner=runner,
        )

    assert "invalid plugin entry point inspection output" in str(excinfo.value)


def test_verify_cli_entry_point_reports_fresh_process_miss(monkeypatch):
    monkeypatch.setattr(installer, "resolve_cli_entry_point", lambda **kwargs: None)

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="")

    with pytest.raises(installer.PluginInstallError) as excinfo:
        installer.verify_cli_entry_point(
            entry_point="demo_plugin:register_cli",
            command_name="demo",
            runner=runner,
        )

    assert "installed plugin entry point was not found" in str(excinfo.value)
