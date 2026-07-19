from __future__ import annotations

import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import typing
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

CLI_ENTRY_POINT_GROUP = "morphcloud.cli_plugins"
PYPI_SIMPLE_INDEX_URL = "https://pypi.org/simple"
EXTRA_INDEX_URL_ENV = "MORPH_PLUGIN_EXTRA_INDEX_URL"
DISABLE_EXTRA_INDEX_ENV = "MORPH_PLUGIN_DISABLE_EXTRA_INDEX"
_DEFAULT_EXTRA_INDEX = object()


class PluginInstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallerResult:
    command: list[str]
    stdout: str
    stderr: str


def build_install_command(
    requirement: str,
    *,
    index_url: str,
    extra_index_url: str | None | object = _DEFAULT_EXTRA_INDEX,
    upgrade: bool = False,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    which: typing.Callable[[str], str | None] = shutil.which,
) -> list[str]:
    _require_target(requirement, "package requirement")
    env = env or os.environ
    target_python = resolve_python_executable(
        python_executable=python_executable,
        venv=venv,
    )
    resolved_extra_index_url = _resolve_extra_index_url(
        env=env,
        extra_index_url=extra_index_url,
    )
    command = _base_pip_command(env=env, which=which, python_executable=target_python)
    command.append("install")
    _append_uv_python_target(command, python_executable=target_python)
    command.extend(["--index-url", index_url])
    if resolved_extra_index_url:
        command.extend(["--extra-index-url", resolved_extra_index_url])
    if upgrade:
        command.append("--upgrade")
    command.append(requirement)
    return command


def build_artifact_install_command(
    artifact_url: str,
    *,
    upgrade: bool = False,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    which: typing.Callable[[str], str | None] = shutil.which,
) -> list[str]:
    _require_target(artifact_url, "artifact URL")
    _reject_sensitive_artifact_url(artifact_url)
    target_python = resolve_python_executable(
        python_executable=python_executable,
        venv=venv,
    )
    command = _base_pip_command(env=env, which=which, python_executable=target_python)
    command.append("install")
    _append_uv_python_target(command, python_executable=target_python)
    if upgrade:
        command.append("--upgrade")
    command.append(artifact_url)
    return command


def build_uninstall_command(
    package_name: str,
    *,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    which: typing.Callable[[str], str | None] = shutil.which,
) -> list[str]:
    _require_target(package_name, "package name")
    target_python = resolve_python_executable(
        python_executable=python_executable,
        venv=venv,
    )
    command = _base_pip_command(env=env, which=which, python_executable=target_python)
    command.append("uninstall")
    _append_uv_python_target(command, python_executable=target_python)
    if not _is_uv_pip_command(command):
        command.append("-y")
    command.append(package_name)
    return command


def install_requirement(
    requirement: str,
    *,
    index_url: str,
    extra_index_url: str | None | object = _DEFAULT_EXTRA_INDEX,
    upgrade: bool = False,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    which: typing.Callable[[str], str | None] = shutil.which,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> InstallerResult:
    command = build_install_command(
        requirement,
        index_url=index_url,
        extra_index_url=extra_index_url,
        upgrade=upgrade,
        python_executable=python_executable,
        venv=venv,
        env=env,
        which=which,
    )
    secrets = [index_url]
    resolved_extra_index_url = _resolve_extra_index_url(
        env=env or os.environ,
        extra_index_url=extra_index_url,
    )
    if resolved_extra_index_url and resolved_extra_index_url != PYPI_SIMPLE_INDEX_URL:
        secrets.append(resolved_extra_index_url)
    return _run_installer(command, secrets=secrets, env=env, runner=runner)


def install_artifact(
    artifact_url: str,
    *,
    upgrade: bool = False,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    which: typing.Callable[[str], str | None] = shutil.which,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> InstallerResult:
    command = build_artifact_install_command(
        artifact_url,
        upgrade=upgrade,
        python_executable=python_executable,
        venv=venv,
        env=env,
        which=which,
    )
    return _run_installer(command, secrets=[artifact_url], env=env, runner=runner)


def uninstall_package(
    package_name: str,
    *,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    which: typing.Callable[[str], str | None] = shutil.which,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> InstallerResult:
    command = build_uninstall_command(
        package_name,
        python_executable=python_executable,
        venv=venv,
        env=env,
        which=which,
    )
    return _run_installer(command, secrets=[], env=env, runner=runner)


def resolve_cli_entry_point(
    *,
    entry_point: str | None = None,
    command_name: str | None = None,
) -> importlib.metadata.EntryPoint | None:
    entry_points = importlib.metadata.entry_points(group=CLI_ENTRY_POINT_GROUP)
    for candidate in entry_points:
        if entry_point and candidate.value == entry_point:
            return candidate
        if command_name and candidate.name == command_name:
            return candidate
    return None


def verify_cli_entry_point(
    *,
    entry_point: str | None = None,
    command_name: str | None = None,
    python_executable: str | None = None,
    venv: str | None = None,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    target_python = resolve_python_executable(
        python_executable=python_executable,
        venv=venv,
    )
    candidate = None
    if target_python is None:
        candidate = resolve_cli_entry_point(
            entry_point=entry_point,
            command_name=command_name,
        )
    if candidate is None:
        status, output = _verify_cli_entry_point_in_subprocess(
            entry_point=entry_point,
            command_name=command_name,
            python_executable=target_python,
            runner=runner,
        )
        if status == 0:
            return
        expected = entry_point or command_name or CLI_ENTRY_POINT_GROUP
        if status == 2:
            raise PluginInstallError(
                f"installed plugin entry point failed to load: {expected}"
                + (f"\n{output}" if output else "")
            )
        raise PluginInstallError(
            f"installed plugin entry point was not found: {expected}"
        )
    try:
        candidate.load()
    except Exception as exc:
        raise PluginInstallError(
            f"installed plugin entry point failed to load: {candidate.value}"
        ) from exc


def _verify_cli_entry_point_in_subprocess(
    *,
    entry_point: str | None,
    command_name: str | None,
    python_executable: str | None,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]],
) -> tuple[int, str]:
    script = """
import importlib.metadata
import sys

group, expected_value, expected_name = sys.argv[1:4]
for candidate in importlib.metadata.entry_points(group=group):
    if expected_value and candidate.value == expected_value:
        break
    if expected_name and candidate.name == expected_name:
        break
else:
    raise SystemExit(1)

try:
    candidate.load()
except Exception as exc:
    print(f"{candidate.value}: {exc}", file=sys.stderr)
    raise SystemExit(2)
"""
    process = runner(
        [
            python_executable or sys.executable,
            "-c",
            script,
            CLI_ENTRY_POINT_GROUP,
            entry_point or "",
            command_name or "",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(os.environ),
    )
    return process.returncode, (process.stderr or process.stdout or "").strip()


def verify_cli_help(
    command_name: str,
    *,
    python_executable: str | None = None,
    venv: str | None = None,
    env: typing.Mapping[str, str] | None = None,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    _require_target(command_name, "CLI command name")
    target_python = resolve_python_executable(
        python_executable=python_executable,
        venv=venv,
    )
    command = [
        target_python or sys.executable,
        "-m",
        "morphcloud.cli",
        command_name,
        "--help",
    ]
    process = runner(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(env or os.environ),
    )
    if process.returncode != 0:
        output = (process.stderr or process.stdout or "").strip()
        raise PluginInstallError(
            f"installed plugin command failed help verification: {command_name}"
            + (f"\n{output}" if output else "")
        )


def list_cli_plugins(
    *,
    python_executable: str | None = None,
    venv: str | None = None,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, str | None]]:
    target_python = resolve_python_executable(
        python_executable=python_executable,
        venv=venv,
    )
    if target_python is None:
        return _current_cli_plugins()
    script = """
import importlib.metadata
import json
import sys

group = sys.argv[1]
plugins = []
for entry_point in importlib.metadata.entry_points(group=group):
    dist = entry_point.dist
    metadata = getattr(dist, "metadata", None)
    plugins.append(
        {
            "name": entry_point.name,
            "entry_point": entry_point.value,
            "package": metadata.get("Name") if metadata is not None else None,
            "version": getattr(dist, "version", None),
        }
    )
print(json.dumps(sorted(plugins, key=lambda item: item["name"] or "")))
"""
    process = runner(
        [target_python, "-c", script, CLI_ENTRY_POINT_GROUP],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(os.environ),
    )
    if process.returncode != 0:
        output = (process.stderr or process.stdout or "").strip()
        raise PluginInstallError(
            "failed to inspect installed plugin entry points"
            + (f"\n{output}" if output else "")
        )
    try:
        payload = json.loads(process.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise PluginInstallError(
            "invalid plugin entry point inspection output"
        ) from exc
    if not isinstance(payload, list):
        raise PluginInstallError("invalid plugin entry point inspection output")
    return [_plugin_entry_payload(item) for item in payload]


def _base_pip_command(
    *,
    env: typing.Mapping[str, str] | None,
    which: typing.Callable[[str], str | None],
    python_executable: str | None,
) -> list[str]:
    env = env or os.environ
    uv = which("uv")
    in_virtualenv = _in_virtualenv(env)
    in_uv_run = _in_uv_run(env)
    if uv and python_executable:
        return [uv, "pip"]
    if uv and in_uv_run and not in_virtualenv:
        raise PluginInstallError(
            "Cannot install plugins from an ambiguous uv run environment. "
            "Activate a virtual environment, pass --python, or pass --venv, then "
            "rerun the plugin command."
        )
    if uv and in_virtualenv:
        return [uv, "pip"]
    return [python_executable or sys.executable, "-m", "pip"]


def _is_uv_pip_command(command: list[str]) -> bool:
    return (
        len(command) >= 2
        and os.path.basename(command[0]) == "uv"
        and command[1] == "pip"
    )


def _append_uv_python_target(
    command: list[str],
    *,
    python_executable: str | None,
) -> None:
    if _is_uv_pip_command(command):
        command.extend(["--python", python_executable or sys.executable])


def resolve_python_executable(
    *,
    python_executable: str | None = None,
    venv: str | None = None,
) -> str | None:
    python_executable = _clean_optional(python_executable)
    venv = _clean_optional(venv)
    if python_executable and venv:
        raise PluginInstallError("--python and --venv are mutually exclusive")
    if python_executable:
        return python_executable
    if not venv:
        return None
    venv_path = Path(venv).expanduser()
    if os.name == "nt":
        return str(venv_path / "Scripts" / "python.exe")
    return str(venv_path / "bin" / "python")


def _run_installer(
    command: list[str],
    *,
    secrets: list[str],
    env: typing.Mapping[str, str] | None,
    runner: typing.Callable[..., subprocess.CompletedProcess[str]],
) -> InstallerResult:
    process = runner(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=dict(env or os.environ),
    )
    stdout = _redact_text(process.stdout or "", secrets)
    stderr = _redact_text(process.stderr or "", secrets)
    if process.returncode != 0:
        rendered_command = " ".join(_redact_command(command, secrets))
        output = (stderr or stdout).strip()
        raise PluginInstallError(
            f"installer command failed ({process.returncode}): {rendered_command}"
            + (f"\n{output}" if output else "")
        )
    return InstallerResult(command=list(command), stdout=stdout, stderr=stderr)


def _redact_command(command: list[str], secrets: list[str]) -> list[str]:
    return [_redact_text(part, secrets) for part in command]


def _redact_text(value: str, secrets: list[str]) -> str:
    rendered = value
    for secret in secrets:
        if secret:
            rendered = rendered.replace(secret, "<redacted>")
    return rendered


def _require_target(value: str, label: str) -> None:
    if not str(value or "").strip():
        raise PluginInstallError(f"{label} is required")


def _reject_sensitive_artifact_url(value: str) -> None:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PluginInstallError(
            "artifact URLs with embedded credentials, query strings, or fragments "
            "cannot be installed directly; publish a package-backed plugin to the "
            "simple index instead"
        )


def _in_virtualenv(env: typing.Mapping[str, str]) -> bool:
    return bool(env.get("VIRTUAL_ENV")) or sys.prefix != sys.base_prefix


def _in_uv_run(env: typing.Mapping[str, str]) -> bool:
    return any(
        env.get(name)
        for name in (
            "UV_RUN_RECURSION_DEPTH",
            "UV_RUN_RECURSION_LIMIT",
            "UV_PROJECT_ENVIRONMENT",
        )
    )


def _resolve_extra_index_url(
    *,
    env: typing.Mapping[str, str],
    extra_index_url: str | None | object,
) -> str | None:
    if extra_index_url is not _DEFAULT_EXTRA_INDEX:
        return _clean_optional(str(extra_index_url)) if extra_index_url else None
    if _env_truthy(env.get(DISABLE_EXTRA_INDEX_ENV)):
        return None
    return _clean_optional(env.get(EXTRA_INDEX_URL_ENV)) or PYPI_SIMPLE_INDEX_URL


def _env_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _clean_optional(value: str | None) -> str | None:
    cleaned = str(value or "").strip()
    return cleaned or None


def _current_cli_plugins() -> list[dict[str, str | None]]:
    plugins = []
    for entry_point in importlib.metadata.entry_points(group=CLI_ENTRY_POINT_GROUP):
        dist = entry_point.dist
        plugins.append(
            {
                "name": entry_point.name,
                "entry_point": entry_point.value,
                "package": _dist_metadata(dist, "Name"),
                "version": getattr(dist, "version", None),
            }
        )
    return sorted(plugins, key=lambda item: item["name"] or "")


def _plugin_entry_payload(value: object) -> dict[str, str | None]:
    if not isinstance(value, dict):
        raise PluginInstallError("invalid plugin entry point inspection output")
    return {
        "name": _payload_str(value.get("name")),
        "entry_point": _payload_str(value.get("entry_point")),
        "package": _payload_str(value.get("package")),
        "version": _payload_str(value.get("version")),
    }


def _payload_str(value: object) -> str | None:
    if value is None:
        return None
    return _clean_optional(str(value))


def _dist_metadata(
    dist: importlib.metadata.Distribution | None,
    key: str,
) -> str | None:
    if dist is None:
        return None
    metadata = getattr(dist, "metadata", None)
    if metadata is None:
        return None
    return metadata.get(key)
