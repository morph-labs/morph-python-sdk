from __future__ import annotations

import importlib.metadata
import json
import re
import types
import typing
from pathlib import Path

import click

from morphcloud import config
from morphcloud.api import ApiError
from morphcloud.cli_helpers import format_json, get_client, print_docker_style_table
from morphcloud.plugins import installer as plugin_installer
from morphcloud.simple_index.client import PluginCatalogEntry, SimpleIndexClient


@click.group("plugin")
def plugin_group() -> None:
    """Manage installable Morph Cloud CLI plugins."""


@plugin_group.command("list")
@click.argument("query", required=False)
@click.option("--include-disabled", is_flag=True, help="Include disabled plugins.")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_list(
    query: str | None,
    include_disabled: bool,
    json_mode: bool,
) -> None:
    """List visible plugins."""
    try:
        entries = _filter_plugins(
            _simple_index_client().list_plugins(),
            query=query,
            include_disabled=include_disabled,
        )
        _print_plugins(entries, json_mode=json_mode)
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("search")
@click.argument("query", required=True)
@click.option("--include-disabled", is_flag=True, help="Include disabled plugins.")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_search(query: str, include_disabled: bool, json_mode: bool) -> None:
    """Search visible plugins."""
    try:
        entries = _filter_plugins(
            _simple_index_client().list_plugins(),
            query=query,
            include_disabled=include_disabled,
        )
        _print_plugins(entries, json_mode=json_mode)
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("show")
@click.argument("name", required=True)
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_show(name: str, json_mode: bool) -> None:
    """Show plugin details."""
    try:
        entry = _simple_index_client().get_plugin(name)
        if json_mode:
            click.echo(format_json(_redacted_entry_dict(entry)))
            return
        _print_plugins([entry], json_mode=False)
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("install")
@click.argument("name", required=True)
@click.option("--upgrade", is_flag=True, help="Upgrade if already installed.")
@click.option("--skip-verify", is_flag=True, help="Skip post-install CLI verification.")
@click.option(
    "--python",
    "python_executable",
    default=None,
    type=click.Path(dir_okay=False, path_type=str),
    help="Install into the selected Python executable.",
)
@click.option(
    "--venv",
    default=None,
    type=click.Path(file_okay=False, path_type=str),
    help="Install into the selected virtual environment.",
)
@click.option(
    "--dry-run", is_flag=True, help="Resolve the plugin without installing it."
)
def plugin_install(
    name: str,
    upgrade: bool,
    skip_verify: bool,
    python_executable: str | None,
    venv: str | None,
    dry_run: bool,
) -> None:
    """Install a plugin into the current Python environment."""
    try:
        target_python = plugin_installer.resolve_python_executable(
            python_executable=python_executable,
            venv=venv,
        )
        client = _simple_index_client()
        entry = client.get_plugin(name)
        _ensure_enabled(entry)
        target = _install_target(entry)
        if dry_run:
            _print_install_plan(
                "upgrade" if upgrade else "install",
                entry=entry,
                target=target,
                index_url=client.redacted_simple_index_url(),
                python_executable=target_python,
            )
            return
        with click.progressbar(
            length=1 if skip_verify else 2,
            label=f"Installing plugin '{entry.name}'",
            show_eta=False,
        ) as progress:
            if entry.artifact_url:
                plugin_installer.install_artifact(
                    entry.artifact_url,
                    upgrade=upgrade,
                    python_executable=target_python,
                )
            else:
                plugin_installer.install_requirement(
                    target,
                    index_url=client.authenticated_simple_index_url(),
                    upgrade=upgrade,
                    python_executable=target_python,
                )
            progress.update(1)
            if not skip_verify:
                _verify_installed(entry, python_executable=target_python)
                progress.update(1)
        click.echo(f"Installed plugin '{entry.name}' ({_redact_url(target)}).")
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("uninstall")
@click.argument("name", required=True)
@click.option(
    "--python",
    "python_executable",
    default=None,
    type=click.Path(dir_okay=False, path_type=str),
    help="Uninstall from the selected Python executable.",
)
@click.option(
    "--venv",
    default=None,
    type=click.Path(file_okay=False, path_type=str),
    help="Uninstall from the selected virtual environment.",
)
def plugin_uninstall(
    name: str,
    python_executable: str | None,
    venv: str | None,
) -> None:
    """Uninstall a plugin package from the current Python environment."""
    try:
        target_python = plugin_installer.resolve_python_executable(
            python_executable=python_executable,
            venv=venv,
        )
        entry = _simple_index_client().get_plugin(name)
        package_name = _uninstall_package_name(
            entry,
            python_executable=target_python,
        )
        plugin_installer.uninstall_package(
            package_name,
            python_executable=target_python,
        )
        click.echo(f"Uninstalled plugin '{entry.name}' ({package_name}).")
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("upgrade")
@click.argument("name", required=True)
@click.option("--skip-verify", is_flag=True, help="Skip post-upgrade CLI verification.")
@click.option(
    "--python",
    "python_executable",
    default=None,
    type=click.Path(dir_okay=False, path_type=str),
    help="Upgrade in the selected Python executable.",
)
@click.option(
    "--venv",
    default=None,
    type=click.Path(file_okay=False, path_type=str),
    help="Upgrade in the selected virtual environment.",
)
@click.option(
    "--dry-run", is_flag=True, help="Resolve the plugin without upgrading it."
)
def plugin_upgrade(
    name: str,
    skip_verify: bool,
    python_executable: str | None,
    venv: str | None,
    dry_run: bool,
) -> None:
    """Upgrade an installed plugin."""
    try:
        target_python = plugin_installer.resolve_python_executable(
            python_executable=python_executable,
            venv=venv,
        )
        client = _simple_index_client()
        entry = client.get_plugin(name)
        _ensure_enabled(entry)
        target = _install_target(entry)
        if dry_run:
            _print_install_plan(
                "upgrade",
                entry=entry,
                target=target,
                index_url=client.redacted_simple_index_url(),
                python_executable=target_python,
            )
            return
        with click.progressbar(
            length=1 if skip_verify else 2,
            label=f"Upgrading plugin '{entry.name}'",
            show_eta=False,
        ) as progress:
            if entry.artifact_url:
                plugin_installer.install_artifact(
                    entry.artifact_url,
                    upgrade=True,
                    python_executable=target_python,
                )
            else:
                plugin_installer.install_requirement(
                    target,
                    index_url=client.authenticated_simple_index_url(),
                    upgrade=True,
                    python_executable=target_python,
                )
            progress.update(1)
            if not skip_verify:
                _verify_installed(entry, python_executable=target_python)
                progress.update(1)
        click.echo(f"Upgraded plugin '{entry.name}' ({_redact_url(target)}).")
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("disable")
@click.argument("name", required=True)
@click.option("--visibility", type=click.Choice(["global", "org"]), default=None)
@click.option("--organization-id", default=None)
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_disable(
    name: str,
    visibility: str | None,
    organization_id: str | None,
    json_mode: bool,
) -> None:
    """Disable a plugin catalog entry."""
    try:
        visibility, organization_id = _scope_options(
            visibility=visibility,
            organization_id=organization_id,
        )
        entry = _simple_index_client().disable_plugin(
            name,
            visibility=visibility,
            organization_id=organization_id,
        )
        _print_mutation_result("Disabled", entry, json_mode=json_mode)
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("enable")
@click.argument("name", required=True)
@click.option("--visibility", type=click.Choice(["global", "org"]), default=None)
@click.option("--organization-id", default=None)
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_enable(
    name: str,
    visibility: str | None,
    organization_id: str | None,
    json_mode: bool,
) -> None:
    """Enable a plugin catalog entry."""
    try:
        client = _simple_index_client()
        current = client.get_plugin(name)
        manifest = current.to_dict()
        manifest["enabled"] = True
        visibility, organization_id = _scope_options_for_existing_entry(
            current,
            visibility=visibility,
            organization_id=organization_id,
        )
        _apply_scope_to_manifest(manifest, visibility, organization_id)
        entry = client.upsert_plugin(
            current.name,
            manifest,
            visibility=visibility,
            organization_id=organization_id,
        )
        _print_mutation_result("Enabled", entry, json_mode=json_mode)
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("register")
@click.argument("name", required=True)
@click.option("--manifest", "manifest_path", type=click.Path(dir_okay=False))
@click.option("--package-name", default=None)
@click.option("--version-spec", default=None)
@click.option("--artifact-url", default=None)
@click.option("--entry-point", default=None)
@click.option("--command-name", default=None)
@click.option("--display-name", default=None)
@click.option("--description", default=None)
@click.option("--version", "plugin_version", default=None)
@click.option("--visibility", type=click.Choice(["global", "org"]), default=None)
@click.option("--organization-id", default=None)
@click.option("--disabled", is_flag=True, help="Register the plugin as disabled.")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_register(
    name: str,
    manifest_path: str | None,
    package_name: str | None,
    version_spec: str | None,
    artifact_url: str | None,
    entry_point: str | None,
    command_name: str | None,
    display_name: str | None,
    description: str | None,
    plugin_version: str | None,
    visibility: str | None,
    organization_id: str | None,
    disabled: bool,
    json_mode: bool,
) -> None:
    """Register or update a plugin catalog entry."""
    try:
        manifest = _build_manifest(
            name=name,
            manifest_path=manifest_path,
            package_name=package_name,
            version_spec=version_spec,
            artifact_url=artifact_url,
            entry_point=entry_point,
            command_name=command_name,
            display_name=display_name,
            description=description,
            plugin_version=plugin_version,
            visibility=visibility,
            organization_id=organization_id,
            disabled=disabled,
        )
        visibility, organization_id = _scope_options_from_manifest(
            manifest,
            visibility=visibility,
            organization_id=organization_id,
        )
        _apply_scope_to_manifest(manifest, visibility, organization_id)
        entry = _simple_index_client().upsert_plugin(
            name,
            manifest,
            visibility=visibility,
            organization_id=organization_id,
        )
        _print_mutation_result("Registered", entry, json_mode=json_mode)
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("publish")
@click.argument("name", required=True)
@click.option("--wheel", type=click.Path(dir_okay=False, exists=True), required=True)
@click.option("--manifest", "manifest_path", type=click.Path(dir_okay=False))
@click.option("--package-name", default=None)
@click.option("--version-spec", default=None)
@click.option("--entry-point", default=None)
@click.option("--command-name", default=None)
@click.option("--display-name", default=None)
@click.option("--description", default=None)
@click.option("--version", "plugin_version", default=None)
@click.option("--visibility", type=click.Choice(["global", "org"]), default=None)
@click.option("--organization-id", default=None)
@click.option("--allow-overwrite", is_flag=True, help="Overwrite an existing wheel.")
@click.option(
    "--skip-existing-package",
    is_flag=True,
    help="Continue to catalog registration when the wheel already exists.",
)
@click.option("--disabled", is_flag=True, help="Register the plugin as disabled.")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_publish(
    name: str,
    wheel: str,
    manifest_path: str | None,
    package_name: str | None,
    version_spec: str | None,
    entry_point: str | None,
    command_name: str | None,
    display_name: str | None,
    description: str | None,
    plugin_version: str | None,
    visibility: str | None,
    organization_id: str | None,
    allow_overwrite: bool,
    skip_existing_package: bool,
    disabled: bool,
    json_mode: bool,
) -> None:
    """Upload a plugin wheel and register its catalog entry."""
    try:
        wheel_path = Path(wheel)
        derived_package_name, derived_version = _wheel_package_version(wheel_path)
        package_name = _validate_or_derive_wheel_package_name(
            package_name,
            derived_package_name,
        )
        plugin_version = _validate_or_derive_wheel_version(
            plugin_version,
            derived_version,
        )
        manifest = _build_manifest(
            name=name,
            manifest_path=manifest_path,
            package_name=package_name,
            version_spec=version_spec,
            artifact_url=None,
            entry_point=entry_point,
            command_name=command_name,
            display_name=display_name,
            description=description,
            plugin_version=plugin_version,
            visibility=visibility,
            organization_id=organization_id,
            disabled=disabled,
        )
        manifest.pop("artifact_url", None)
        manifest["package_name"] = package_name
        manifest["package"] = package_name
        if version_spec is None:
            manifest["version_spec"] = f"=={plugin_version}"
        visibility, organization_id = _scope_options_from_manifest(
            manifest,
            visibility=visibility,
            organization_id=organization_id,
        )
        if visibility is None:
            raise click.ClickException("--visibility is required for plugin publish.")
        _apply_scope_to_manifest(manifest, visibility, organization_id)

        client = _simple_index_client()
        package_status = "uploaded"
        package_payload: dict[str, typing.Any] | None
        try:
            package_payload = client.upload_package(
                wheel_path,
                project=package_name,
                allow_overwrite=allow_overwrite,
                visibility=visibility,
                organization_id=organization_id,
            )
        except ApiError as exc:
            if not (skip_existing_package and exc.status_code == 409):
                raise
            package_status = "skipped_existing"
            package_payload = None
            if not _package_file_is_visible(
                client.list_packages(),
                package_name=package_name,
                filename=wheel_path.name,
            ):
                raise click.ClickException(
                    "Package upload was skipped after a conflict, but the requested "
                    f"scope cannot see {package_name}/{wheel_path.name}. "
                    "Publish a new package version or upload the wheel to this scope "
                    "before registering the plugin."
                )

        entry = client.upsert_plugin(
            name,
            manifest,
            visibility=visibility,
            organization_id=organization_id,
        )
        if json_mode:
            click.echo(
                format_json(
                    {
                        "package_status": package_status,
                        "package": package_payload,
                        "plugin": _redacted_entry_dict(entry),
                    }
                )
            )
            return
        if package_status == "skipped_existing":
            click.echo("Package already exists; continuing to catalog registration.")
        else:
            uploaded_name = (
                str(package_payload.get("filename"))
                if package_payload and package_payload.get("filename")
                else wheel_path.name
            )
            click.echo(f"Uploaded package '{uploaded_name}'.")
        click.echo(f"Published plugin '{entry.name}'.")
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("delete")
@click.argument("name", required=True)
@click.option("--visibility", type=click.Choice(["global", "org"]), default=None)
@click.option("--organization-id", default=None)
@click.option("--yes", is_flag=True, help="Do not prompt for confirmation.")
def plugin_delete(
    name: str,
    visibility: str | None,
    organization_id: str | None,
    yes: bool,
) -> None:
    """Delete a plugin catalog entry."""
    try:
        if not yes:
            click.confirm(f"Delete plugin '{name}'?", abort=True)
        visibility, organization_id = _scope_options(
            visibility=visibility,
            organization_id=organization_id,
        )
        _simple_index_client().delete_plugin(
            name,
            visibility=visibility,
            organization_id=organization_id,
        )
        click.echo(f"Deleted plugin '{name}'.")
    except Exception as exc:
        _raise_click_error(exc)


@plugin_group.command("doctor")
@click.option("--json", "json_mode", is_flag=True, help="Output JSON.")
def plugin_doctor(json_mode: bool) -> None:
    """Report plugin configuration and registration status."""
    try:
        settings = _resolve_current_settings()
        simple_index = _simple_index_client_for_settings(settings)
        installed = _installed_cli_plugins()
        catalog_plugins, catalog_status, catalog_error = _catalog_plugin_statuses(
            simple_index,
            installed,
            api_key=settings.api_key,
        )
        report = {
            "profile": settings.profile,
            "simple_index_url": simple_index.redacted_simple_index_url(),
            "auth_configured": bool(settings.api_key),
            "auth_status": "configured" if settings.api_key else "missing",
            "catalog_status": catalog_status,
            "catalog_error": catalog_error,
            "catalog_plugins": catalog_plugins,
            "installed_cli_plugins": installed,
        }
        if json_mode:
            click.echo(format_json(report))
            return
        click.echo(f"Profile: {report['profile'] or '(default)'}")
        click.echo(f"Simple index: {report['simple_index_url']}")
        click.echo(f"Auth: {report['auth_status']}")
        if catalog_status == "ok":
            click.echo(f"Catalog: ok ({len(catalog_plugins)} visible plugins)")
        elif catalog_status == "skipped":
            click.echo("Catalog: skipped (MORPH_API_KEY is not configured)")
        else:
            click.echo(f"Catalog: error ({catalog_error})")
        if catalog_plugins:
            print_docker_style_table(
                [
                    "Name",
                    "Package",
                    "Installed",
                    "Entry Point",
                    "Command",
                    "Enabled",
                    "Visibility",
                ],
                [
                    [
                        item["name"],
                        item["package_name"] or "",
                        item["installed_version"] or "no",
                        _status_label(item["entry_point_registered"]),
                        _status_label(item["command_registered"]),
                        "yes" if item["enabled"] else "no",
                        item["visibility"] or "",
                    ]
                    for item in catalog_plugins
                ],
            )
        if installed:
            click.echo("Installed CLI entry points:")
            print_docker_style_table(
                ["Name", "Entry Point", "Package", "Version"],
                [
                    [
                        item["name"],
                        item["entry_point"],
                        item["package"],
                        item["version"],
                    ]
                    for item in installed
                ],
            )
        else:
            click.echo("No installed CLI plugins found.")
    except Exception as exc:
        _raise_click_error(exc)


plugin_group.add_command(plugin_show, "info")
plugin_group.add_command(plugin_upgrade, "update")


def register_cli_plugin(cli_group: click.Group) -> None:
    cli_group.add_command(plugin_group)


def _simple_index_client() -> SimpleIndexClient:
    return get_client().simple_index


def _resolve_current_settings() -> config.ResolvedSettings:
    ctx = click.get_current_context(silent=True)
    obj = getattr(ctx, "obj", None) or {}
    profile = obj.get("profile") if isinstance(obj, dict) else None
    return config.resolve_settings(profile=profile)


def _simple_index_client_for_settings(
    settings: config.ResolvedSettings,
) -> SimpleIndexClient:
    client = typing.cast(
        typing.Any,
        types.SimpleNamespace(
            api_key=settings.api_key,
            simple_index_base_url=settings.simple_index_base_url,
        ),
    )
    return SimpleIndexClient(client)


def _filter_plugins(
    entries: list[PluginCatalogEntry],
    *,
    query: str | None,
    include_disabled: bool,
) -> list[PluginCatalogEntry]:
    filtered = [entry for entry in entries if include_disabled or entry.enabled]
    if query:
        needle = query.lower()
        filtered = [
            entry
            for entry in filtered
            if needle in entry.name.lower()
            or needle in (entry.package_name or "").lower()
            or needle in (entry.artifact_url or "").lower()
            or needle in (entry.command_name or "").lower()
        ]
    return sorted(filtered, key=lambda item: item.name)


def _print_plugins(entries: list[PluginCatalogEntry], *, json_mode: bool) -> None:
    if json_mode:
        click.echo(format_json([_redacted_entry_dict(entry) for entry in entries]))
        return
    if not entries:
        click.echo("No plugins found.")
        return
    print_docker_style_table(
        ["Name", "Package", "Version", "Command", "Visibility", "Enabled", "Source"],
        [
            [
                entry.name,
                _display_package_or_artifact(entry),
                entry.version_spec or "",
                entry.command_name or "",
                entry.visibility or "",
                "yes" if entry.enabled else "no",
                entry.source or "",
            ]
            for entry in entries
        ],
    )


def _print_mutation_result(
    action: str,
    entry: PluginCatalogEntry,
    *,
    json_mode: bool,
) -> None:
    if json_mode:
        click.echo(format_json(_redacted_entry_dict(entry)))
        return
    click.echo(f"{action} plugin '{entry.name}'.")


def _print_install_plan(
    action: str,
    *,
    entry: PluginCatalogEntry,
    target: str,
    index_url: str,
    python_executable: str | None,
) -> None:
    click.echo(f"Would {action} plugin '{entry.name}' ({_redact_url(target)}).")
    if python_executable:
        click.echo(f"Python: {python_executable}")
    if entry.artifact_url:
        click.echo(f"Artifact: {_redact_url(entry.artifact_url)}")
    else:
        click.echo(f"Package index: {index_url}")
    if entry.command_name:
        click.echo(f"Command: morphcloud {entry.command_name}")


def _build_manifest(
    *,
    name: str,
    manifest_path: str | None,
    package_name: str | None,
    version_spec: str | None,
    artifact_url: str | None,
    entry_point: str | None,
    command_name: str | None,
    display_name: str | None,
    description: str | None,
    plugin_version: str | None,
    visibility: str | None,
    organization_id: str | None,
    disabled: bool,
) -> dict[str, typing.Any]:
    manifest: dict[str, typing.Any] = {}
    if manifest_path:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise click.ClickException("Plugin manifest must be a JSON object.")
        manifest.update(data)

    explicit = {
        "name": name,
        "package_name": package_name,
        "version_spec": version_spec,
        "artifact_url": artifact_url,
        "entry_point": entry_point,
        "command_name": command_name,
        "display_name": display_name,
        "description": description,
        "version": plugin_version,
        "visibility": visibility,
        "organization_id": organization_id,
    }
    manifest.update(
        {key: value for key, value in explicit.items() if value is not None}
    )
    if disabled:
        manifest["enabled"] = False
    elif "enabled" not in manifest:
        manifest["enabled"] = True
    if "version" not in manifest:
        raise click.ClickException(
            "--version is required when the manifest omits version."
        )
    if (
        "package_name" not in manifest
        and "package" not in manifest
        and "artifact_url" not in manifest
    ):
        raise click.ClickException(
            "--package-name or --artifact-url is required when the manifest omits an install target."
        )
    return manifest


def _scope_options_from_manifest(
    manifest: dict[str, typing.Any],
    *,
    visibility: str | None,
    organization_id: str | None,
) -> tuple[str | None, str | None]:
    resolved_visibility = _clean_optional(visibility) or _clean_optional(
        manifest.get("visibility")
    )
    resolved_organization_id = _clean_optional(organization_id) or _clean_optional(
        manifest.get("organization_id")
    )
    return _scope_options(
        visibility=resolved_visibility,
        organization_id=resolved_organization_id,
    )


def _scope_options_for_existing_entry(
    entry: PluginCatalogEntry,
    *,
    visibility: str | None,
    organization_id: str | None,
) -> tuple[str | None, str | None]:
    if visibility is not None or organization_id is not None:
        return _scope_options(visibility=visibility, organization_id=organization_id)
    return _scope_options(
        visibility=entry.visibility,
        organization_id=entry.organization_id,
    )


def _scope_options(
    *,
    visibility: str | None,
    organization_id: str | None,
) -> tuple[str | None, str | None]:
    visibility = _clean_optional(visibility)
    organization_id = _clean_optional(organization_id)
    if visibility is None and organization_id:
        visibility = "org"
    if visibility is not None and visibility not in {"global", "org"}:
        raise click.ClickException("visibility must be global or org.")
    if visibility == "org" and not organization_id:
        raise click.ClickException(
            "--organization-id is required when --visibility is org."
        )
    if visibility == "global" and organization_id:
        raise click.ClickException(
            "--organization-id cannot be used when --visibility is global."
        )
    return visibility, organization_id


def _package_file_is_visible(
    package_payload: dict[str, typing.Any],
    *,
    package_name: str,
    filename: str,
) -> bool:
    normalized_package = _normalize_project_name(package_name)
    for project in package_payload.get("data", []):
        if (
            _normalize_project_name(str(project.get("project", "")))
            != normalized_package
        ):
            continue
        for file_payload in project.get("files", []):
            if file_payload.get("filename") == filename:
                return True
    return False


def _apply_scope_to_manifest(
    manifest: dict[str, typing.Any],
    visibility: str | None,
    organization_id: str | None,
) -> None:
    if visibility is None:
        return
    manifest["visibility"] = visibility
    if organization_id is None:
        manifest.pop("organization_id", None)
    else:
        manifest["organization_id"] = organization_id


def _wheel_package_version(wheel: Path) -> tuple[str, str]:
    filename = wheel.name
    if not filename.endswith(".whl"):
        raise click.ClickException("--wheel must point to a .whl file.")
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        raise click.ClickException(f"Invalid wheel filename: {filename}")
    return _normalize_project_name(parts[0]), parts[1]


def _validate_or_derive_wheel_package_name(
    package_name: str | None,
    derived_package_name: str,
) -> str:
    package_name = _clean_optional(package_name)
    if package_name is None:
        return derived_package_name
    if _normalize_project_name(package_name) != derived_package_name:
        raise click.ClickException(
            "wheel filename package mismatch: "
            f"expected {package_name}, got {derived_package_name}"
        )
    return package_name


def _validate_or_derive_wheel_version(
    plugin_version: str | None,
    derived_version: str,
) -> str:
    plugin_version = _clean_optional(plugin_version)
    if plugin_version is None:
        return derived_version
    if plugin_version != derived_version:
        raise click.ClickException(
            "wheel filename version mismatch: "
            f"expected {plugin_version}, got {derived_version}"
        )
    return plugin_version


def _normalize_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _clean_optional(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _ensure_enabled(entry: PluginCatalogEntry) -> None:
    if not entry.enabled:
        raise click.ClickException(f"Plugin '{entry.name}' is disabled.")


def _install_target(entry: PluginCatalogEntry) -> str:
    target = entry.install_target
    if not target:
        raise click.ClickException(
            f"Plugin '{entry.name}' does not define an install target."
        )
    return target


def _package_name(entry: PluginCatalogEntry) -> str:
    if not entry.package_name:
        raise click.ClickException(
            f"Plugin '{entry.name}' does not define package_name."
        )
    return entry.package_name


def _uninstall_package_name(
    entry: PluginCatalogEntry,
    *,
    python_executable: str | None = None,
) -> str:
    if entry.package_name:
        return entry.package_name
    matching_cli_entry = _matching_installed_cli_entry(
        entry,
        _installed_cli_plugins(python_executable=python_executable),
    )
    package_name = matching_cli_entry.get("package") if matching_cli_entry else None
    if package_name:
        return package_name
    raise click.ClickException(
        f"Plugin '{entry.name}' does not define package_name and no installed CLI "
        "entry point identifies its package."
    )


def _verify_installed(
    entry: PluginCatalogEntry,
    *,
    python_executable: str | None = None,
) -> None:
    plugin_installer.verify_cli_entry_point(
        entry_point=entry.entry_point,
        command_name=entry.command_name,
        python_executable=python_executable,
    )
    if entry.command_name:
        plugin_installer.verify_cli_help(
            entry.command_name,
            python_executable=python_executable,
        )


def _installed_cli_plugins(
    *,
    python_executable: str | None = None,
) -> list[dict[str, str | None]]:
    return plugin_installer.list_cli_plugins(python_executable=python_executable)


def _catalog_plugin_statuses(
    simple_index: SimpleIndexClient,
    installed: list[dict[str, str | None]],
    *,
    api_key: str | None,
) -> tuple[list[dict[str, typing.Any]], str, str | None]:
    if not api_key:
        return [], "skipped", "MORPH_API_KEY is not configured"
    try:
        entries = simple_index.list_plugins()
    except Exception as exc:
        return [], "error", _redact_diagnostic(str(exc), [api_key])
    return (
        [
            _catalog_plugin_status(entry, installed)
            for entry in sorted(entries, key=lambda item: item.name)
        ],
        "ok",
        None,
    )


def _catalog_plugin_status(
    entry: PluginCatalogEntry,
    installed: list[dict[str, str | None]],
) -> dict[str, typing.Any]:
    matching_cli_entry = _matching_installed_cli_entry(entry, installed)
    installed_version = (
        _installed_package_version(entry.package_name) if entry.package_name else None
    )
    if installed_version is None and matching_cli_entry is not None:
        installed_version = matching_cli_entry.get("version")
    installed_package = entry.package_name
    if installed_package is None and matching_cli_entry is not None:
        installed_package = matching_cli_entry.get("package")
    command_registered = (
        _has_installed_cli_command(entry.command_name, installed)
        if entry.command_name
        else None
    )
    entry_point_registered = (
        _has_installed_cli_entry_point(entry.entry_point, installed)
        if entry.entry_point
        else None
    )
    return {
        "name": entry.name,
        "package_name": entry.package_name,
        "version_spec": entry.version_spec,
        "artifact_url": _redact_url(entry.artifact_url) if entry.artifact_url else None,
        "enabled": entry.enabled,
        "entry_point": entry.entry_point,
        "command_name": entry.command_name,
        "visibility": entry.visibility,
        "organization_id": entry.organization_id,
        "source": entry.source,
        "installed": bool(installed_version or matching_cli_entry),
        "installed_package": installed_package,
        "installed_version": installed_version,
        "entry_point_registered": entry_point_registered,
        "command_registered": command_registered,
    }


def _matching_installed_cli_entry(
    entry: PluginCatalogEntry,
    installed: list[dict[str, str | None]],
) -> dict[str, str | None] | None:
    for item in installed:
        if entry.entry_point and item.get("entry_point") == entry.entry_point:
            return item
        if entry.command_name and item.get("name") == entry.command_name:
            return item
    return None


def _has_installed_cli_entry_point(
    entry_point: str,
    installed: list[dict[str, str | None]],
) -> bool:
    return any(item.get("entry_point") == entry_point for item in installed)


def _has_installed_cli_command(
    command_name: str,
    installed: list[dict[str, str | None]],
) -> bool:
    return any(item.get("name") == command_name for item in installed)


def _installed_package_version(package_name: str | None) -> str | None:
    if not package_name:
        return None
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _redact_diagnostic(value: str, secrets: list[str | None]) -> str:
    rendered = _redact_urls_in_text(value)
    for secret in secrets:
        if secret:
            rendered = rendered.replace(secret, "<redacted>")
    return rendered


def _redacted_entry_dict(entry: PluginCatalogEntry) -> dict[str, typing.Any]:
    data = entry.to_dict()
    artifact_url = data.get("artifact_url")
    if artifact_url:
        data["artifact_url"] = _redact_url(str(artifact_url))
    return data


def _display_package_or_artifact(entry: PluginCatalogEntry) -> str:
    if entry.package_name:
        return entry.package_name
    if entry.artifact_url:
        return _redact_url(entry.artifact_url)
    return ""


def _redact_url(value: str | None) -> str:
    if not value:
        return ""
    if "://" not in value:
        return value
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(value)
    has_sensitive_parts = "@" in parsed.netloc or bool(parsed.query or parsed.fragment)
    if not has_sensitive_parts:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"<redacted>@{host}" if "@" in parsed.netloc else host
    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            "<redacted>" if parsed.query else "",
            "<redacted>" if parsed.fragment else "",
        )
    )


_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _redact_urls_in_text(value: str) -> str:
    return _URL_RE.sub(lambda match: _redact_url(match.group(0)), value)


def _status_label(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "n/a"


def _raise_click_error(exc: Exception) -> typing.NoReturn:
    if isinstance(exc, click.ClickException):
        raise exc
    if isinstance(exc, KeyError):
        name = exc.args[0] if exc.args else "plugin"
        raise click.ClickException(f"Plugin '{name}' not found.") from exc
    secrets: list[str | None] = []
    try:
        secrets.append(_resolve_current_settings().api_key)
    except Exception:
        pass
    raise click.ClickException(_redact_diagnostic(str(exc), secrets)) from exc
