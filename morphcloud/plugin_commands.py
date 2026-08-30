"""Ontology declarations for Morph Cloud plugin-management workflows."""
from __future__ import annotations
from pathlib import Path
from typing import Annotated, Any, Literal
from .plugins import cli as implementation
from .simple_index.client import PluginCatalogEntry

def _call(command: Any, **values: Any) -> None:
    command.callback(**values)

def list_plugins(query: str | None=None, include_disabled: bool=False, json_mode: bool=False) -> None:
    """List visible plugins."""
    _call(implementation.plugin_list, query=query, include_disabled=include_disabled, json_mode=json_mode)

def search_plugins(query: str, include_disabled: bool=False, json_mode: bool=False) -> None:
    """Search visible plugins."""
    _call(implementation.plugin_search, query=query, include_disabled=include_disabled, json_mode=json_mode)

def show_plugin(name: str, json_mode: bool=False) -> None:
    """Show plugin details."""
    _call(implementation.plugin_show, name=name, json_mode=json_mode)

def install_plugin(name: str, upgrade: bool=False, skip_verify: bool=False, python_executable: str | None=None, venv: str | None=None, dry_run: bool=False) -> None:
    """Install a plugin into the current Python environment."""
    _call(implementation.plugin_install, name=name, upgrade=upgrade, skip_verify=skip_verify, python_executable=python_executable, venv=venv, dry_run=dry_run)

def uninstall_plugin(name: str, python_executable: str | None=None, venv: str | None=None) -> None:
    """Uninstall a plugin package from the current Python environment."""
    _call(implementation.plugin_uninstall, name=name, python_executable=python_executable, venv=venv)

def upgrade_plugin(name: str, skip_verify: bool=False, python_executable: str | None=None, venv: str | None=None, dry_run: bool=False) -> None:
    """Upgrade an installed plugin."""
    _call(implementation.plugin_upgrade, name=name, skip_verify=skip_verify, python_executable=python_executable, venv=venv, dry_run=dry_run)

def disable_plugin(name: str, visibility: Literal['global', 'org'] | None=None, organization_id: str | None=None, json_mode: bool=False) -> None:
    """Disable a plugin catalog entry."""
    _call(implementation.plugin_disable, name=name, visibility=visibility, organization_id=organization_id, json_mode=json_mode)

def enable_plugin(name: str, visibility: Literal['global', 'org'] | None=None, organization_id: str | None=None, json_mode: bool=False) -> None:
    """Enable a plugin catalog entry."""
    _call(implementation.plugin_enable, name=name, visibility=visibility, organization_id=organization_id, json_mode=json_mode)

def _catalog_values(*, name: str, manifest_path: Path | None, package_name: str | None, version_spec: str | None, artifact_url: str | None, entry_point: str | None, command_name: str | None, display_name: str | None, description: str | None, plugin_version: str | None, visibility: str | None, organization_id: str | None, disabled: bool, json_mode: bool) -> dict[str, Any]:
    return {'name': name, 'manifest_path': str(manifest_path) if manifest_path is not None else None, 'package_name': package_name, 'version_spec': version_spec, 'artifact_url': artifact_url, 'entry_point': entry_point, 'command_name': command_name, 'display_name': display_name, 'description': description, 'plugin_version': plugin_version, 'visibility': visibility, 'organization_id': organization_id, 'disabled': disabled, 'json_mode': json_mode}

def register_plugin(name: str, manifest_path: Path | None=None, package_name: str | None=None, version_spec: str | None=None, artifact_url: str | None=None, entry_point: str | None=None, command_name: str | None=None, display_name: str | None=None, description: str | None=None, plugin_version: str | None=None, visibility: Literal['global', 'org'] | None=None, organization_id: str | None=None, disabled: bool=False, json_mode: bool=False) -> None:
    """Register or update a plugin catalog entry."""
    _call(implementation.plugin_register, **_catalog_values(name=name, manifest_path=manifest_path, package_name=package_name, version_spec=version_spec, artifact_url=artifact_url, entry_point=entry_point, command_name=command_name, display_name=display_name, description=description, plugin_version=plugin_version, visibility=visibility, organization_id=organization_id, disabled=disabled, json_mode=json_mode))

def publish_plugin(name: str, wheel: Path, manifest_path: Path | None=None, package_name: str | None=None, version_spec: str | None=None, entry_point: str | None=None, command_name: str | None=None, display_name: str | None=None, description: str | None=None, plugin_version: str | None=None, visibility: Literal['global', 'org'] | None=None, organization_id: str | None=None, allow_overwrite: bool=False, skip_existing_package: bool=False, disabled: bool=False, json_mode: bool=False) -> None:
    """Upload a plugin wheel and register its catalog entry."""
    values = _catalog_values(name=name, manifest_path=manifest_path, package_name=package_name, version_spec=version_spec, artifact_url=None, entry_point=entry_point, command_name=command_name, display_name=display_name, description=description, plugin_version=plugin_version, visibility=visibility, organization_id=organization_id, disabled=disabled, json_mode=json_mode)
    values.pop('artifact_url')
    values.update(wheel=str(wheel), allow_overwrite=allow_overwrite, skip_existing_package=skip_existing_package)
    _call(implementation.plugin_publish, **values)

def delete_plugin(name: str, visibility: Literal['global', 'org'] | None=None, organization_id: str | None=None, yes: bool=False) -> None:
    """Delete a plugin catalog entry."""
    _call(implementation.plugin_delete, name=name, visibility=visibility, organization_id=organization_id, yes=yes)

def doctor_plugins(json_mode: bool=False) -> None:
    """Report plugin configuration and registration status."""
    _call(implementation.plugin_doctor, json_mode=json_mode)
