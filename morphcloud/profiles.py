"""MorphCloud CLI profile workflows."""
from __future__ import annotations
import json
import shlex
from typing import Annotated
import click
from . import config

def _mask_secret(value: str | None) -> str | None:
    if not value:
        return value
    if len(value) <= 8:
        return '********'
    return f'{value[:4]}...{value[-4:]}'

def list_profiles() -> None:
    """List configured profiles."""
    cfg = config.load_config()
    profiles = cfg.get('profiles', {}) if isinstance(cfg, dict) else {}
    active = cfg.get('active_profile') if isinstance(cfg, dict) else None
    if not profiles:
        click.echo('No profiles configured.')
        return
    for name in sorted(profiles):
        prefix = '* ' if active == name else '  '
        click.echo(f'{prefix}{name}')

def current_profile() -> None:
    """Print the active profile."""
    cfg = config.load_config()
    active = cfg.get('active_profile') if isinstance(cfg, dict) else None
    click.echo(active if active else 'No active profile.')

def show_profile(name: str) -> None:
    """Show one profile with its API key masked."""
    profile = config.resolve_profile(name, config.load_config())
    if not profile:
        raise click.ClickException(f"Profile '{name}' not found.")
    display = dict(profile)
    if 'api_key' in display:
        display['api_key'] = _mask_secret(str(display.get('api_key') or ''))
    click.echo(json.dumps(display, indent=2))

def set_profile(name: str, api_key: str | None=None, base_url: str | None=None, api_host: str | None=None, ssh_hostname: str | None=None, ssh_port: int | None=None, service_base_url: str | None=None, volumes_base_url: str | None=None, admin_base_url: str | None=None, db_base_url: str | None=None, simple_index_base_url: str | None=None) -> None:
    """Create or update a profile."""
    updates = {'api_key': api_key, 'base_url': base_url, 'api_host': api_host, 'ssh_hostname': ssh_hostname, 'ssh_port': ssh_port, 'service_base_url': service_base_url, 'volumes_base_url': volumes_base_url, 'admin_base_url': admin_base_url, 'db_base_url': db_base_url, 'simple_index_base_url': simple_index_base_url}
    updates = {key: value for key, value in updates.items() if value is not None}
    if not updates:
        raise click.ClickException('No profile fields provided to set.')
    cfg = config.load_config()
    if not isinstance(cfg, dict):
        cfg = {}
    profiles = cfg.get('profiles')
    if not isinstance(profiles, dict):
        profiles = {}
    profile = profiles.get(name)
    if not isinstance(profile, dict):
        profile = {}
    profile.update(updates)
    profiles[name] = profile
    cfg['profiles'] = profiles
    cfg.setdefault('version', 1)
    config.save_config(cfg)
    click.echo(f"Profile '{name}' updated.")

def use_profile(name: str) -> None:
    """Set the active profile."""
    cfg = config.load_config()
    profiles = cfg.get('profiles', {}) if isinstance(cfg, dict) else {}
    if name not in profiles:
        raise click.ClickException(f"Profile '{name}' not found.")
    cfg['active_profile'] = name
    cfg.setdefault('version', 1)
    config.save_config(cfg)
    click.echo(f"Active profile set to '{name}'.")

def delete_profile(name: str) -> None:
    """Delete a configured profile."""
    cfg = config.load_config()
    if not isinstance(cfg, dict):
        raise click.ClickException(f"Profile '{name}' not found.")
    profiles = cfg.get('profiles', {})
    if not isinstance(profiles, dict) or name not in profiles:
        raise click.ClickException(f"Profile '{name}' not found.")
    profiles.pop(name, None)
    cfg['profiles'] = profiles
    if cfg.get('active_profile') == name:
        cfg.pop('active_profile', None)
    config.save_config(cfg)
    click.echo(f"Profile '{name}' deleted.")

def profile_environment(name: str | None=None, include_api_key: bool=True) -> None:
    """Render shell exports for a profile."""
    settings = config.resolve_settings(profile=name)
    for key, value in settings.as_env(include_api_key=include_api_key).items():
        click.echo(f'export {key}={shlex.quote(str(value))}')
