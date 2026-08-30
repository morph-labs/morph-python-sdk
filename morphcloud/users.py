"""Authenticated-user resources, workflows, and terminal presentation."""
from __future__ import annotations
import datetime
import json
import sys
from pathlib import Path
from typing import Annotated, Any
import click
from .api import APIKey, CreateAPIKeyResponse, ManagedSSHKey, Secret, UserSSHKey, UserUsageOverview
from .cli_helpers import format_json, print_docker_style_table
from .cli_runtime import MorphRuntimeContext

def _timestamp(value: Any) -> str:
    if value is None or not isinstance(value, (int, float)):
        return 'N/A'
    try:
        return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    except (OSError, TypeError, ValueError):
        return 'Invalid Timestamp'

def _status(value: Any) -> str:
    return str(getattr(value, 'value', value))

def render_api_key_list(result: list[APIKey], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    if inputs.get('json_mode'):
        for key in result:
            click.echo(format_json(key))
        return
    print_docker_style_table(['ID', 'Prefix', 'Created', 'Last Used'], [[key.id, key.key_prefix, _timestamp(key.created), _timestamp(key.last_used)] for key in result])

def render_api_key_created(result: CreateAPIKeyResponse, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    click.secho('API key created.', fg='green', bold=True)
    click.echo(f'ID: {result.id}')
    click.echo(f'Prefix: {result.key_prefix}')
    click.echo(f'Created: {_timestamp(result.created)}')
    click.secho('This is your API key — it will not be shown again:', fg='yellow')
    click.secho(result.key, fg='yellow')

def list_api_keys(ctx: MorphRuntimeContext, json_mode: bool=False) -> list[APIKey]:
    """List API keys."""
    return ctx.client.user.list_api_keys()

def create_api_key(ctx: MorphRuntimeContext) -> CreateAPIKeyResponse:
    """Create a new API key."""
    return ctx.client.user.create_api_key()

def delete_api_key(ctx: MorphRuntimeContext, api_key_id: str) -> None:
    """Delete an API key."""
    ctx.client.user.delete_api_key(api_key_id)

def render_secret_list(result: list[Secret], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    if inputs.get('json_mode'):
        for secret in result:
            click.echo(format_json(secret))
        return
    rows = []
    for secret in result:
        metadata = ', '.join((f'{key}={value}' for key, value in secret.metadata.items()))
        rows.append([secret.name, secret.description or '', metadata, _timestamp(secret.created), _timestamp(secret.updated)])
    print_docker_style_table(['Name', 'Description', 'Metadata', 'Created', 'Updated'], rows)

def render_secret_created(result: Secret, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    click.secho('Secret created.', fg='green', bold=True)
    click.echo(f'Name: {result.name}')
    click.echo(f'Created: {_timestamp(result.created)}')

def list_secrets(ctx: MorphRuntimeContext, json_mode: bool=False) -> list[Secret]:
    """List user secrets without revealing their values."""
    return ctx.client.user.list_secrets()

def create_secret(ctx: MorphRuntimeContext, name: str, value: str | None=None, value_stdin: bool=False, description: str | None=None, metadata: dict[str, str] | None=None) -> Secret:
    """Create or replace a user secret."""
    if value_stdin and value is not None:
        raise click.ClickException('Use either --value or --value-stdin, not both.')
    if value_stdin:
        value = sys.stdin.read()
    if value is None:
        if sys.stdin.isatty():
            value = click.prompt('Secret value', hide_input=True, confirmation_prompt=True)
        else:
            raise click.ClickException('Secret value is required. Provide --value or pipe via --value-stdin.')
    return ctx.client.user.create_secret(name=name, value=value, description=description, metadata=metadata)

def delete_secret(ctx: MorphRuntimeContext, name: str) -> None:
    """Delete a user secret."""
    ctx.client.user.delete_secret(name)

def _read_public_key(public_key: str | None, public_key_file: Path | None) -> str:
    if public_key is not None and public_key_file is not None:
        raise click.ClickException('Use either --public-key or --public-key-file, not both.')
    if public_key_file is not None:
        if public_key_file.suffix.lower() != '.pub':
            raise click.ClickException('--public-key-file must point to a public .pub file, never a private key.')
        try:
            public_key = public_key_file.read_text(encoding='utf-8')
        except (OSError, UnicodeError) as exc:
            raise click.ClickException(f'Could not read public-key file: {exc}') from exc
    if public_key is None:
        raise click.ClickException('Provide the public key with --public-key or --public-key-file.')
    value = public_key.strip()
    if not value:
        raise click.ClickException('SSH public key cannot be empty.')
    if 'PRIVATE KEY' in value:
        raise click.ClickException('Private keys are not accepted. Provide only the public .pub value.')
    if '\n' in value or '\r' in value:
        raise click.ClickException('Provide exactly one SSH public key.')
    return value

def _parse_expiry(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise click.BadParameter('must be Unix seconds or an ISO 8601 datetime', param_hint="'--expires'") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return int(parsed.timestamp())

def render_ssh_key_list(result: list[ManagedSSHKey], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    print_docker_style_table(['ID', 'Name', 'Algorithm', 'Fingerprint', 'Status', 'Created', 'Last Used', 'Expires'], [[key.id, key.name, key.algorithm, key.fingerprint, _status(key.status), _timestamp(key.created), _timestamp(key.last_used), _timestamp(key.expires)] for key in result])

def render_ssh_key_detail(result: ManagedSSHKey | UserSSHKey, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    if isinstance(result, ManagedSSHKey):
        print_docker_style_table(['ID', 'Name', 'Algorithm', 'Fingerprint', 'Status', 'Created', 'Updated', 'Last Used', 'Expires', 'Revoked'], [[result.id, result.name, result.algorithm, result.fingerprint, _status(result.status), _timestamp(result.created), _timestamp(result.updated), _timestamp(result.last_used), _timestamp(result.expires), _timestamp(result.revoked)]])
        return
    print_docker_style_table(['Public Key', 'Created'], [[result.public_key, _timestamp(result.created)]])

def render_ssh_key_created(result: ManagedSSHKey, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    click.secho('SSH public key added.', fg='green', bold=True)
    click.echo(f'ID: {result.id}')
    click.echo(f'Name: {result.name}')
    click.echo(f'Fingerprint: {result.fingerprint}')

def render_ssh_key_edited(result: ManagedSSHKey, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    click.secho('SSH public key edited.', fg='green', bold=True)
    click.echo(f'ID: {result.id}')
    click.echo(f'Name: {result.name}')
    click.echo(f'Expires: {_timestamp(result.expires)}')

def render_legacy_ssh_key_set(result: UserSSHKey, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    click.secho('SSH key updated.', fg='green', bold=True)
    click.echo(f'Created: {_timestamp(result.created)}')

def list_ssh_keys(ctx: MorphRuntimeContext) -> list[ManagedSSHKey]:
    """List managed SSH public keys."""
    return ctx.client.user.list_ssh_keys()

def get_ssh_key(ctx: MorphRuntimeContext, ssh_key_id: str | None=None) -> ManagedSSHKey | UserSSHKey:
    """Get a managed key by ID, or the legacy singular key when ID is omitted."""
    if ssh_key_id is not None:
        return ctx.client.user.get_managed_ssh_key(ssh_key_id)
    return ctx.client.user.get_ssh_key()

def add_ssh_key(ctx: MorphRuntimeContext, name: str, public_key: str | None=None, public_key_file: Path | None=None, expires: str | None=None) -> ManagedSSHKey:
    """Add a managed SSH public key."""
    key_value = _read_public_key(public_key, public_key_file)
    expiry = _parse_expiry(expires)
    return ctx.client.user.add_ssh_key(name=name, public_key=key_value, expires=expiry)

def edit_ssh_key(ctx: MorphRuntimeContext, ssh_key_id: str, name: str | None=None, expires: str | None=None, clear_expiry: bool=False) -> ManagedSSHKey:
    """Edit a managed key's name or expiry; public material is immutable."""
    parsed_expiry = _parse_expiry(expires)
    if name is None and parsed_expiry is None and (not clear_expiry):
        raise click.ClickException('Provide at least one of --name, --expires, or --clear-expiry.')
    if parsed_expiry is not None and clear_expiry:
        raise click.ClickException('Use either --expires or --clear-expiry, not both.')
    return ctx.client.user.edit_ssh_key(ssh_key_id, name=name, expires=parsed_expiry, clear_expiry=clear_expiry)

def revoke_ssh_key(ctx: MorphRuntimeContext, ssh_key_id: str, yes: bool=False) -> None:
    """Revoke one managed key across all current organization memberships."""
    if not yes:
        click.confirm('Revoke this key for direct SSH across all current organization memberships? Browser terminal and instance credentials are separate.', abort=True)
    ctx.client.user.revoke_ssh_key(ssh_key_id)

def set_legacy_ssh_key(ctx: MorphRuntimeContext, public_key: str) -> UserSSHKey:
    """Set the legacy singular compatibility key."""
    return ctx.client.user.set_ssh_key(public_key)

def render_user_usage(result: UserUsageOverview, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    click.secho('User usage overview', fg='green', bold=True)
    click.echo(f'Interval buckets: {len(result.items)}')
    if result.instance:
        last = result.instance[-1]
        click.echo(f'Last bucket instance CPU: {last.instance_cpu_time}, MEM: {last.instance_memory_time}, DISK: {last.instance_disk_time}')
    if result.snapshot:
        last = result.snapshot[-1]
        click.echo(f'Last bucket snapshot MEM: {last.snapshot_memory_time}, DISK: {last.snapshot_disk_time}')

def user_usage(ctx: MorphRuntimeContext, interval: str | None=None) -> UserUsageOverview:
    """Show usage for the current authenticated user."""
    return ctx.client.user.usage(interval=interval)
