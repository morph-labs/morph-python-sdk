"""Morph snapshot operations and presentation policy."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Annotated, Any
import click
from .api import Snapshot
from .cli_helpers import format_json, print_docker_style_table
from .cli_runtime import MorphRuntimeContext

def _created_text(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, TypeError, ValueError):
        return 'N/A'

def render_snapshot_list(result: Any, policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Render full or paginated snapshot inventory."""
    if result is None:
        return
    paginated = hasattr(result, 'snapshots')
    snapshots = list(result.snapshots if paginated else result)
    if inputs.get('json_mode'):
        if paginated:
            click.echo(format_json(result))
        else:
            for snapshot in snapshots:
                click.echo(format_json(snapshot))
        return
    if paginated:
        click.echo(f'Total snapshots: {result.total} | Page {result.page} of {result.total_pages} (showing {len(snapshots)})')
    rows = []
    for snapshot in snapshots:
        ttl_seconds = getattr(getattr(snapshot, 'ttl', None), 'ttl_seconds', None)
        rows.append([snapshot.id, _created_text(snapshot.created), getattr(snapshot.status, 'value', snapshot.status), '' if ttl_seconds is None else ttl_seconds, snapshot.spec.vcpus, snapshot.spec.memory, snapshot.spec.disk_size, snapshot.refs.image_id])
    print_docker_style_table(['ID', 'Created At', 'Status', 'TTL (s)', 'VCPUs', 'Memory (MB)', 'Disk Size (MB)', 'Image ID'], rows)

def _interactive_snapshot_list(client: Any, *, metadata: dict[str, str], page: int, limit: int) -> None:
    search: dict[str, str] = {}
    while True:
        response = client.snapshots.list_paginated(metadata={**metadata, **search}, page=page, limit=limit)
        click.clear()
        click.secho('MorphCloud - Snapshot List', bold=True)
        render_snapshot_list(response, {}, {'json_mode': False})
        click.echo('[n] next  [p] previous  [s] metadata search  [q] quit')
        key = click.getchar().lower()
        if key in {'q', '\x03'}:
            return
        if key == 'n' and response.has_next:
            page += 1
        elif key == 'p' and response.has_prev:
            page -= 1
        elif key == 's':
            value = click.prompt('Metadata filter (KEY=VALUE, empty to clear)', default='', show_default=False).strip()
            if not value:
                search = {}
            elif '=' not in value:
                click.echo('Invalid format. Use key=value.', err=True)
            else:
                key_name, item = value.split('=', 1)
                search = {key_name.strip(): item.strip()}
            page = 1

def render_snapshot_ttl(result: Snapshot, policy: dict[str, object], inputs: dict[str, object]) -> None:
    """Distinguish setting retention from clearing it."""
    snapshot_id = inputs['__identity']
    ttl_seconds = inputs['ttl_seconds']
    if ttl_seconds == -1:
        click.echo(f'TTL removed for {snapshot_id}')
    else:
        click.echo(f'TTL set for {snapshot_id}: {ttl_seconds} seconds')

def list_snapshots(ctx: MorphRuntimeContext, metadata: dict[str, str] | None=None, interactive: bool=False, page: int | None=None, limit: int | None=None, json_mode: bool=False) -> Any:
    """List all snapshots."""
    if interactive:
        _interactive_snapshot_list(ctx.client, metadata=metadata or {}, page=page or 1, limit=limit or 50)
        return None
    if page is not None or limit is not None:
        return ctx.client.snapshots.list_paginated(metadata=metadata or {}, page=page or 1, limit=limit or 50)
    return ctx.client.snapshots.list(metadata=metadata or {})

def create_snapshot(ctx: MorphRuntimeContext, image_id: str, vcpus: int, memory: int, disk_size: int, digest: str | None=None, ttl_seconds: int | None=None, metadata: dict[str, str] | None=None) -> Snapshot:
    """Create a snapshot from an image and machine configuration."""
    return ctx.client.snapshots.create(image_id=image_id, vcpus=vcpus, memory=memory, disk_size=disk_size, digest=digest, metadata=metadata, ttl_seconds=ttl_seconds)

def get_snapshot(snapshot: Snapshot) -> Snapshot:
    """Get detailed information about a snapshot as JSON."""
    return snapshot

def set_snapshot_metadata(snapshot: Snapshot, ctx: MorphRuntimeContext, metadata: dict[str, str] | None=None, metadata_args: list[str]=()) -> Snapshot:
    """Set or replace snapshot metadata."""
    combined: dict[str, str] = {}
    for item in metadata_args:
        if '=' not in item:
            raise click.UsageError('Metadata must be in key=value format.')
        key, value = item.split('=', 1)
        combined[key] = value
    combined.update(metadata or {})
    snapshot.set_metadata(combined)
    return ctx.client.snapshots.get(snapshot.id)

def set_snapshot_ttl(snapshot: Snapshot, ttl_seconds: int) -> Snapshot:
    """Set snapshot retention in seconds, or use -1 to clear it."""
    if ttl_seconds == 0 or ttl_seconds < -1:
        raise click.BadParameter('must be greater than 0, or -1 to clear', param_hint="'--ttl-seconds'")
    snapshot.set_ttl(None if ttl_seconds == -1 else ttl_seconds)
    return snapshot
