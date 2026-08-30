"""Morph base-image operations and presentation policy."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Annotated, Any
import click
from .api import Image
from .cli_helpers import format_json, print_docker_style_table
from .cli_runtime import MorphRuntimeContext

def _created_text(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, TypeError, ValueError):
        return 'N/A'

def render_image_list(result: list[Image], policy: dict[str, Any], inputs: dict[str, Any]) -> None:
    """Preserve line-delimited JSON while presenting a readable terminal table."""
    if inputs.get('json_mode'):
        for image in result:
            click.echo(format_json(image))
        return
    print_docker_style_table(['ID', 'Name', 'Description', 'Disk Size (MB)', 'Created At'], [[image.id, image.name, image.description, image.disk_size, _created_text(image.created)] for image in result])

def list_images(ctx: MorphRuntimeContext, json_mode: bool=False) -> list[Image]:
    """List all available base images."""
    return ctx.client.images.list()
