from __future__ import annotations

import json
import sys
import typing

import click

import morphcloud.api as api


def format_json(obj: typing.Any) -> str:
    """Pretty-print Pydantic models or other objects as JSON."""
    if hasattr(obj, "model_dump"):
        data_to_dump = obj.model_dump()
    elif hasattr(obj, "dict"):
        data_to_dump = obj.dict()
    else:
        data_to_dump = obj
    return json.dumps(data_to_dump, indent=2)


def print_docker_style_table(headers: list[str], rows: list[list[typing.Any]]) -> None:
    """Print a table in Docker ps style with dynamic column widths."""
    if not headers:
        return

    widths = []
    for i in range(len(headers)):
        width = len(str(headers[i]))
        if rows:
            column_values = [str(row[i]) if i < len(row) else "" for row in rows]
            width = max(width, max(len(val) for val in column_values))
        widths.append(width)

    header_line = ""
    separator_line = ""
    for i, header in enumerate(headers):
        header_line += f"{str(header):<{widths[i]}}  "
        separator_line += "-" * widths[i] + "  "

    click.echo(header_line.rstrip())
    click.echo(separator_line.rstrip())

    if rows:
        for row in rows:
            line = ""
            for i in range(len(headers)):
                value = str(row[i]) if i < len(row) else ""
                line += f"{value:<{widths[i]}}  "
            click.echo(line.rstrip())


def _get_profile_override() -> typing.Optional[str]:
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return None
    obj = getattr(ctx, "obj", None) or {}
    return obj.get("profile")


def get_client(profile_override: typing.Optional[str] = None) -> api.MorphCloudClient:
    """Get or create a MorphCloudClient instance. Raises error if API key is missing."""
    try:
        profile_override = (
            profile_override
            if profile_override is not None
            else _get_profile_override()
        )
        return api.MorphCloudClient(profile=profile_override)
    except ValueError as e:
        if "API key must be provided" in str(e):
            click.echo(
                "Error: MORPH_API_KEY environment variable is not set.", err=True
            )
            click.echo(
                "Please set it, e.g., with: export MORPH_API_KEY='your_api_key'",
                err=True,
            )
            click.echo(
                "Or configure a profile, e.g., morphcloud profile set default --api-key '<key>'",
                err=True,
            )
            click.echo(
                "You can generate API keys at: https://cloud.morph.so/web/keys",
                err=True,
            )
            sys.exit(1)
        raise


def handle_api_error(error: Exception) -> typing.NoReturn:
    """Handle API errors with user-friendly messages."""
    if isinstance(error, api.ApiError):
        click.echo(f"API Error (Status Code: {error.status_code})", err=True)
        click.echo(f"Response Body: {error.response_body}", err=True)
    elif isinstance(error, click.ClickException):
        raise error
    else:
        click.echo(f"An unexpected error occurred: {error}", err=True)
    sys.exit(1)


__all__ = [
    "format_json",
    "get_client",
    "handle_api_error",
    "print_docker_style_table",
]
