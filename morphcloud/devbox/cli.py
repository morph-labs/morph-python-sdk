"""CLI commands for MorphCloud Devboxes.

This module defines the built-in `morphcloud devbox` command group.
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
import time
import typing as _t
import urllib.parse
from pathlib import Path

import click
import paramiko

from morphcloud._ssh import SSHClient as MorphSSHClient
from morphcloud._ssh import SSHError as MorphSSHError
from morphcloud._utils import Spinner
from morphcloud.api import copy_into_or_from_instance
from morphcloud.cli_helpers import (
    format_json,
    get_client,
    handle_api_error,
    print_docker_style_table,
)
from morphcloud.config import resolve_settings

from .client import DevboxClient
from .gen.core.api_error import ApiError as DevboxApiError
from .gen.types import TemplateCacheRequest
from .gen.types.devbox_response import DevboxResponse
from .gen.types.http_service import HttpService
from .template_local_runner import ExperimentalLocalTemplateRunner
from .template_runner import (
    TemplateRunnerError,
    TemplateRunOptions,
    TemplateWorkflowRunner,
    TemplateWorkflowTransport,
    build_presenter,
)
from .terminals import build_tmux_attach_command, sanitize_tmux_session_name, sh_quote

_READY_STATUS = "ready"
_TRANSIENT_STATUSES = {"provisioning", "pending", "resuming", "rebooting", "starting"}
_RESUMEABLE_STATUSES = {"paused", "pausing", "stopped", "stopping"}
_FAILURE_STATUSES = {"error", "failed", "terminated", "deleting", "deleted"}

_DEVBOX_LIST_HEADERS = ["Name", "ID", "Snapshot ID", "Created At", "Status", "Saves"]
_DEVBOX_LIST_COLUMN_WIDTHS = {
    "Name": 24,
    "ID": 26,
    "Snapshot ID": 26,
    "Created At": 22,
    "Status": 12,
    "Saves": 6,
}

_TEMPLATE_LIST_HEADERS = ["Name", "ID", "Status", "Cached", "Updated"]
_TEMPLATE_LIST_COLUMN_WIDTHS = {
    "Name": 24,
    "ID": 26,
    "Status": 12,
    "Cached": 11,
    "Updated": 22,
}

_TERMINAL_LIST_HEADERS = ["Name", "ID", "Windows", "Clients", "Created", "Activity"]
_TERMINAL_LIST_COLUMN_WIDTHS = {
    "Name": 28,
    "ID": 10,
    "Windows": 7,
    "Clients": 7,
    "Created": 22,
    "Activity": 22,
}

_INSTANT_REASON_HINTS = {
    "not_ready": "Template is still building; wait for caching to finish before starting an instant devbox.",
    "requires_build": "Template requires secrets; run 'morphcloud devbox template cache {template_id}' to prepare your personal snapshot.",
    "forbidden": "Instant start is not available for this template with your credentials.",
}


@click.group()
def devbox():
    """Manage devboxes in MorphCloud."""
    pass


@devbox.command("list")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def list_devboxes(json_output: bool) -> None:
    """List devboxes for the authenticated account."""
    _, devbox_client = _get_devbox_client()

    try:
        result = devbox_client.devboxes_core.list_devboxes()
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    items = list(getattr(result, "data", []) or [])
    if not items:
        click.echo("No devboxes found")
        return

    headers = list(_DEVBOX_LIST_HEADERS)
    rows = []
    for item in items:
        metadata = dict(getattr(item, "metadata", {}) or {})
        name = _resolve_name(metadata, getattr(item, "id", ""))
        status = (getattr(item, "status", "") or "").upper()
        saves = getattr(item, "saves_count", getattr(item, "timeline_count", 0)) or 0
        snapshot = getattr(getattr(item, "refs", None), "snapshot_id", "") or "-"
        created = _format_timestamp(getattr(item, "created", None))
        rows.append(
            [
                _truncate_text(name, _DEVBOX_LIST_COLUMN_WIDTHS["Name"]),
                _truncate_text(item.id, _DEVBOX_LIST_COLUMN_WIDTHS["ID"]),
                _truncate_text(snapshot, _DEVBOX_LIST_COLUMN_WIDTHS["Snapshot ID"]),
                _truncate_text(created, _DEVBOX_LIST_COLUMN_WIDTHS["Created At"]),
                _truncate_text(status, _DEVBOX_LIST_COLUMN_WIDTHS["Status"]),
                _truncate_text(str(saves), _DEVBOX_LIST_COLUMN_WIDTHS["Saves"]),
            ]
        )

    print_docker_style_table(headers, rows)


@devbox.command("get")
@click.argument("devbox_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def get_devbox(devbox_id: str, json_output: bool) -> None:
    """Get details for a specific devbox."""
    _, devbox_client = _get_devbox_client()

    try:
        result = devbox_client.devboxes_core.get_devbox(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    metadata = dict(getattr(result, "metadata", {}) or {})
    spec = getattr(result, "spec", None)
    networking = getattr(result, "networking", None)

    click.echo(f"ID: {result.id}")
    click.echo(f"Name: {_resolve_name(metadata, result.id)}")
    click.echo(f"Status: {result.status}")
    click.echo(f"Created: {_format_timestamp(getattr(result, 'created', None))}")
    click.echo(
        f"Snapshot: {getattr(getattr(result, 'refs', None), 'snapshot_id', '-')}"
    )

    template_id = metadata.get("template_id")
    if isinstance(template_id, str) and template_id.strip():
        click.echo(f"Template: {template_id}")

    if spec is not None:
        click.echo("Spec:")
        click.echo(f"  vCPUs: {getattr(spec, 'vcpus', 'Unknown')}")
        click.echo(f"  Memory: {getattr(spec, 'memory', 'Unknown')} MB")
        click.echo(f"  Disk: {getattr(spec, 'disk_size', 'Unknown')} GB")

    if networking:
        http_services = getattr(networking, "http_services", []) or []
        if http_services:
            click.echo("HTTP Services:")
            for svc in http_services:
                name = getattr(svc, "name", "")
                port = getattr(svc, "port", "")
                url = getattr(svc, "url", "")
                click.echo(f"  - {name} (port {port}) {url}")


@devbox.group("template")
def template_group():
    """Manage devbox templates."""
    pass


@template_group.command("list")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def list_templates(json_output: bool) -> None:
    """List available devbox templates."""
    _, devbox_client = _get_devbox_client()
    try:
        result = devbox_client.templates.list_templates()
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    items = list(getattr(result, "data", []) or [])
    if not items:
        click.echo("No templates found")
        return

    headers = list(_TEMPLATE_LIST_HEADERS)
    rows = []
    for template in items:
        cached = getattr(template, "cached_step_count", 0)
        total = getattr(template, "step_count", 0)
        cached_text = f"{cached}/{total}"
        status = str(getattr(template, "status", "") or "").upper()
        updated = _format_timestamp(getattr(template, "updated_at", None))
        rows.append(
            [
                _truncate_text(
                    getattr(template, "name", ""), _TEMPLATE_LIST_COLUMN_WIDTHS["Name"]
                ),
                _truncate_text(
                    getattr(template, "id", ""), _TEMPLATE_LIST_COLUMN_WIDTHS["ID"]
                ),
                _truncate_text(status, _TEMPLATE_LIST_COLUMN_WIDTHS["Status"]),
                _truncate_text(cached_text, _TEMPLATE_LIST_COLUMN_WIDTHS["Cached"]),
                _truncate_text(updated, _TEMPLATE_LIST_COLUMN_WIDTHS["Updated"]),
            ]
        )

    print_docker_style_table(headers, rows)


@template_group.command("get")
@click.argument("template_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def get_template(template_id: str, json_output: bool) -> None:
    """Show template details."""
    _, devbox_client = _get_devbox_client()
    try:
        template = devbox_client.templates.get_template(template_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(template))
        return

    click.echo(f"ID: {template.id}")
    click.echo(f"Name: {template.name}")
    status = str(getattr(template, "status", "") or "")
    click.echo(f"Status: {status}")
    click.echo(f"Base Snapshot: {getattr(template, 'base_snapshot_id', '-')}")
    final_snapshot = getattr(template, "final_snapshot_id", None) or "-"
    click.echo(f"Final Snapshot: {final_snapshot}")
    click.echo(
        f"Steps Cached: {getattr(template, 'cached_step_count', 0)}/{getattr(template, 'step_count', 0)}"
    )
    click.echo(f"Created: {_format_timestamp(getattr(template, 'created_at', None))}")
    click.echo(f"Updated: {_format_timestamp(getattr(template, 'updated_at', None))}")
    description = getattr(template, "description", None)
    if description:
        click.echo(f"Description: {description}")


@template_group.command("create")
@click.option("--name", required=True, help="Display name for the template.")
@click.option(
    "--base-snapshot",
    "base_snapshot_option",
    required=True,
    help="Snapshot identifier used as the base for this template.",
)
@click.option(
    "--file",
    "yaml_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Path to the template YAML definition.",
)
@click.option("--description", help="Optional template description.")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def create_template(
    name: str,
    base_snapshot_option: str,
    yaml_file: Path,
    description: _t.Optional[str],
    json_output: bool,
) -> None:
    """Create a new template."""
    _, devbox_client = _get_devbox_client()
    try:
        yaml_content = yaml_file.read_text()
    except Exception as exc:
        raise click.ClickException(f"Failed to read template YAML: {exc}") from exc

    if not yaml_content.strip():
        raise click.ClickException("Template YAML file is empty.")

    try:
        with Spinner(
            text=f"Creating template '{name}'...",
            success_text="Template created",
            success_emoji="🆕",
        ):
            template = devbox_client.templates.create_template(
                name=name,
                yaml=yaml_content,
                base_snapshot_option=base_snapshot_option,
                description=description,
            )
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(template))
        return

    click.secho(f"Template created: {template.id}", fg="green")


@template_group.command("update")
@click.argument("template_id")
@click.option("--name", help="Updated display name.")
@click.option(
    "--base-snapshot",
    "base_snapshot_option",
    help="Updated base snapshot identifier.",
)
@click.option(
    "--file",
    "yaml_file",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Path to updated template YAML content.",
)
@click.option("--description", help="Updated description.")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def update_template(
    template_id: str,
    name: _t.Optional[str],
    base_snapshot_option: _t.Optional[str],
    yaml_file: _t.Optional[Path],
    description: _t.Optional[str],
    json_output: bool,
) -> None:
    """Update an existing template."""
    _, devbox_client = _get_devbox_client()

    if not any([name, base_snapshot_option, yaml_file, description]):
        raise click.UsageError("Provide at least one field to update.")

    yaml_content = None
    if yaml_file is not None:
        try:
            yaml_content = yaml_file.read_text()
        except Exception as exc:
            raise click.ClickException(f"Failed to read template YAML: {exc}") from exc
        if not yaml_content.strip():
            raise click.ClickException("Template YAML file is empty.")

    try:
        with Spinner(
            text=f"Updating template {template_id}...",
            success_text="Template updated",
            success_emoji="✏️",
        ):
            devbox_client.templates.update_template(
                template_id,
                name=name,
                yaml=yaml_content,
                description=description,
                base_snapshot_option=base_snapshot_option,
            )
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        updated = devbox_client.templates.get_template(template_id)
        click.echo(format_json(updated))
    else:
        click.secho(f"Template updated: {template_id}", fg="green")


@template_group.command("delete")
@click.argument("template_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def delete_template(template_id: str, json_output: bool) -> None:
    """Delete a template and associated aliases."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Deleting template {template_id}...",
            success_text="Template deleted",
            success_emoji="🗑",
        ):
            devbox_client.templates.delete_template(template_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json({"id": template_id, "deleted": True}))
    else:
        click.secho(f"Template deleted: {template_id}", fg="green")


@template_group.command("cache")
@click.argument("template_id")
@click.option(
    "--secret",
    "secret_items",
    multiple=True,
    help="Runtime secret to provide during build (key=value). Repeat for multiple secrets.",
)
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def cache_template(
    template_id: str, secret_items: _t.Tuple[str, ...], json_output: bool
) -> None:
    """Start caching/building a template."""
    _, devbox_client = _get_devbox_client()
    secrets = _parse_key_value_items(secret_items, label="Secret entries")

    request = TemplateCacheRequest(runtime_secrets=secrets or None) if secrets else None
    try:
        with Spinner(
            text=f"Starting cache build for template {template_id}...",
            success_text="Template build started",
            success_emoji="🏗",
        ):
            response = devbox_client.templates.cache_template(
                template_id, request=request
            )
    except Exception as exc:
        handle_api_error(exc)
        return

    run_id = getattr(response, "run_id", None)
    if json_output:
        click.echo(format_json(response))
    else:
        click.secho(f"Build run started: {run_id}", fg="green")
        click.echo("Use 'morphcloud devbox template events' to monitor progress.")


@template_group.command("cancel-cache")
@click.argument("template_id")
def cancel_template_cache(template_id: str) -> None:
    """Cancel a running template build."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Cancelling cache for template {template_id}...",
            success_text="Template cache cancelled",
            success_emoji="🛑",
        ):
            devbox_client.templates.cancel_template_caching(template_id)
    except Exception as exc:
        handle_api_error(exc)
        return


@template_group.command("events")
@click.argument("template_id")
@click.option("--run-id", required=True, help="Run ID returned from the cache command.")
@click.option(
    "--force", is_flag=True, default=False, help="Force fetching cached events."
)
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def template_events(
    template_id: str, run_id: str, force: bool, json_output: bool
) -> None:
    """Fetch build events for a template run."""
    _, devbox_client = _get_devbox_client()
    try:
        events = devbox_client.templates.template_events(
            template_id, run_id=run_id, force=force or None
        )
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(events if events is not None else {}))
        return

    if not events:
        click.echo("No events available.")
        return

    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict):
                kind = event.get("type") or event.get("status") or "event"
                message = event.get("message") or ""
                step = event.get("index")
                if step is not None:
                    click.echo(f"[{kind}] step={step}: {message}")
                else:
                    click.echo(f"[{kind}] {message}")
            else:
                click.echo(str(event))
    else:
        click.echo(str(events))


@template_group.command("submit-secrets")
@click.argument("template_id")
@click.option("--run-id", required=True, help="Run ID awaiting secrets.")
@click.option(
    "--secret",
    "secret_items",
    multiple=True,
    required=True,
    help="Secret to submit (key=value). Repeat for multiple secrets.",
)
def submit_template_secrets(
    template_id: str, run_id: str, secret_items: _t.Tuple[str, ...]
) -> None:
    """Submit secrets while a template build is awaiting input."""
    _, devbox_client = _get_devbox_client()
    secrets = _parse_key_value_items(secret_items, label="Secret entries")
    try:
        with Spinner(
            text="Submitting build secrets...",
            success_text="Secrets submitted",
            success_emoji="🔐",
        ):
            devbox_client.templates.submit_build_secret(
                template_id, run_id, request=secrets
            )
    except Exception as exc:
        handle_api_error(exc)
        return


@template_group.command("share")
@click.argument("template_id")
@click.option("--alias", required=True, help="Alias slug to publish for this template.")
@click.option("--description", help="Optional alias description.")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def share_template(
    template_id: str, alias: str, description: _t.Optional[str], json_output: bool
) -> None:
    """Share a template via a public alias."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Sharing template {template_id}...",
            success_text="Template shared",
            success_emoji="🌐",
        ):
            response = devbox_client.templates.share_template(
                template_id,
                alias=alias,
                description=description,
            )
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(response))
    else:
        click.secho(f"Template shared as alias '{alias}'", fg="green")


@template_group.command("run")
@click.argument("target", required=False)
@click.option(
    "--param",
    "param_items",
    multiple=True,
    help="Workflow input to provide for this run (key=value). Repeat for multiple inputs.",
)
@click.option(
    "--secret",
    "secret_items",
    multiple=True,
    help="Runtime secret override for this run (key=value). Repeat for multiple secrets.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Bypass cache and rebuild all non-secret steps for this run.",
)
@click.option(
    "--attach",
    "attach_run_id",
    help="Attach to an existing template run instead of starting a new build.",
)
@click.option(
    "--plain",
    is_flag=True,
    default=False,
    help="Disable the interactive TUI and use plain text output.",
)
@click.option("--json", "json_output", is_flag=True, help="Output structured JSON")
@click.option(
    "--handoff-ttl-seconds",
    type=int,
    help="Set a handoff TTL on the created devbox.",
)
@click.option(
    "--handoff-ttl-action",
    type=click.Choice(["pause", "stop"]),
    help="Action to take when the handoff TTL expires.",
)
@click.option(
    "--experimental-run-locally",
    is_flag=True,
    default=False,
    help="Treat TARGET as a local template YAML path or shared alias YAML and execute it locally in the template TUI.",
)
@click.option(
    "--experimental-run-local",
    "deprecated_experimental_run_local",
    is_flag=True,
    default=False,
    hidden=True,
)
def run_template(
    target: _t.Optional[str],
    param_items: _t.Tuple[str, ...],
    secret_items: _t.Tuple[str, ...],
    force: bool,
    attach_run_id: _t.Optional[str],
    plain: bool,
    json_output: bool,
    handoff_ttl_seconds: _t.Optional[int],
    handoff_ttl_action: _t.Optional[str],
    experimental_run_locally: bool,
    deprecated_experimental_run_local: bool,
) -> None:
    """Run a template workflow from a template id, shared alias, or interactive browser.

    Targets beginning with ``tpl_`` resolve as template ids. Any other target resolves
    as a shared/public alias. Omit TARGET to browse owned templates and search aliases
    interactively. Use ``--experimental-run-locally`` to execute a local template YAML
    or shared alias YAML with the same TUI/presenter stack.
    """
    experimental_run_local = (
        experimental_run_locally or deprecated_experimental_run_local
    )
    params = _parse_key_value_items(param_items, label="Workflow params")
    secrets = _parse_key_value_items(secret_items, label="Secret entries")
    presenter = build_presenter(plain=plain, json_output=json_output)
    options = TemplateRunOptions(
        workflow_context=params,
        runtime_secrets=secrets,
        force=force,
        attach_run_id=attach_run_id,
        handoff_ttl_seconds=handoff_ttl_seconds,
        handoff_ttl_action=handoff_ttl_action,
    )

    try:
        if experimental_run_local:
            if attach_run_id:
                raise click.UsageError(
                    "--attach is not supported with --experimental-run-locally."
                )
            if not target:
                raise click.UsageError(
                    "Provide a template YAML path or shared template alias as TARGET when using --experimental-run-locally."
                )
            result = ExperimentalLocalTemplateRunner().run(
                target, options=options, presenter=presenter
            )
        else:
            client, devbox_client, anonymous = _get_template_runner_backend()
            runner = TemplateWorkflowRunner(
                TemplateWorkflowTransport(
                    client,
                    devbox_client,
                    anonymous=anonymous,
                )
            )
            result = runner.run(target, options=options, presenter=presenter)
    except TemplateRunnerError as exc:
        raise click.ClickException(str(exc)) from exc
    except click.ClickException:
        raise
    except click.Abort:
        raise
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result.as_dict()))
        exit_code = result.exit_code()
        if exit_code:
            click.get_current_context().exit(exit_code)
        return

    if result.status == "awaiting_input" and result.awaiting_input is not None:
        raise click.ClickException(
            f"Run {result.run_id} is awaiting secret {result.awaiting_input.secret_name}. "
            f"Re-run interactively or provide --secret {result.awaiting_input.secret_name}=VALUE."
        )

    if result.status in {"error", "cancelled"}:
        raise click.ClickException(result.error or "Template workflow failed.")


@devbox.command("start")
@click.argument("template_id")
@click.option("--name", help="Optional display name for the new devbox.")
@click.option(
    "--metadata",
    "-m",
    "metadata_items",
    multiple=True,
    help="Additional metadata entries (key=value). Can be provided multiple times.",
)
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def start_devbox(
    template_id: str,
    name: _t.Optional[str],
    metadata_items: _t.Tuple[str, ...],
    json_output: bool,
) -> None:
    """Start a devbox from a template."""
    _, devbox_client = _get_devbox_client()
    metadata = _parse_metadata_options(metadata_items)

    availability = _instant_start_availability(devbox_client, template_id)
    if not availability.get("available", False):
        reason = str(availability.get("reason") or "unavailable")
        reason_message = _INSTANT_REASON_HINTS.get(
            reason, f"Template is not available for instant start (reason: {reason})."
        ).format(template_id=template_id)
        raise click.ClickException(reason_message)

    if "template_id" not in metadata:
        metadata["template_id"] = template_id

    payload: _t.Dict[str, _t.Any] = {}
    if name:
        payload["name"] = name
    if metadata:
        payload["metadata"] = {k: str(v) for k, v in metadata.items()}

    try:
        with Spinner(
            text=f"Starting devbox from template {template_id}...",
            success_text="Devbox creation complete!",
            success_emoji="🚀",
        ):
            devbox = _instant_start_devbox(devbox_client, template_id, payload)
    except click.ClickException:
        raise
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(devbox))
        return

    click.secho(f"Devbox created: {devbox.id}", fg="green")
    click.echo(f"Status: {getattr(devbox, 'status', '')}")
    click.echo(f"Snapshot: {getattr(devbox.refs, 'snapshot_id', '-')}")


@devbox.command("ssh")
@click.argument("devbox_id")
@click.argument("remote_command", nargs=-1, required=False, type=click.UNPROCESSED)
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Seconds to wait for the devbox to become READY.",
)
@click.option(
    "--keepalive",
    default=15,
    show_default=True,
    help="Seconds between SSH keepalive packets.",
)
def ssh_devbox(
    devbox_id: str,
    remote_command: _t.Tuple[str, ...],
    timeout: int,
    keepalive: int,
) -> None:
    """Open an SSH session to a devbox or run a remote command."""
    client, devbox_client = _get_devbox_client()

    try:
        devbox = devbox_client.devboxes_core.get_devbox(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    status = _normalize_status(getattr(devbox, "status", None))
    if status in _RESUMEABLE_STATUSES:
        click.secho(
            f"Devbox {devbox_id} is {status.upper()}. Attempting to resume...",
            fg="yellow",
        )
        try:
            devbox_client.devboxes_actions.resume_devbox(devbox_id)
        except Exception as exc:
            handle_api_error(exc)
            return
    elif status not in {_READY_STATUS} | _TRANSIENT_STATUSES:
        click.secho(
            f"Devbox {devbox_id} is in status '{status or 'unknown'}'. Waiting for READY...",
            fg="yellow",
        )

    try:
        with Spinner(
            text=f"Waiting for {devbox_id} to become ready...",
            success_text=f"Devbox {devbox_id} is ready",
            success_emoji="✅",
        ):
            devbox = _wait_for_devbox_ready(devbox_client, devbox_id, timeout=timeout)
    except click.ClickException:
        raise
    except Exception as exc:
        handle_api_error(exc)
        return

    try:
        creds = devbox_client.admin.get_devbox_ssh_credentials(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    username = getattr(creds, "access_token", None)
    password = getattr(creds, "password", None)
    if not username or not password:
        raise click.ClickException("SSH credentials were not returned by the service.")

    ssh_hostname = client.ssh_hostname
    ssh_port = _safe_int_from_env("MORPH_SSH_PORT", default=client.ssh_port)
    connect_timeout = _safe_int_from_env("DEVBOX_SSH_CONNECT_TIMEOUT", default=30)

    ssh_target = f"{devbox_id}.{ssh_hostname}"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        with Spinner(
            text=f"Connecting to {ssh_target}...",
            success_text="SSH connection established",
            success_emoji="🔌",
        ):
            ssh_client.connect(
                hostname=ssh_target,
                port=ssh_port,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
                timeout=connect_timeout,
            )
    except paramiko.AuthenticationException as exc:
        raise click.ClickException(
            "Authentication failed while connecting to the devbox."
        ) from exc
    except (paramiko.SSHException, OSError) as exc:
        raise click.ClickException(f"SSH connection failed: {exc}") from exc

    transport = ssh_client.get_transport()
    if transport is not None:
        try:
            transport.set_keepalive(int(keepalive))
        except Exception:
            pass

    ssh_wrapper = MorphSSHClient(ssh_client)

    exit_code = 0
    try:
        is_interactive = sys.stdin.isatty() and not remote_command
        if is_interactive:
            click.secho("💻 Starting interactive SSH shell...", fg="magenta")
            exit_code = ssh_wrapper.interactive_shell()
        else:
            command = " ".join(remote_command)
            if not command:
                raise click.UsageError(
                    "Command must be provided in non-interactive mode or when stdin is not a TTY."
                )
            click.secho(f"🛸 Running remote command: {command}", fg="yellow")
            try:
                result = ssh_wrapper.run(command)
            except MorphSSHError as exc:
                raise click.ClickException(str(exc)) from exc
            if result.stdout:
                click.echo(result.stdout.rstrip())
            if result.stderr:
                click.echo(result.stderr.rstrip(), err=True)
            exit_code = result.returncode
            click.echo(f"Remote command exited with code {exit_code}")
    except MorphSSHError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        ssh_wrapper.close()

    sys.exit(exit_code)


@devbox.group("terminal")
def terminal_group() -> None:
    """Manage devbox terminals (tmux sessions)."""


def _format_devbox_api_error(error: DevboxApiError, *, context: str) -> str:
    status = getattr(error, "status_code", None)
    body = getattr(error, "body", None)

    detail: _t.Optional[str] = None
    if isinstance(body, dict):
        raw_detail = body.get("detail")
        if isinstance(raw_detail, dict):
            maybe_error = raw_detail.get("error")
            if isinstance(maybe_error, dict):
                detail = maybe_error.get("message") or maybe_error.get("type")
            detail = detail or raw_detail.get("message") or raw_detail.get("detail")
        elif isinstance(raw_detail, str):
            detail = raw_detail

        if not detail:
            error_block = body.get("error")
            if isinstance(error_block, dict):
                detail = error_block.get("message") or error_block.get("type")
            elif isinstance(error_block, str):
                detail = error_block

        if not detail and isinstance(body.get("message"), str):
            detail = body["message"]
    elif isinstance(body, str):
        detail = body

    suffix = detail or (str(body) if body is not None else None) or "Unknown error"
    if status is not None:
        return f"{context} failed (status {status}): {suffix}"
    return f"{context} failed: {suffix}"


def _ensure_devbox_ready_for_terminals(
    devbox_client, devbox_id: str, *, timeout: int
) -> DevboxResponse:
    try:
        devbox = devbox_client.devboxes_core.get_devbox(devbox_id)
    except DevboxApiError as exc:
        raise click.ClickException(
            _format_devbox_api_error(exc, context="Get devbox")
        ) from exc
    except Exception as exc:
        handle_api_error(exc)

    status = _normalize_status(getattr(devbox, "status", None))
    if status in _RESUMEABLE_STATUSES:
        click.secho(
            f"Devbox {devbox_id} is {status.upper()}. Attempting to resume...",
            fg="yellow",
        )
        try:
            devbox_client.devboxes_actions.resume_devbox(devbox_id)
        except DevboxApiError as exc:
            raise click.ClickException(
                _format_devbox_api_error(exc, context="Resume devbox")
            ) from exc
        except Exception as exc:
            handle_api_error(exc)

    if status != _READY_STATUS:
        try:
            with Spinner(
                text=f"Waiting for {devbox_id} to become ready...",
                success_text=f"Devbox {devbox_id} is ready",
                success_emoji="✅",
            ):
                devbox = _wait_for_devbox_ready(
                    devbox_client, devbox_id, timeout=timeout
                )
        except click.ClickException:
            raise
        except DevboxApiError as exc:
            raise click.ClickException(
                _format_devbox_api_error(exc, context="Wait for devbox ready")
            ) from exc
        except Exception as exc:
            handle_api_error(exc)
    return devbox


def _looks_like_tmux_session_id(value: str) -> bool:
    trimmed = (value or "").strip()
    return trimmed.startswith("$") and trimmed[1:].isdigit()


@terminal_group.command("list")
@click.argument("devbox_id")
@click.option("--socket", default=None, help="Optional tmux socket name/path.")
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Seconds to wait for the devbox to become READY.",
)
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def terminal_list(
    devbox_id: str, socket: _t.Optional[str], timeout: int, json_output: bool
) -> None:
    """List devbox terminals (tmux sessions)."""
    _, devbox_client = _get_devbox_client()

    _ensure_devbox_ready_for_terminals(devbox_client, devbox_id, timeout=timeout)

    try:
        result = devbox_client.terminals.list(devbox_id, socket=socket)
    except DevboxApiError as exc:
        raise click.ClickException(
            _format_devbox_api_error(exc, context="Terminal list")
        ) from exc
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    sessions = list(result.sessions or [])
    if not sessions:
        if result.tmux_installed is False:
            click.secho("tmux is not installed on this devbox.", fg="yellow")
            click.echo(f"Run: morphcloud devbox terminal start {devbox_id}")
            return
        click.echo("No terminals found")
        return

    headers = list(_TERMINAL_LIST_HEADERS)
    rows: list[list[_t.Any]] = []
    for session in sessions:
        rows.append(
            [
                _truncate_text(session.name, _TERMINAL_LIST_COLUMN_WIDTHS["Name"]),
                _truncate_text(session.id, _TERMINAL_LIST_COLUMN_WIDTHS["ID"]),
                _truncate_text(
                    session.windows, _TERMINAL_LIST_COLUMN_WIDTHS["Windows"]
                ),
                _truncate_text(
                    session.clients, _TERMINAL_LIST_COLUMN_WIDTHS["Clients"]
                ),
                _truncate_text(
                    session.created, _TERMINAL_LIST_COLUMN_WIDTHS["Created"]
                ),
                _truncate_text(
                    session.activity, _TERMINAL_LIST_COLUMN_WIDTHS["Activity"]
                ),
            ]
        )

    print_docker_style_table(headers, rows)


@terminal_group.command("start")
@click.argument("devbox_id")
@click.option("--name", "session_name", required=False, help="Tmux session name.")
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Seconds to wait for the devbox to become READY.",
)
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def terminal_start(
    devbox_id: str, session_name: _t.Optional[str], timeout: int, json_output: bool
) -> None:
    """Start a new devbox terminal (tmux session)."""
    _, devbox_client = _get_devbox_client()

    devbox = _ensure_devbox_ready_for_terminals(
        devbox_client, devbox_id, timeout=timeout
    )
    metadata = dict(getattr(devbox, "metadata", {}) or {})

    requested = (
        session_name
        if session_name is not None
        else f"tmux-{_resolve_name(metadata, devbox_id)}"
    )
    safe_name = sanitize_tmux_session_name(requested)
    if not safe_name:
        raise click.ClickException("Session name cannot be empty.")

    try:
        result = devbox_client.terminals.start(
            devbox_id, name=safe_name, ensure_tmux=True, detached=True
        )
    except DevboxApiError as exc:
        raise click.ClickException(
            _format_devbox_api_error(exc, context="Terminal start")
        ) from exc
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    if requested != safe_name:
        click.secho(f"Sanitized session name to: {safe_name}", fg="yellow")

    install = result.install
    if install is not None and getattr(install, "tmux_version", None):
        click.echo(f"tmux version: {install.tmux_version}")

    click.secho(f"Terminal started: {safe_name}", fg="green")
    click.echo(f"Session ID: {result.session.id}")
    click.echo(
        f"Connect with: morphcloud devbox terminal connect {devbox_id} {safe_name}"
    )


@terminal_group.command("connect")
@click.argument("devbox_id")
@click.argument("session")
@click.option(
    "--command",
    "initial_command",
    required=False,
    help="Optional command to run when creating the session (name targets only).",
)
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Seconds to wait for the devbox to become READY.",
)
@click.option(
    "--keepalive",
    default=15,
    show_default=True,
    help="Seconds between SSH keepalive packets.",
)
def terminal_connect(
    devbox_id: str,
    session: str,
    initial_command: _t.Optional[str],
    timeout: int,
    keepalive: int,
) -> None:
    """Connect to a devbox terminal (tmux session) over SSH."""
    if not sys.stdin.isatty():
        raise click.ClickException("This command requires an interactive TTY.")

    client, devbox_client = _get_devbox_client()
    _ensure_devbox_ready_for_terminals(devbox_client, devbox_id, timeout=timeout)

    target = (session or "").strip()
    if not target:
        raise click.ClickException("Session cannot be empty.")

    if initial_command and _looks_like_tmux_session_id(target):
        raise click.UsageError(
            "--command requires a session name (not a session id like $0)."
        )

    attach_cmd: str
    if _looks_like_tmux_session_id(target):
        attach_cmd = f"tmux attach-session -t {sh_quote(target)}"
    else:
        attach_cmd = build_tmux_attach_command(target, initial_command)
    if not attach_cmd:
        raise click.ClickException("Failed to build tmux attach command.")

    # Ensure tmux is installed (idempotent); this may take a while on first use.
    try:
        with Spinner(
            text=f"Ensuring tmux is installed on {devbox_id}...",
            success_text="tmux ready",
            success_emoji="🧰",
        ):
            devbox_client.tmux.tmux_install(devbox_id)
    except DevboxApiError as exc:
        raise click.ClickException(
            _format_devbox_api_error(exc, context="tmux install")
        ) from exc
    except Exception as exc:
        handle_api_error(exc)
        return

    try:
        creds = devbox_client.admin.get_devbox_ssh_credentials(devbox_id)
    except DevboxApiError as exc:
        raise click.ClickException(
            _format_devbox_api_error(exc, context="Get SSH credentials")
        ) from exc
    except Exception as exc:
        handle_api_error(exc)
        return

    username = getattr(creds, "access_token", None)
    password = getattr(creds, "password", None)
    if not username or not password:
        raise click.ClickException("SSH credentials were not returned by the service.")

    ssh_hostname = client.ssh_hostname
    ssh_port = _safe_int_from_env("MORPH_SSH_PORT", default=client.ssh_port)
    connect_timeout = _safe_int_from_env("DEVBOX_SSH_CONNECT_TIMEOUT", default=30)
    ssh_target = f"{devbox_id}.{ssh_hostname}"

    click.secho(f"Attaching to tmux session on {ssh_target}...", fg="magenta")

    exit_code: int
    try:
        with _DevboxSSHContext(
            hostname=ssh_target,
            port=ssh_port,
            username=username,
            password=password,
            timeout=connect_timeout,
            keepalive=keepalive,
        ) as ssh_wrapper:
            exit_code = ssh_wrapper.interactive_shell(command=attach_cmd)
    except paramiko.AuthenticationException as exc:
        raise click.ClickException(
            "Authentication failed while connecting to the devbox."
        ) from exc
    except (paramiko.SSHException, OSError) as exc:
        raise click.ClickException(f"SSH connection failed: {exc}") from exc

    sys.exit(exit_code)


@devbox.command("chat")
@click.argument("devbox_id")
@click.option(
    "--conversation-file",
    "-f",
    type=click.Path(dir_okay=False),
    help="Path to a conversation file.",
)
@click.argument("instructions", nargs=-1, required=False, type=click.UNPROCESSED)
def chat_devbox(
    devbox_id: str,
    conversation_file: _t.Optional[str],
    instructions: _t.Tuple[str, ...],
) -> None:
    """Start an interactive LLM agent chat session with a devbox."""
    client, devbox_client = _get_devbox_client()

    devbox_id = devbox_id.strip()
    if not devbox_id:
        raise click.UsageError("Devbox identifier is required.")

    try:
        from morphcloud._llm import agent_loop

        with Spinner(
            text=f"Waiting for devbox {devbox_id} to be ready for chat...",
            success_text=f"Devbox ready for chat: {devbox_id}",
            success_emoji="💬",
        ):
            _wait_for_devbox_ready(devbox_client, devbox_id, timeout=300)

        creds = devbox_client.admin.get_devbox_ssh_credentials(devbox_id)

        ssh_hostname = client.ssh_hostname
        ssh_port = _safe_int_from_env("MORPH_SSH_PORT", default=client.ssh_port)
        connect_timeout = _safe_int_from_env("DEVBOX_SSH_CONNECT_TIMEOUT", default=30)
        keepalive = _safe_int_from_env("MORPH_SSH_KEEPALIVE_SECS", default=15)

        adapter = _DevboxInstanceAdapter(
            hostname=f"{devbox_id}.{ssh_hostname}",
            port=ssh_port,
            username=creds.access_token,
            password=creds.password,
            timeout=connect_timeout,
            keepalive=keepalive,
        )

        click.echo("Starting chat agent...")

        initial_prompt = " ".join(instructions) if instructions else None
        agent_loop(
            adapter,
            initial_prompt=initial_prompt,
            conversation_file=conversation_file,
        )

    except ImportError:
        click.echo(
            "Error: Chat requires additional dependencies (e.g., 'anthropic').",
            err=True,
        )
        sys.exit(1)
    except click.ClickException:
        raise
    except Exception as exc:
        handle_api_error(exc)


@devbox.command("pause")
@click.argument("devbox_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def pause_devbox(devbox_id: str, json_output: bool) -> None:
    """Pause a running devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Pausing devbox {devbox_id}...",
            success_text=f"Devbox paused: {devbox_id}",
            success_emoji="⏸",
        ):
            result = devbox_client.devboxes_actions.pause_devbox(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
    else:
        click.echo(f"Status: {getattr(result, 'status', '')}")


@devbox.command("resume")
@click.argument("devbox_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def resume_devbox(devbox_id: str, json_output: bool) -> None:
    """Resume a paused devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Resuming devbox {devbox_id}...",
            success_text=f"Devbox resumed: {devbox_id}",
            success_emoji="▶️",
        ):
            result = devbox_client.devboxes_actions.resume_devbox(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
    else:
        click.echo(f"Status: {getattr(result, 'status', '')}")


@devbox.command("reboot")
@click.argument("devbox_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def reboot_devbox(devbox_id: str, json_output: bool) -> None:
    """Reboot a devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Rebooting devbox {devbox_id}...",
            success_text=f"Devbox rebooted: {devbox_id}",
            success_emoji="🔄",
        ):
            result = devbox_client.devboxes_actions.reboot_devbox(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
    else:
        click.echo(f"Status: {getattr(result, 'status', '')}")


@devbox.command("delete")
@click.argument("devbox_id")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def delete_devbox(devbox_id: str, json_output: bool) -> None:
    """Delete a devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Deleting devbox {devbox_id}...",
            success_text=f"Devbox deleted: {devbox_id}",
            success_emoji="🗑",
        ):
            result = devbox_client.devboxes_lifecycle.delete_devbox(devbox_id)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
    else:
        deleted_flag = getattr(result, "deleted", None)
        if deleted_flag is not None:
            click.echo(f"Deleted: {deleted_flag}")


@devbox.command("save")
@click.argument("devbox_id")
@click.argument("name")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def save_devbox(devbox_id: str, name: str, json_output: bool) -> None:
    """Create a snapshot of a devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Saving devbox {devbox_id}...",
            success_text=f"Snapshot created for {devbox_id}",
            success_emoji="💾",
        ):
            snapshot = devbox_client.devboxes_actions.save_devbox(devbox_id, name=name)
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(snapshot))
    else:
        click.echo(f"Snapshot ID: {getattr(snapshot, 'id', '')}")
        click.echo(f"Name: {getattr(snapshot, 'name', '')}")


@devbox.command("copy")
@click.argument("source")
@click.argument("destination")
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    default=False,
    help="Copy directories recursively.",
)
def copy_devbox_files(source: str, destination: str, recursive: bool) -> None:
    """
    Copy files/directories between local machine and a devbox.

    Use 'devbox_id:/path' for remote paths. Examples:
      morph devbox copy ./local.txt devbox_123:/remote/path/
      morph devbox copy devbox_123:/remote/file.log ./local_dir/
      morph devbox copy -r ./local_dir devbox_123:/remote/dir
    """
    client, devbox_client = _get_devbox_client()

    def is_remote_path(path_str: str) -> bool:
        return ":" in path_str and not path_str.startswith(":")

    source_is_remote = is_remote_path(source)
    dest_is_remote = is_remote_path(destination)
    if source_is_remote and dest_is_remote:
        raise click.UsageError("Both 'source' and 'destination' cannot be remote.")
    if not source_is_remote and not dest_is_remote:
        raise click.UsageError("Neither 'source' nor 'destination' is remote.")

    if source_is_remote:
        devbox_id, remote_path = source.split(":", 1)
        local_path = destination
        uploading = False
    else:
        devbox_id, remote_path = destination.split(":", 1)
        local_path = source
        uploading = True

    devbox_id = devbox_id.strip()
    if not devbox_id:
        raise click.UsageError("Devbox identifier is missing in remote path.")

    try:
        with Spinner(
            text=f"Waiting for devbox {devbox_id} to be ready for copy...",
            success_text=f"Devbox ready: {devbox_id}",
            success_emoji="⚡",
        ):
            _wait_for_devbox_ready(devbox_client, devbox_id, timeout=300)

        creds = devbox_client.admin.get_devbox_ssh_credentials(devbox_id)
        ssh_hostname = client.ssh_hostname
        ssh_port = _safe_int_from_env("MORPH_SSH_PORT", default=client.ssh_port)
        connect_timeout = _safe_int_from_env("DEVBOX_SSH_CONNECT_TIMEOUT", default=30)
        keepalive = _safe_int_from_env("MORPH_SSH_KEEPALIVE_SECS", default=15)

        adapter = _DevboxInstanceAdapter(
            hostname=f"{devbox_id}.{ssh_hostname}",
            port=ssh_port,
            username=creds.access_token,
            password=creds.password,
            timeout=connect_timeout,
            keepalive=keepalive,
        )

        click.echo("Starting copy operation...")
        copy_into_or_from_instance(
            instance_obj=adapter,
            local_path=local_path,
            remote_path=remote_path,
            uploading=uploading,
            recursive=recursive,
            verbose=True,
        )

    except click.ClickException:
        raise
    except TimeoutError:
        click.echo(
            f"Error: Timed out waiting for devbox {devbox_id} to become ready.",
            err=True,
        )
        sys.exit(1)
    except Exception as exc:
        handle_api_error(exc)


def register_cli_plugin(cli_group) -> None:
    """Register the devbox CLI group with the main morphcloud CLI."""
    cli_group.add_command(devbox)


@devbox.command("expose-http")
@click.argument("devbox_id")
@click.option("--name", required=True, help="Unique name for the HTTP service.")
@click.option(
    "--port", type=int, required=True, help="Local port on the devbox to expose."
)
@click.option(
    "--auth-mode",
    type=click.Choice(["none", "api_key"], case_sensitive=False),
    required=False,
    help="Authentication mode for the HTTP service.",
)
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def expose_http_service(
    devbox_id: str, name: str, port: int, auth_mode: _t.Optional[str], json_output: bool
) -> None:
    """Expose a local port as an HTTP service on the devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Exposing HTTP service '{name}' on devbox {devbox_id}...",
            success_text=f"HTTP service exposed on {devbox_id}",
            success_emoji="🌐",
        ):
            result = devbox_client.devboxes_actions.expose_http_service_on_devbox(
                devbox_id,
                name=name,
                port=port,
                auth_mode=(auth_mode.lower() if isinstance(auth_mode, str) else None),
            )
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    svc_url = _find_http_service_url(result, name)
    if svc_url:
        click.secho(f"Service '{name}' exposed at {svc_url}", fg="green")
    else:
        click.secho(f"Service '{name}' exposed", fg="green")


@devbox.command("hide-http")
@click.argument("devbox_id")
@click.option("--name", required=True, help="Name of the HTTP service to hide.")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def hide_http_service(devbox_id: str, name: str, json_output: bool) -> None:
    """Hide (unexpose) an HTTP service on the devbox."""
    _, devbox_client = _get_devbox_client()
    try:
        with Spinner(
            text=f"Hiding HTTP service '{name}' on devbox {devbox_id}...",
            success_text=f"HTTP service hidden on {devbox_id}",
            success_emoji="🙈",
        ):
            result = devbox_client.devboxes_actions.unexpose_http_service_on_devbox(
                devbox_id, name
            )
    except Exception as exc:
        handle_api_error(exc)
        return

    if json_output:
        click.echo(format_json(result))
        return

    click.secho(f"Service '{name}' is no longer exposed", fg="green")


def _get_devbox_client():
    """Return the MorphCloud client and its devbox service client."""
    client = get_client()
    return client, client.devbox


def _get_template_runner_backend():
    """Return authenticated or anonymous transport inputs for template execution."""
    settings = resolve_settings()
    if settings.api_key:
        client = get_client()
        return client, client.devbox, False

    service_api_key = (
        os.environ.get("MNW_DEVBOX_SERVICE_API_KEY")
        or os.environ.get("MORPH_DEVBOX_SERVICE_API_KEY")
        or ""
    ).strip()
    if not service_api_key:
        raise click.ClickException(
            "MORPH_API_KEY is not set. To run a shared/public template without a "
            "user API key, set MNW_DEVBOX_SERVICE_API_KEY."
        )

    devbox_client = DevboxClient(
        token=service_api_key,
        base_url=settings.devbox_base_url,
    )
    devbox_client.ssh_hostname = settings.ssh_hostname
    devbox_client.ssh_port = settings.ssh_port
    return None, devbox_client, True


def _parse_key_value_items(items: _t.Iterable[str], *, label: str) -> _t.Dict[str, str]:
    """Parse repeated key=value items."""
    data: _t.Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise click.UsageError(f"{label} must be provided as key=value.")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise click.UsageError(f"{label} keys cannot be empty.")
        data[key] = value
    return data


def _parse_metadata_options(items: _t.Iterable[str]) -> _t.Dict[str, str]:
    """Parse repeated metadata options of the form key=value."""
    return _parse_key_value_items(items, label="Metadata entries")


class _DevboxSSHContext:
    def __init__(
        self,
        *,
        hostname: str,
        port: int,
        username: str,
        password: str,
        timeout: int,
        keepalive: int,
    ):
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._timeout = timeout
        self._keepalive = keepalive
        self._client: _t.Optional[paramiko.SSHClient] = None
        self._wrapper: _t.Optional[MorphSSHClient] = None

    def __enter__(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=self._hostname,
            port=self._port,
            username=self._username,
            password=self._password,
            timeout=self._timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = ssh_client.get_transport()
        if transport is not None:
            try:
                transport.set_keepalive(self._keepalive)
            except Exception:
                pass
        self._client = ssh_client
        self._wrapper = MorphSSHClient(ssh_client)
        return self._wrapper

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._wrapper is not None:
            self._wrapper.close()
            self._wrapper = None
        self._client = None


class _DevboxInstanceAdapter:
    def __init__(
        self,
        *,
        hostname: str,
        port: int,
        username: str,
        password: str,
        timeout: int,
        keepalive: int,
    ):
        self._params = {
            "hostname": hostname,
            "port": port,
            "username": username,
            "password": password,
            "timeout": timeout,
            "keepalive": keepalive,
        }

    def ssh(self):
        return _DevboxSSHContext(**self._params)


def _instant_start_availability(
    devbox_client, template_id: str
) -> _t.Dict[str, _t.Any]:
    path = (
        f"api/templates/{_encode_template_id(template_id)}/instant-devbox/availability"
    )
    response = devbox_client._client_wrapper.httpx_client.request(path, method="GET")
    if response.status_code >= 400:
        _raise_instant_error(response, context="availability check")
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _instant_start_devbox(
    devbox_client, template_id: str, payload: _t.Optional[_t.Dict[str, _t.Any]]
) -> DevboxResponse:
    path = f"api/templates/{_encode_template_id(template_id)}/instant-devbox"
    response = devbox_client._client_wrapper.httpx_client.request(
        path,
        method="POST",
        json=payload or None,
    )
    if response.status_code >= 400:
        _raise_instant_error(response, context="start request")
    try:
        data = response.json()
    except ValueError as exc:
        raise click.ClickException(
            "Instant devbox start did not return JSON payload."
        ) from exc
    try:
        return DevboxResponse.model_validate(data)
    except Exception as exc:
        raise click.ClickException(
            "Failed to parse devbox response from instant start."
        ) from exc


def _raise_instant_error(response, *, context: str) -> None:
    message = f"Instant devbox {context} failed (status {response.status_code})"
    detail: _t.Optional[str] = None
    try:
        body = response.json()
    except ValueError:
        detail = response.text or None
    else:
        if isinstance(body, dict):
            raw_detail = body.get("detail")
            if isinstance(raw_detail, dict):
                detail = (
                    raw_detail.get("message")
                    or raw_detail.get("detail")
                    or (
                        raw_detail.get("error", {}).get("message")
                        if isinstance(raw_detail.get("error"), dict)
                        else None
                    )
                )
            elif isinstance(raw_detail, str):
                detail = raw_detail
            if not detail:
                error_block = body.get("error")
                if isinstance(error_block, dict):
                    detail = error_block.get("message")
            if not detail and isinstance(body.get("message"), str):
                detail = body["message"]
        elif isinstance(body, str):
            detail = body
    if not detail:
        detail = response.text or message
    raise click.ClickException(f"{message}: {detail}")


def _encode_template_id(template_id: str) -> str:
    return urllib.parse.quote(str(template_id), safe="")


def _wait_for_devbox_ready(devbox_client, devbox_id: str, *, timeout: int) -> _t.Any:
    """Poll the devbox until it reports READY or a terminal failure state."""
    deadline = time.time() + max(timeout, 1)
    last_status = None

    while True:
        devbox = devbox_client.devboxes_core.get_devbox(devbox_id)
        status = _normalize_status(getattr(devbox, "status", None))

        if status == _READY_STATUS:
            return devbox

        if status in _FAILURE_STATUSES:
            raise click.ClickException(
                f"Devbox {devbox_id} entered failure state '{status}'. Aborting SSH connection."
            )

        if time.time() >= deadline:
            raise click.ClickException(
                f"Timed out waiting for devbox {devbox_id} to become READY (last status: {status or 'unknown'})."
            )

        # Avoid hammering the API
        if status != last_status:
            last_status = status
        time.sleep(5)


def _resolve_name(metadata: _t.Mapping[str, _t.Any], fallback: str) -> str:
    """Best-effort display name resolution for a devbox."""
    for key in ("webUIName", "display_name", "name", "devboxName"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _format_timestamp(timestamp: _t.Optional[_t.Union[int, float]]) -> str:
    """Convert epoch seconds to a readable UTC timestamp."""
    if timestamp in (None, 0):
        return "-"
    try:
        dt = _dt.datetime.utcfromtimestamp(float(timestamp))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(timestamp)


def _normalize_status(status: _t.Optional[str]) -> str:
    if isinstance(status, str):
        return status.lower()
    return ""


def _safe_int_from_env(env_var: str, *, default: int) -> int:
    """Parse an integer from an environment variable with a fallback."""
    try:
        return int(os.environ.get(env_var, default))
    except (TypeError, ValueError):
        return default


def _truncate_text(value: _t.Any, max_width: int) -> str:
    """Truncate a value to fit within a configured column width."""
    text = "" if value is None else str(value)
    if max_width <= 0:
        return ""
    if len(text) <= max_width:
        return text
    if max_width <= 3:
        return text[:max_width]
    return text[: max_width - 3] + "..."


def _find_http_service_url(devbox: DevboxResponse, name: str) -> _t.Optional[str]:
    networking = getattr(devbox, "networking", None)
    if not networking:
        return None
    services = getattr(networking, "http_services", None) or []
    try:
        for svc in services:
            svc_name = getattr(svc, "name", None)
            if isinstance(svc_name, str) and svc_name == name:
                url = getattr(svc, "url", None)
                if isinstance(url, str) and url:
                    return url
    except Exception:
        return None
    return None
