# morphcloud/cli.py

import datetime
import importlib.metadata
import json
import sys
import threading
import time

import click
import requests
from packaging import version

import morphcloud.api as api
from morphcloud._utils import Spinner
from morphcloud.api import copy_into_or_from_instance

# ─────────────────────────────────────────────────────────────
#  Version & CLI Setup
# ─────────────────────────────────────────────────────────────

try:
    __version__ = importlib.metadata.version("morphcloud")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0-dev"  # Fallback if package not installed


def check_for_package_update(display_mode="normal"):
    """
    Check if the installed version of morphcloud is the latest available on PyPI.
    Display a notification if a newer version is available.

    Args:
        display_mode (str): How to display the notification:
            - "normal": Standard output (for --help, --version)
            - "error": To stderr with spacing (for exception hook)
            - "silent": Just return values, don't display anything

    Returns:
        tuple: (current_version, latest_version, is_latest) or None if check fails
    """
    # Skip for development versions
    if __version__ == "0.0.0-dev":
        return None

    try:
        # Query PyPI API for the latest version
        response = requests.get("https://pypi.org/pypi/morphcloud/json", timeout=2)
        response.raise_for_status()

        latest_version = response.json()["info"]["version"]

        # Compare versions
        is_latest = version.parse(__version__) >= version.parse(latest_version)

        # Display notification if not using the latest version
        if not is_latest:
            message = (
                f"NOTE: You are using morphcloud version {__version__}, however version {latest_version} "
                f"is available. Consider upgrading via: pip install --upgrade morphcloud"
            )

            if display_mode == "normal":
                click.secho(f"\n{message}\n", fg="yellow")
            elif display_mode == "error":
                # When coming from exception hook, add spacing and output to stderr
                click.secho(f"\n{message}", fg="yellow", err=True)

        return (__version__, latest_version, is_latest)

    except Exception:
        # Silently handle any errors (network issues, package not found, etc.)
        return None


# Custom command class that supports aliases
class AliasedCommand(click.Command):
    def __init__(self, name, aliases=None, **kwargs):
        super().__init__(name, **kwargs)
        self.aliases = aliases or []


# Custom group class that supports command aliases
class AliasedGroup(click.Group):
    def command(self, *args, **kwargs):
        """Custom command decorator that supports aliases."""
        aliases = kwargs.pop("aliases", None)
        decorator = super().command(*args, **kwargs)

        if aliases:

            def _decorator(f):
                cmd = decorator(f)
                if cmd.name:
                    for alias in aliases:
                        self.add_command(cmd, name=alias)
                return cmd

            return _decorator
        return decorator

    def get_command(self, ctx, name):
        rv = click.Group.get_command(self, ctx, name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx) if x.startswith(name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail(f"Too many matches: {', '.join(sorted(matches))}")


# Replace your CustomGroup class with this enhanced version


class VersionCheckGroup(AliasedGroup):
    """
    Custom Click Group that adds version checking on help display
    and also when errors occur.
    """

    def format_help(self, ctx, formatter):
        # Prepend version information to help text
        formatter.write_text(f"Version: {__version__}\n\n")
        super().format_help(ctx, formatter)

        # Check for updates after displaying help
        if "--help" in sys.argv or "-h" in sys.argv:
            check_for_package_update()

    def get_command(self, ctx, cmd_name):
        # Add update check when --version is run
        if cmd_name == "--version":
            check_for_package_update()
        return super().get_command(ctx, cmd_name)

    def main(self, *args, **kwargs):
        try:
            return super().main(*args, **kwargs)
        except click.exceptions.ClickException:
            # Let Click handle its own exceptions, but check version after
            # We need to raise first so Click can display the error
            exctype, value, tb = sys.exc_info()
            raise
        except Exception as e:
            # For non-Click exceptions, check version before letting the exception propagate
            check_for_package_update(display_mode="error")
            raise


def load_cli_plugins(cli_group: click.Group):
    """Load CLI plugins from entry points."""
    import importlib.metadata

    try:
        plugin_entry_points = importlib.metadata.entry_points(
            group="morphcloud.cli_plugins"
        )
        for entry_point in plugin_entry_points:
            plugin_loader_func = entry_point.load()
            plugin_loader_func(cli_group)
    except Exception:
        pass


@click.group(cls=VersionCheckGroup)
@click.version_option(version=__version__, package_name="morphcloud")
def cli():
    """
    Morph Cloud CLI - A tool for creating, managing, and interacting with Morph Cloud resources.
    """
    pass


# ─────────────────────────────────────────────────────────────
#  Utilities
# ─────────────────────────────────────────────────────────────


def format_json(obj):
    """Helper to pretty print Pydantic models or other objects as JSON."""
    if hasattr(obj, "model_dump"):
        data_to_dump = obj.model_dump()
    elif hasattr(obj, "dict"):
        data_to_dump = obj.dict()
    else:
        data_to_dump = obj
    return json.dumps(data_to_dump, indent=2)


def print_docker_style_table(headers, rows):
    """Print a table in Docker ps style with dynamic column widths using Click's echo."""
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


def unix_timestamp_to_datetime(timestamp):
    """Convert a Unix timestamp to a human-readable UTC datetime string."""
    try:
        if timestamp is None or not isinstance(timestamp, (int, float)):
            return "N/A"
        dt_object = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        return dt_object.strftime("%Y-%m-%d %H:%M:%S %Z")
    except (OSError, TypeError, ValueError):
        try:
            dt_object = datetime.datetime.utcfromtimestamp(timestamp)
            return dt_object.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "Invalid Timestamp"


def get_client():
    """Get or create a MorphCloudClient instance. Raises error if API key is missing."""
    try:
        return api.MorphCloudClient()
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
                "You can generate API keys at: https://cloud.morph.so/web/keys",
                err=True,
            )
            sys.exit(1)
        raise


def handle_api_error(error):
    """Handle API errors with user-friendly messages."""
    if isinstance(error, api.ApiError):
        click.echo(f"API Error (Status Code: {error.status_code})", err=True)
        click.echo(f"Response Body: {error.response_body}", err=True)
    elif isinstance(error, click.ClickException):
        raise error
    else:
        click.echo(f"An unexpected error occurred: {error}", err=True)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
#  User Commands
# ─────────────────────────────────────────────────────────────


@cli.group(cls=AliasedGroup)
def user():
    """Manage settings for the current authenticated user."""
    pass


# ── API Keys ────────────────────────────────────────────────


@user.group(cls=AliasedGroup, name="api-key")
def user_api_key():
    """Manage user API keys."""
    pass


@user_api_key.command(name="list", aliases=["ls"])
@click.option("--json", "json_mode", is_flag=True, default=False)
def user_api_key_list(json_mode):
    client = get_client()
    try:
        keys = client.user.list_api_keys()
        if json_mode:
            for k in keys:
                click.echo(format_json(k))
        else:
            headers = ["ID", "Prefix", "Created", "Last Used"]
            rows = [
                [
                    k.id,
                    k.key_prefix,
                    unix_timestamp_to_datetime(k.created),
                    unix_timestamp_to_datetime(k.last_used),
                ]
                for k in keys
            ]
            print_docker_style_table(headers, rows)
    except Exception as e:
        handle_api_error(e)


@user_api_key.command(name="create", aliases=["new"])
@click.option("--json", "json_mode", is_flag=True, default=False)
def user_api_key_create(json_mode):
    client = get_client()
    try:
        with Spinner(
            text="Creating API key...",
            success_text="API key created",
            success_emoji="🔑",
        ):
            resp = client.user.create_api_key()
        if json_mode:
            click.echo(format_json(resp))
        else:
            click.secho("API key created.", fg="green")
            click.echo(f"ID: {resp.id}")
            click.echo(f"Prefix: {resp.key_prefix}")
            click.echo(f"Created: {unix_timestamp_to_datetime(resp.created)}")
            click.secho(
                "This is your API key — it will not be shown again:", fg="yellow"
            )
            click.secho(resp.key, fg="yellow")
    except Exception as e:
        handle_api_error(e)


@user_api_key.command(name="delete", aliases=["rm"])
@click.argument("api_key_id")
def user_api_key_delete(api_key_id):
    client = get_client()
    try:
        with Spinner(
            text=f"Deleting API key {api_key_id}...",
            success_text="API key deleted",
            success_emoji="🗑",
        ):
            client.user.delete_api_key(api_key_id)
    except Exception as e:
        handle_api_error(e)


# ── SSH Key ─────────────────────────────────────────────────


@user.group(cls=AliasedGroup, name="ssh-key")
def user_ssh_key():
    """Manage user SSH public key."""
    pass


@user_ssh_key.command(name="get")
@click.option("--json", "json_mode", is_flag=True, default=False)
def user_ssh_key_get(json_mode):
    client = get_client()
    try:
        info = client.user.get_ssh_key()
        if json_mode:
            click.echo(format_json(info))
        else:
            headers = ["Public Key", "Created"]
            rows = [[info.public_key, unix_timestamp_to_datetime(info.created)]]
            print_docker_style_table(headers, rows)
    except Exception as e:
        handle_api_error(e)


@user_ssh_key.command(name="set", aliases=["update"])
@click.option(
    "--public-key",
    required=True,
    help="SSH public key string (e.g., 'ssh-rsa AAAA...')",
)
@click.option("--json", "json_mode", is_flag=True, default=False)
def user_ssh_key_set(public_key, json_mode):
    client = get_client()
    try:
        with Spinner(
            text="Updating SSH key...",
            success_text="SSH key updated",
            success_emoji="🔐",
        ):
            info = client.user.update_ssh_key(public_key)
        if json_mode:
            click.echo(format_json(info))
        else:
            click.secho("SSH key updated.", fg="green")
            click.echo(f"Created: {unix_timestamp_to_datetime(info.created)}")
    except Exception as e:
        handle_api_error(e)


# ── Usage ───────────────────────────────────────────────────


@user.command(name="usage")
@click.option("--interval", default=None, help="Lookback window (e.g., 30m, 3h, 7d)")
@click.option("--json", "json_mode", is_flag=True, default=False)
def user_usage(interval, json_mode):
    client = get_client()
    try:
        usage = client.user.usage(interval=interval)
        if json_mode:
            click.echo(format_json(usage))
        else:
            click.secho("User usage overview", fg="green")
            click.echo(f"Interval buckets: {len(usage.items)}")
            if usage.instance:
                last = usage.instance[-1]
                click.echo(
                    f"Last bucket instance CPU: {last.instance_cpu_time}, MEM: {last.instance_memory_time}, DISK: {last.instance_disk_time}"
                )
            if usage.snapshot:
                last = usage.snapshot[-1]
                click.echo(
                    f"Last bucket snapshot MEM: {last.snapshot_memory_time}, DISK: {last.snapshot_disk_time}"
                )
    except Exception as e:
        handle_api_error(e)


# ─────────────────────────────────────────────────────────────
#  Image Commands
# ─────────────────────────────────────────────────────────────


@cli.group(cls=AliasedGroup)
def image():
    """Manage Morph base images."""
    pass


@image.command(name="list", aliases=["ls"])
@click.option(
    "--json", "json_mode", is_flag=True, default=False, help="Output in JSON format."
)
def list_image(json_mode):
    """List all available images."""
    client = get_client()
    try:
        images = client.images.list()
        if json_mode:
            for img in images:
                click.echo(format_json(img))
        else:
            headers = ["ID", "Name", "Description", "Disk Size (MB)", "Created At"]
            rows = []
            for image in images:
                rows.append(
                    [
                        image.id,
                        image.name,
                        image.description,
                        image.disk_size,  # API returns MB
                        unix_timestamp_to_datetime(image.created),
                    ]
                )
            print_docker_style_table(headers, rows)
    except Exception as e:
        handle_api_error(e)


# ─────────────────────────────────────────────────────────────
#  Snapshot Commands
# ─────────────────────────────────────────────────────────────


@cli.group(cls=AliasedGroup)
def snapshot():
    """Manage Morph snapshots (VM states)."""
    pass


@snapshot.command(name="list", aliases=["ls"])
@click.option(
    "--metadata",
    "-m",
    help="Filter snapshots by metadata (format: key=value)",
    multiple=True,
)
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def list_snapshots(metadata, json_mode):
    """List all snapshots."""
    client = get_client()
    try:
        metadata_dict = {}
        for meta in metadata:
            key, value = meta.split("=", 1)
            metadata_dict[key] = value
        snapshots = client.snapshots.list(metadata=metadata_dict)
        if json_mode:
            for snap in snapshots:
                click.echo(format_json(snap))
        else:
            headers = [
                "ID",
                "Created At",
                "Status",
                "VCPUs",
                "Memory (MB)",
                "Disk Size (MB)",
                "Image ID",
            ]
            rows = []
            for snap in snapshots:
                rows.append(
                    [
                        snap.id,
                        unix_timestamp_to_datetime(snap.created),
                        snap.status,
                        snap.spec.vcpus,
                        snap.spec.memory,
                        snap.spec.disk_size,
                        snap.refs.image_id,
                    ]
                )
            print_docker_style_table(headers, rows)
    except Exception as e:
        handle_api_error(e)


@snapshot.command("create")
@click.option("--image-id", required=True, help="ID of the base image to use.")
@click.option("--vcpus", type=int, required=True, help="Number of virtual CPUs.")
@click.option("--memory", type=int, required=True, help="Memory in Megabytes (MB).")
@click.option(
    "--disk-size", type=int, required=True, help="Disk size in Megabytes (MB)."
)
@click.option("--digest", help="Optional unique digest for caching/identification.")
@click.option(
    "--metadata",
    "-m",
    "metadata_options",
    help="Metadata to attach (format: key=value).",
    multiple=True,
)
@click.option(
    "--json", "json_mode", is_flag=True, default=False, help="Output result as JSON."
)
def create_snapshot(
    image_id, vcpus, memory, disk_size, digest, metadata_options, json_mode
):
    """Create a new snapshot from a base image and specifications."""
    client = get_client()
    try:
        metadata_dict = {}
        for meta in metadata_options:
            if "=" not in meta:
                raise click.UsageError("Metadata option must be in key=value format.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v

        with Spinner(
            text=f"Creating snapshot from base image {image_id}...",
            success_text="Snapshot creation complete!",
            success_emoji="📸",
        ):
            new_snapshot = client.snapshots.create(
                image_id=image_id,
                vcpus=vcpus,
                memory=memory,
                disk_size=disk_size,
                digest=digest,
                metadata=metadata_dict if metadata_dict else None,
            )

        if json_mode:
            click.echo(format_json(new_snapshot))
        else:
            click.secho(f"Snapshot created: {new_snapshot.id}", fg="green")
            if new_snapshot.digest:
                click.echo(f"Digest: {new_snapshot.digest}")
    except Exception as e:
        handle_api_error(e)


@snapshot.command("delete")
@click.argument("snapshot_id")
def delete_snapshot(snapshot_id):
    """Delete a specific snapshot by its ID."""
    client = get_client()
    try:
        with Spinner(
            text=f"Deleting snapshot {snapshot_id}...",
            success_text=f"Snapshot deleted: {snapshot_id}",
            success_emoji="🗑",
        ):
            snap_obj = client.snapshots.get(snapshot_id)
            snap_obj.delete()
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Snapshot '{snapshot_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@snapshot.command("get")
@click.argument("snapshot_id")
def get_snapshot(snapshot_id):
    """Get detailed information about a specific snapshot (outputs JSON)."""
    client = get_client()
    try:
        snapshot_obj = client.snapshots.get(snapshot_id)
        click.echo(format_json(snapshot_obj))
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Snapshot '{snapshot_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@snapshot.command("set-metadata")
@click.argument("snapshot_id")
@click.option(
    "--metadata",
    "-m",
    help="Metadata to attach (format: key=value)",
    multiple=True,
)
@click.argument("metadata_args", nargs=-1, required=False)
def set_snapshot_metadata(snapshot_id, metadata, metadata_args):
    """
    Set or update metadata on a snapshot.

    Example:
        morph snapshot set-metadata snap_123 key1=value1 "key 2=value with spaces"
    """
    client = get_client()
    try:
        snapshot_obj = client.snapshots.get(snapshot_id)

        metadata_dict = {}
        for meta in metadata_args:
            if "=" not in meta:
                raise click.UsageError("Metadata must be in key=value format.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v
        for meta in metadata:
            if "=" not in meta:
                raise click.UsageError("Metadata must be in key=value format.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v

        with Spinner(
            text=f"Updating metadata on snapshot {snapshot_id}...",
            success_text=f"Metadata updated: {snapshot_id}",
            success_emoji="📝",
        ):
            snapshot_obj.set_metadata(metadata_dict)

        updated = client.snapshots.get(snapshot_id)
        click.echo(format_json(updated))
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Snapshot '{snapshot_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


# ─────────────────────────────────────────────────────────────
#  Instance Commands
# ─────────────────────────────────────────────────────────────


@cli.group(cls=AliasedGroup)
def instance():
    """Manage Morph instances."""
    pass


@instance.command(name="list", aliases=["ls"])
@click.option(
    "--metadata", "-m", help="Filter instances by metadata (key=value)", multiple=True
)
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def list_instances(metadata, json_mode):
    """List all instances."""
    client = get_client()
    try:
        metadata_dict = {}
        for meta in metadata:
            key, value = meta.split("=", 1)
            metadata_dict[key] = value

        instances = client.instances.list(metadata=metadata_dict)
        if json_mode:
            for inst in instances:
                click.echo(format_json(inst))
        else:
            headers = [
                "ID",
                "Snapshot ID",
                "Created At",
                "Status",
                "VCPUs",
                "Memory (MB)",
                "Disk Size (MB)",
                "Http Services",
            ]
            rows = []
            total_vcpus = 0
            total_memory_mb = 0
            total_disk_mb = 0

            for inst in instances:
                rows.append(
                    [
                        inst.id,
                        inst.refs.snapshot_id,
                        unix_timestamp_to_datetime(inst.created),
                        inst.status,
                        inst.spec.vcpus,
                        inst.spec.memory,
                        inst.spec.disk_size,
                        ", ".join(
                            f"{svc.name}:{svc.port}"
                            for svc in inst.networking.http_services
                        ),
                    ]
                )
                # Accumulate totals
                total_vcpus += inst.spec.vcpus
                total_memory_mb += inst.spec.memory
                total_disk_mb += inst.spec.disk_size

            # Add totals row if there are instances
            if instances:
                # Add a separator row (dashes)
                separator_row = [
                    "─" * 10,
                    "─" * 10,
                    "─" * 10,
                    "─" * 10,
                    "─" * 5,
                    "─" * 10,
                    "─" * 10,
                    "─" * 10,
                ]
                rows.append(separator_row)

                # Add totals row
                totals_row = [
                    f"{len(instances)} instances",  # Total count in ID column
                    "",  # Blank snapshot ID
                    "",  # Blank created at
                    "",  # Blank status
                    total_vcpus,  # Total vCPUs
                    f"{total_memory_mb / 1024:.1f} GB",  # Memory in GB
                    f"{total_disk_mb / 1024:.1f} GB",  # Disk in GB
                    "",  # Blank HTTP services
                ]
                rows.append(totals_row)

            print_docker_style_table(headers, rows)
    except Exception as e:
        handle_api_error(e)


@instance.command("start")
@click.argument("snapshot_id")
@click.option(
    "--metadata", "-m", "metadata_options", help="Metadata (key=value).", multiple=True
)
@click.option("--ttl-seconds", type=int, help="Time-to-live in seconds.")
@click.option(
    "--ttl-action",
    type=click.Choice(["stop", "pause"]),
    help="Action when TTL expires.",
)
@click.option(
    "--json", "json_mode", is_flag=True, default=False, help="Output result as JSON."
)
def start_instance(snapshot_id, metadata_options, ttl_seconds, ttl_action, json_mode):
    """Start a new instance from a snapshot."""
    client = get_client()
    try:
        metadata_dict = {}
        for meta in metadata_options:
            if "=" not in meta:
                raise click.UsageError("Metadata must be key=value.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v

        with Spinner(
            text=f"Starting instance from snapshot {snapshot_id}...",
            success_text="Instance start complete!",
            success_emoji="🚀",
        ):
            new_instance = client.instances.start(
                snapshot_id=snapshot_id,
                metadata=metadata_dict if metadata_dict else None,
                ttl_seconds=ttl_seconds,
                ttl_action=ttl_action,
            )

        if json_mode:
            click.echo(format_json(new_instance))
        else:
            click.secho(f"Instance started: {new_instance.id}", fg="green")
            click.echo(f"Status: {new_instance.status.value}")
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Snapshot '{snapshot_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("stop")
@click.argument("instance_id")
def stop_instance(instance_id):
    """Stop (terminate) a running or paused instance."""
    client = get_client()
    try:
        with Spinner(
            text=f"Stopping instance {instance_id}...",
            success_text=f"Instance stopped: {instance_id}",
            success_emoji="🛑",
        ):
            client.instances.stop(instance_id)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("pause")
@click.argument("instance_id")
def pause_instance(instance_id):
    """Pause a running instance (preserves state)."""
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        with Spinner(
            text=f"Pausing instance {instance_id}...",
            success_text=f"Instance paused: {instance_id}",
            success_emoji="⏸",
        ):
            instance_obj.pause()
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        elif e.status_code == 409:
            click.echo(
                f"Error: Instance '{instance_id}' cannot be paused ({e.response_body}).",
                err=True,
            )
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("resume")
@click.argument("instance_id")
def resume_instance(instance_id):
    """Resume a previously paused instance."""
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        with Spinner(
            text=f"Resuming instance {instance_id}...",
            success_text=f"Instance resumed: {instance_id}",
            success_emoji="⏯",
        ):
            instance_obj.resume()
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        elif e.status_code == 409:
            click.echo(
                f"Error: Instance '{instance_id}' cannot be resumed ({e.response_body}).",
                err=True,
            )
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("get")
@click.argument("instance_id")
def get_instance(instance_id):
    """Get detailed information about a specific instance (JSON)."""
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        click.echo(format_json(instance_obj))
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("snapshot")
@click.argument("instance_id")
@click.option("--digest", help="Optional unique digest.")
@click.option(
    "--metadata",
    "-m",
    help="Metadata to attach (format: key=value)",
    multiple=True,
)
@click.option(
    "--json", "json_mode", is_flag=True, default=False, help="Output result as JSON."
)
def snapshot_instance(instance_id, digest, metadata, json_mode):
    """Create a new snapshot from an instance."""
    client = get_client()

    if metadata:
        metadata_dict = {}
        for meta in metadata:
            if "=" not in meta:
                raise click.UsageError("Metadata must be key=value.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v
    else:
        metadata_dict = None

    try:
        instance_obj = client.instances.get(instance_id)
        if instance_obj.status not in [
            api.InstanceStatus.READY,
            api.InstanceStatus.PAUSED,
        ]:
            click.echo(
                f"Error: Instance must be READY or PAUSED. Current: {instance_obj.status.value}",
                err=True,
            )
            sys.exit(1)

        with Spinner(
            text=f"Creating snapshot from {instance_id}...",
            success_text="Instance snapshot complete!",
            success_emoji="📸",
        ):
            new_snapshot = instance_obj.snapshot(digest=digest, metadata=metadata_dict)

        if json_mode:
            click.echo(format_json(new_snapshot))
        else:
            click.secho(f"Snapshot created: {new_snapshot.id}", fg="green")
            if new_snapshot.digest:
                click.echo(f"Digest: {new_snapshot.digest}")
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        elif e.status_code == 409:
            click.echo(
                f"Error: Instance '{instance_id}' cannot be snapshotted ({e.response_body}).",
                err=True,
            )
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("branch")
@click.argument("instance_id")
@click.option(
    "--count",
    type=int,
    default=1,
    show_default=True,
    help="Number of new instances to create.",
)
@click.option(
    "--json", "json_mode", is_flag=True, default=False, help="Output result as JSON."
)
def branch_instance(instance_id, count, json_mode):
    """Snapshot and launch multiple new instances from it (branching)."""
    if count < 1:
        raise click.UsageError("Count must be >= 1.")
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        if instance_obj.status not in [
            api.InstanceStatus.READY,
            api.InstanceStatus.PAUSED,
        ]:
            click.echo(
                f"Error: Instance must be READY or PAUSED. Current: {instance_obj.status.value}",
                err=True,
            )
            sys.exit(1)

        with Spinner(
            text=f"Branching instance {instance_id} into {count} new instance(s)...",
            success_text="Branch operation complete!",
            success_emoji="🌱",
        ):
            snapshot_obj, new_instances = instance_obj.branch(count)

        if json_mode:
            result = {
                "snapshot": snapshot_obj.model_dump(),
                "new_instances": [inst.model_dump() for inst in new_instances],
            }
            click.echo(json.dumps(result, indent=2))
        else:
            click.secho(f"Created intermediate snapshot: {snapshot_obj.id}", fg="green")
            click.echo("Started new instances:")
            for inst in new_instances:
                click.echo(f"- {inst.id} (Status: {inst.status.value})")
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        elif e.status_code == 409:
            click.echo(
                f"Error: Instance '{instance_id}' cannot be branched ({e.response_body}).",
                err=True,
            )
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("expose-http")
@click.argument("instance_id")
@click.argument("name")
@click.argument("port", type=int)
@click.option(
    "--auth-mode",
    type=click.Choice(["none", "api_key"]),
    default="none",
    help="Auth mode.",
)
def expose_http_service(instance_id, name, port, auth_mode):
    """
    Expose an HTTP service on an instance to a public URL.
    """
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        if instance_obj.status != api.InstanceStatus.READY:
            click.echo(
                f"Error: Instance must be READY to expose services. Current: {instance_obj.status.value}",
                err=True,
            )
            sys.exit(1)

        with Spinner(
            text=f"Exposing '{name}' on {instance_id} (port {port})...",
            success_text="Service exposed successfully!",
            success_emoji="🌐",
        ):
            auth_param = auth_mode if auth_mode == "api_key" else None
            service_url = instance_obj.expose_http_service(name, port, auth_param)

        click.echo(f"URL: {service_url}")
        if auth_param == "api_key":
            click.echo("Authentication: API key required")
        else:
            click.echo("Authentication: None")
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        elif e.status_code == 409:
            click.echo(
                f"Error: Could not expose service (Conflict: {e.response_body}).",
                err=True,
            )
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("hide-http")
@click.argument("instance_id")
@click.argument("name")
def hide_http_service(instance_id, name):
    """
    Hide a previously exposed HTTP service.
    """
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        with Spinner(
            text=f"Hiding service '{name}' on {instance_id}...",
            success_text=f"Service '{name}' hidden successfully.",
            success_emoji="🙈",
        ):
            instance_obj.hide_http_service(name)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(
                f"Error: Instance '{instance_id}' or Service '{name}' not found.",
                err=True,
            )
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("exec")
@click.argument("instance_id")
@click.argument("command_args", nargs=-1, required=True)
def exec_command(instance_id, command_args):
    """
    Execute a command inside an instance and print output.
    """
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        # if instance_obj.status != api.InstanceStatus.READY:
        #     click.echo(
        #         f"Error: Instance must be READY to execute commands. Current: {instance_obj.status.value}",
        #         err=True,
        #     )
        #     sys.exit(1)

        cmd_str = " ".join(command_args)
        with Spinner(
            text=f"Executing: {cmd_str} on {instance_id}...",
            success_text="Command execution complete!",
            success_emoji="🏁",
        ):
            result = instance_obj.exec(list(command_args))

        if result.stdout:
            click.echo("--- Stdout ---")
            click.echo(result.stdout.strip())
        if result.stderr:
            click.echo("--- Stderr ---", err=True)
            click.echo(result.stderr.strip(), err=True)

        click.echo(f"--- Exit Code: {result.exit_code} ---")
        sys.exit(result.exit_code)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("set-metadata")
@click.argument("instance_id")
@click.option(
    "--metadata",
    "-m",
    help="Metadata to attach (format: key=value)",
    multiple=True,
)
@click.argument("metadata_args", nargs=-1, required=False)
def set_instance_metadata(instance_id, metadata, metadata_args):
    """
    Set or update metadata on an instance.
    """
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        metadata_dict = {}
        for meta in metadata_args:
            if "=" not in meta:
                raise click.UsageError("Metadata must be in key=value format.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v

        for meta in metadata:
            if "=" not in meta:
                raise click.UsageError("Metadata must be in key=value format.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v

        # set_metadata is typically quick, so no spinner needed here
        instance_obj.set_metadata(metadata_dict)

        updated_instance = client.instances.get(instance_id)
        click.echo(f"Metadata updated for {instance_id}:")
        click.echo(format_json(updated_instance))
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("set-ttl")
@click.argument("instance_id")
@click.option(
    "--ttl-seconds",
    type=int,
    required=True,
    help="Time-to-live in seconds. Use -1 to remove TTL.",
)
@click.option(
    "--ttl-action",
    type=click.Choice(["stop", "pause"]),
    required=False,
    help="Action when TTL expires.",
    default="stop",
)
def set_instance_ttl(instance_id, ttl_seconds, ttl_action):
    """
    Set or remove a time-to-live (TTL) for an instance.
    The instance will be stopped or paused when the TTL expires.
    Pass --ttl-seconds -1 to remove TTL.
    """
    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)
        if instance_obj.status != api.InstanceStatus.READY:
            click.echo(
                f"Error: Instance must be READY to set TTL. Current: {instance_obj.status.value}",
                err=True,
            )
            sys.exit(1)

        removing = ttl_seconds == -1
        spinner_text = (
            f"Removing TTL for {instance_id}..."
            if removing
            else f"Setting TTL for {instance_id} to {ttl_seconds} seconds..."
        )
        success_text = (
            "TTL removed successfully!" if removing else "TTL set successfully!"
        )
        with Spinner(
            text=spinner_text,
            success_text=success_text,
            success_emoji="⏳",
        ):
            instance_obj.set_ttl(None if removing else ttl_seconds, ttl_action)

        if removing:
            click.echo(f"TTL removed for {instance_id}")
        else:
            click.echo(f"TTL set for {instance_id}: {ttl_seconds} seconds")
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("set-wake-on")
@click.argument("instance_id")
@click.option(
    "--ssh",
    "wake_on_ssh",
    type=click.BOOL,
    default=None,
    help="Enable or disable wake-on-SSH. Accepts true/false.",
)
@click.option(
    "--http",
    "wake_on_http",
    type=click.BOOL,
    default=None,
    help="Enable or disable wake-on-HTTP. Accepts true/false.",
)
def set_wake_on(instance_id, wake_on_ssh, wake_on_http):
    """
    Configure the wake-on-event settings for an instance.
    """
    if wake_on_ssh is None and wake_on_http is None:
        click.echo(
            "Error: You must specify at least one option: --ssh or --http.", err=True
        )
        sys.exit(1)

    client = get_client()
    try:
        instance_obj = client.instances.get(instance_id)

        # Build a readable string for the spinner
        changes = []
        if wake_on_ssh is not None:
            changes.append(f"wake-on-ssh to {wake_on_ssh}")
        if wake_on_http is not None:
            changes.append(f"wake-on-http to {wake_on_http}")
        change_str = " and ".join(changes)

        with Spinner(
            text=f"Setting {change_str} for {instance_id}...",
            success_text="Wake-on-event settings updated successfully!",
            success_emoji="⚙️",
        ):
            instance_obj.set_wake_on(wake_on_ssh=wake_on_ssh, wake_on_http=wake_on_http)

        click.secho(f"Successfully updated settings for {instance_id}.", fg="green")

    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("ssh")
@click.argument("instance_id")
@click.option("--rm", is_flag=True, default=False, help="Stop the instance after SSH.")
@click.option(
    "--snapshot",
    "create_snapshot_on_exit",
    is_flag=True,
    default=False,
    help="Snapshot before stopping (requires --rm or manual stop).",
)
@click.argument("remote_command", nargs=-1, required=False, type=click.UNPROCESSED)
def ssh_portal(instance_id, rm, create_snapshot_on_exit, remote_command):
    """Start an interactive SSH session or run a command on an instance."""
    client = get_client()
    exit_code = 1
    instance_obj = None

    try:
        instance_obj = client.instances.get(instance_id)

        # --- REFACTORED BLOCK: Explicit status check ---
        status = instance_obj.status
        if status == api.InstanceStatus.PAUSED:
            # Check if wake-on-ssh is enabled
            if instance_obj.wake_on.wake_on_ssh:
                click.secho(
                    f"Instance {instance_id} is PAUSED. Attempting to resume via wake-on-SSH...",
                    fg="yellow",
                )
            else:
                click.echo(
                    f"Error: Instance {instance_id} is PAUSED and wake-on-SSH is not enabled.",
                    err=True,
                )
                click.echo(
                    "Please run 'morph instance resume <INSTANCE_ID>' first.", err=True
                )
                sys.exit(1)
        elif status == api.InstanceStatus.PENDING:
            click.secho(
                f"Instance {instance_id} is PENDING, waiting for it to become ready...",
                fg="cyan",
            )
        elif status != api.InstanceStatus.READY:
            click.echo(
                f"Error: Cannot SSH into instance with status '{status.value}'.",
                err=True,
            )
            sys.exit(1)
        # --- END OF REFACTORED BLOCK ---

        # The rest of the function remains the same, as the SDK's ssh() method
        # handles the connection details.
        with Spinner(
            text="Connecting via SSH...",
            success_text="SSH connection established",
            success_emoji="🔌",
            color="cyan",
        ):
            # The instance_obj.ssh() call will trigger the auto-resume logic in the SDK
            ssh_ctx = instance_obj.ssh()
            ssh = ssh_ctx.__enter__()

        is_interactive = sys.stdin.isatty() and not remote_command
        if is_interactive:
            click.secho("💻 Starting interactive SSH shell...", fg="magenta")
            exit_code = ssh.interactive_shell()
        else:
            cmd_str = " ".join(remote_command) if remote_command else None
            if not cmd_str:
                raise click.UsageError(
                    "Command must be provided in non-interactive mode or if stdin is not a TTY."
                )
            click.secho(f"🛸 Running remote command: {cmd_str}", fg="yellow")
            result = ssh.run(cmd_str)
            if result.stdout:
                click.echo(result.stdout.strip())
            if result.stderr:
                click.echo(result.stderr.strip(), err=True)
            exit_code = result.returncode
            click.echo(f"Remote command exited with code {exit_code}")

        ssh_ctx.__exit__(None, None, None)

    except TimeoutError:
        click.echo(
            f"Error: Timed out waiting for {instance_id} to become ready.", err=True
        )
        sys.exit(1)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)
    finally:
        if instance_obj:
            if create_snapshot_on_exit:
                with Spinner(
                    text="Creating snapshot before exiting...",
                    success_text="Snapshot created",
                    success_emoji="📸",
                ):
                    snap = instance_obj.snapshot()
                click.echo(f"Snapshot ID: {snap.id}")

            if rm:
                with Spinner(
                    text=f"Stopping instance {instance_id}...",
                    success_text=f"Instance stopped: {instance_id}",
                    success_emoji="🛑",
                ):
                    client.instances.stop(instance_id)

    sys.exit(exit_code)


@instance.command("port-forward")
@click.argument("instance_id")
@click.argument("remote_port", type=int)
@click.argument("local_port", type=int, required=False)
def port_forward(instance_id, remote_port, local_port):
    """
    Forward a port from the instance to your local machine.

    Example:
        morph instance port-forward inst_123 8080 8000
    """
    local_port = local_port or remote_port
    client = get_client()
    try:
        with Spinner(
            text=f"Waiting for {instance_id} to be ready...",
            success_text=f"Instance ready: {instance_id}",
            success_emoji="⚡",
        ):
            instance_obj = client.instances.get(instance_id)
            instance_obj.wait_until_ready(timeout=300)

        click.echo("Setting up port forward...")
        with (
            instance_obj.ssh() as ssh,
            ssh.tunnel(local_port=local_port, remote_port=remote_port) as tunnel,
        ):
            click.echo(
                f"Forwarding remote port {remote_port} to localhost:{local_port}"
            )
            click.echo("Press Ctrl+C to stop.")
            tunnel.wait()
    except TimeoutError:
        click.echo(f"Error: Timed out waiting for {instance_id} to be ready.", err=True)
        sys.exit(1)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except KeyboardInterrupt:
        click.echo("\nPort forwarding stopped.")
        sys.exit(0)
    except Exception as e:
        click.echo(f"Port forwarding error: {e}", err=True)
        handle_api_error(e)


@instance.command("copy")
@click.argument("source")
@click.argument("destination")
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    default=False,
    help="Copy directories recursively.",
)
def copy_files(source, destination, recursive):
    """
    Copy files/directories between local machine and a Morph instance.

    Use 'instance_id:/path' for remote paths. Examples:
      morph instance copy ./local.txt inst_123:/remote/path/
      morph instance copy inst_123:/remote/file.log ./local_dir/
      morph instance copy -r ./local_dir inst_123:/remote/dir
    """
    client = get_client()

    # Helper to determine if a path is remote by checking for "instance_id:/..."
    def is_remote_path(path_str):
        return ":" in path_str and not path_str.startswith(":")

    # Exactly one side must be remote
    source_is_remote = is_remote_path(source)
    dest_is_remote = is_remote_path(destination)
    if source_is_remote and dest_is_remote:
        raise click.UsageError("Both 'source' and 'destination' cannot be remote.")
    if not source_is_remote and not dest_is_remote:
        raise click.UsageError("Neither 'source' nor 'destination' is remote.")

    if source_is_remote:
        # Download direction: remote → local
        instance_id, remote_path = source.split(":", 1)
        local_path = destination
        uploading = False
    else:
        # Upload direction: local → remote
        instance_id, remote_path = destination.split(":", 1)
        local_path = source
        uploading = True

    try:
        instance_obj = client.instances.get(instance_id)
        # Wait for instance to become ready
        with Spinner(
            text=f"Waiting for instance {instance_id} to be ready for copy...",
            success_text=f"Instance ready: {instance_id}",
            success_emoji="⚡",
        ):
            instance_obj.wait_until_ready(timeout=300)

        click.echo("Starting copy operation...")

        # Now we call the "pure" helper
        copy_into_or_from_instance(
            instance_obj=instance_obj,
            local_path=local_path,
            remote_path=remote_path,
            uploading=uploading,
            recursive=recursive,
            verbose=True,
        )

    except TimeoutError:
        click.echo(
            f"Error: Timed out waiting for instance {instance_id} to become ready.",
            err=True,
        )
        sys.exit(1)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("chat")
@click.argument("instance_id")
@click.option(
    "--conversation-file",
    "-f",
    type=click.Path(dir_okay=False),
    help="Path to a conversation file.",
)
@click.argument("instructions", nargs=-1, required=False, type=click.UNPROCESSED)
def chat(instance_id, conversation_file, instructions):
    """Start an interactive LLM agent chat session with an instance."""
    client = get_client()
    try:
        from morphcloud._llm import agent_loop

        instance_obj = client.instances.get(instance_id)
        with Spinner(
            text=f"Waiting for instance {instance_id} to be ready for chat...",
            success_text=f"Instance ready for chat: {instance_id}",
            success_emoji="💬",
        ):
            instance_obj.wait_until_ready(timeout=300)

        click.echo("Starting chat agent...")

        initial_prompt = " ".join(instructions) if instructions else None
        agent_loop(
            instance_obj,
            initial_prompt=initial_prompt,
            conversation_file=conversation_file,
        )
    except ImportError:
        click.echo(
            "Error: Chat requires additional dependencies (e.g., 'anthropic').",
            err=True,
        )
        sys.exit(1)
    except TimeoutError:
        click.echo(
            f"Error: Timed out waiting for instance '{instance_id}' to be ready.",
            err=True,
        )
        sys.exit(1)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("computer-mcp")
@click.argument("instance_id")
def computer(instance_id):
    """Start an interactive MCP computer session with an instance."""
    client = get_client()
    try:
        from morphcloud.computer import Computer

        instance = client.instances.get(instance_id)

        computer = Computer(instance)

        computer.mcp().run()
    except ImportError as e:
        click.echo(
            f"Error: Computer requires additional dependencies (e.g., 'mcp'). {e}",
            err=True,
        )
        sys.exit(1)
    except TimeoutError:
        click.echo(
            f"Error: Timed out waiting for instance '{instance_id}' to be ready.",
            err=True,
        )
        sys.exit(1)
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("boot")
@click.argument("snapshot_id")
@click.option("--vcpus", type=int, required=False)
@click.option("--memory", type=int, required=False)
@click.option("--disk-size", type=int, required=False)
@click.option("--metadata", "-m", "metadata_options", multiple=True)
def boot_instance(snapshot_id, vcpus, memory, disk_size, metadata_options):
    """Boot a new instance from a snapshot."""
    client = get_client()
    try:
        metadata_dict = {}
        for meta in metadata_options:
            if "=" not in meta:
                raise click.UsageError("Metadata must be key=value.")
            k, v = meta.split("=", 1)
            metadata_dict[k] = v

        with Spinner(
            text=f"Booting instance from snapshot {snapshot_id}...",
            success_text="Instance boot complete!",
            success_emoji="🚀",
        ):
            new_instance = client.instances.boot(
                snapshot_id=snapshot_id,
                vcpus=vcpus,
                memory=memory,
                disk_size=disk_size,
                metadata=metadata_dict if metadata_dict else None,
            )

        click.secho(f"Instance booted: {new_instance.id}", fg="green")
    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Snapshot '{snapshot_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("ssh-key")
@click.argument("instance_id")
@click.option(
    "--password",
    "show_password_only",
    is_flag=True,
    help="Output only the value of the password field.",
)
def ssh_key(instance_id, show_password_only):
    """
    Retrieve the SSH key details for an instance.

    This key is ephemeral and is used for establishing the SSH connection.
    """
    client = get_client()
    try:
        # A spinner provides better UX for network requests.
        with Spinner(
            text=f"Retrieving SSH key for instance {instance_id}...",
            success_text="SSH key retrieved!",
            success_emoji="🔑",
        ):
            # Per the request, this command calls the endpoint directly.
            # It accesses the internal http_client from the main client object.
            response = client._http_client.get(f"/instance/{instance_id}/ssh/key")
            key_data = response.json()

        if show_password_only:
            # If the --password flag is used, print only that value.
            password = key_data.get("password")
            if password is not None:
                click.echo(password)
            else:
                # Handle cases where the key might be missing from the response.
                click.echo(
                    "Error: 'password' field not found in the API response.", err=True
                )
                sys.exit(1)
        else:
            # Print the full key details in a formatted JSON output.
            click.echo(format_json(key_data))

    except api.ApiError as e:
        if e.status_code == 404:
            click.echo(f"Error: Instance '{instance_id}' not found.", err=True)
            sys.exit(1)
        else:
            handle_api_error(e)
    except Exception as e:
        handle_api_error(e)


@instance.command("cleanup")
@click.option(
    "--snapshot-pattern",
    help="Comma-separated glob patterns to match snapshot IDs (e.g., 'snapshot_dev_*,snapshot_test_*')",
)
@click.option(
    "--snapshot-exclude-pattern",
    help="Comma-separated glob patterns to exclude snapshot IDs",
)
@click.option(
    "--service-pattern",
    help="Comma-separated glob patterns to match exposed service names (instances with matching services are kept alive)",
)
@click.option(
    "--service-exclude-pattern",
    help="Comma-separated glob patterns to exclude service names (instances with matching services are processed)",
)
@click.option(
    "--exclude-paused/--include-paused",
    default=True,
    help="Whether to exclude paused instances from cleanup (default: exclude)",
)
@click.option(
    "--action",
    type=click.Choice(["stop", "pause"]),
    default="stop",
    help="Action to perform on filtered instances",
)
@click.option(
    "--max-workers",
    type=int,
    default=10,
    help="Maximum number of concurrent operations",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip confirmation prompt and proceed immediately",
)
@click.option(
    "--json",
    "json_mode",
    is_flag=True,
    default=False,
    help="Output results in JSON format",
)
def cleanup_instances(
    snapshot_pattern,
    snapshot_exclude_pattern,
    service_pattern,
    service_exclude_pattern,
    exclude_paused,
    action,
    max_workers,
    yes,
    json_mode,
):
    """
    Clean up instances based on various filtering criteria.

    All pattern options support comma-separated lists of glob patterns.

    Examples:

      # Stop all instances from dev snapshots
      morph instance cleanup --snapshot-pattern "snapshot_dev_*"

      # Stop instances from multiple snapshot patterns
      morph instance cleanup --snapshot-pattern "snapshot_dev_*,snapshot_test_*,snapshot_tmp_*"

      # Keep instances exposing webhook or monitoring services, stop everything else
      morph instance cleanup --service-pattern "*webhook*,*monitor*"

      # Clean up test instances but exclude production snapshots
      morph instance cleanup --snapshot-pattern "snapshot_test_*" --snapshot-exclude-pattern "snapshot_prod_*,snapshot_staging_*"

      # Pause instances that don't have monitoring or logging services
      morph instance cleanup --service-exclude-pattern "*monitor*,*log*" --action pause

      # Skip confirmation for automated scripts
      morph instance cleanup --snapshot-pattern "snapshot_temp_*" --yes
    """
    client = get_client()

    try:
        # Use confirmation unless --yes flag is provided
        confirm = not yes

        result = client.instances.cleanup(
            snapshot_pattern=snapshot_pattern,
            snapshot_exclude_pattern=snapshot_exclude_pattern,
            service_pattern=service_pattern,
            service_exclude_pattern=service_exclude_pattern,
            exclude_paused=exclude_paused,
            action=action,
            max_workers=max_workers,
            confirm=confirm,
        )

        if json_mode:
            click.echo(json.dumps(result, indent=2))
        else:
            # Rich output is already handled by the cleanup method itself
            # Just show a final summary
            if result.get("success"):
                if result.get("cancelled"):
                    click.secho("Operation cancelled by user.", fg="cyan")
                elif result["processed"] > 0:
                    click.secho(
                        f"✅ Successfully {action}{'ped' if action == 'stop' else 'd'} {result['processed']} instances.",
                        fg="green",
                    )
                else:
                    click.secho("No instances needed cleanup.", fg="green")
            else:
                if "error" in result:
                    click.secho(f"❌ Error: {result['error']}", fg="red", err=True)
                else:
                    click.secho(
                        f"❌ {result['failed']} instances failed to {action}.",
                        fg="red",
                        err=True,
                    )
                    sys.exit(1)

    except api.ApiError as e:
        click.echo(f"API Error (Status Code: {e.status_code})", err=True)
        click.echo(f"Response Body: {e.response_body}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"An unexpected error occurred: {e}", err=True)
        sys.exit(1)


# Load CLI plugins
load_cli_plugins(cli)


if __name__ == "__main__":
    cli()
