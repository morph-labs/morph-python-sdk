import os
import sys
import json
import hashlib

import click
from . import api

from contextlib import ExitStack

from morphcloud._ssh import ssh_connect, forward_tunnel
from morphcloud._oci import deploy_container_to_instance


def format_json(obj):
    """Helper to pretty print objects"""
    if hasattr(obj, "dict"):
        return json.dumps(obj.dict(), indent=2)
    return json.dumps(obj, indent=2)


def print_docker_style_table(headers, rows):
    """
    Print a table in Docker ps style with dynamic column widths using Click's echo.
    Args:
        headers (list): List of column headers
        rows (list): List of rows, where each row is a list of values
    """
    # Handle empty input cases
    if not headers:
        return
    
    # Calculate column widths based on content
    widths = []
    for i in range(len(headers)):
        # Initialize with header length
        width = len(str(headers[i]))
        
        # Only check row values if rows exist
        if rows:
            column_values = [str(row[i]) if i < len(row) else '' for row in rows]
            width = max(width, max(len(val) for val in column_values))
        
        widths.append(width)
    
    # Print headers
    header_line = ""
    separator_line = ""
    for i, header in enumerate(headers):
        header_line += f"{str(header):<{widths[i]}}  "
        separator_line += "-" * widths[i] + "  "
    
    click.echo(header_line.rstrip())
    click.echo(separator_line.rstrip())
    
    # Print rows only if they exist
    if rows:
        for row in rows:
            line = ""
            for i in range(len(headers)):
                # Handle case where row might have fewer columns than headers
                value = str(row[i]) if i < len(row) else ''
                line += f"{value:<{widths[i]}}  "
            click.echo(line.rstrip())


def unix_timestamp_to_datetime(timestamp):
    import datetime
    return datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


@click.group()
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
def cli(debug):
    """Morph Cloud CLI"""
    pass


# Images
@cli.group()
def image():
    """Manage Morph images"""
    pass


@image.command("list")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
def list_image(json_mode):
    """List all available images"""
    images = api.Image.list()
    if json_mode:
        for image in images:
            click.echo(format_json(image))
    else:
        headers = ["ID", "Name", "Description", "Disk Size (MB)", "Created At"]
        rows = []
        for image in images:
            rows.append([
                image.id,
                image.name,
                image.description,
                image.disk_size,
                unix_timestamp_to_datetime(image.created),
            ])
        print_docker_style_table(headers, rows)


# Snapshots
@cli.group()
def snapshot():
    """Manage Morph snapshots"""
    pass


@snapshot.command("list")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
def list_snapshots(json_mode):
    """List all snapshots"""
    snapshots = api.Snapshot.list()
    if json_mode:
        for snapshot in snapshots:
            click.echo(format_json(snapshot))
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
        for snapshot in snapshots:
            rows.append([
                snapshot.id,
                unix_timestamp_to_datetime(snapshot.created),
                snapshot.status,
                snapshot.spec.vcpus,
                snapshot.spec.memory,
                snapshot.spec.disk_size,
                snapshot.refs.image_id,
            ])
        print_docker_style_table(headers, rows)


@snapshot.command("create")
@click.option("--image-id", help="ID of the base image")
@click.option("--vcpus", type=int, help="Number of VCPUs")
@click.option("--memory", type=int, help="Memory in MB")
@click.option("--disk-size", type=int, help="Disk size in MB")
@click.option("--digest", help="User provided digest")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
def create_snapshot(image_id, vcpus, memory, disk_size, digest, json_mode):
    """Create a new snapshot"""
    snapshot = api.Snapshot.create(
        image_id=image_id,
        vcpus=vcpus,
        memory=memory,
        disk_size=disk_size,
        digest=digest,
    )
    if json_mode:
        click.echo(format_json(snapshot))
    else:
        click.echo(f"{snapshot.id}")


@snapshot.command("delete")
@click.argument("snapshot_id")
def delete_snapshot(snapshot_id):
    """Delete a snapshot"""
    snapshot = api.Snapshot(
        id=snapshot_id,
        object="snapshot",
        created=0,
        status=api.SnapshotStatus.READY,
        spec=api.ResourceSpec(vcpus=0, memory=0, disk_size=0),
        refs=api.SnapshotRefs(image_id="")
    )
    snapshot.delete()
    click.echo(f"Deleted snapshot {snapshot_id}")


# Instances
@cli.group()
def instance():
    """Manage Morph instances"""
    pass


@instance.command("list")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
def list_instances(json_mode):
    """List all instances"""
    instances = api.Instance.list()
    if json_mode:
        for instance in instances:
            click.echo(format_json(instance))
    else:
        headers = [
            "ID",
            "Snapshot ID",
            "Created At",
            "Status",
            "VCPUs",
            "Memory (MB)",
            "Disk Size (MB)",
            "IP Address",
        ]
        rows = []
        for instance in instances:
            rows.append([
                instance.id,
                instance.refs.snapshot_id,
                unix_timestamp_to_datetime(instance.created),
                instance.status,
                instance.spec.vcpus,
                instance.spec.memory,
                instance.spec.disk_size,
                instance.networking.internal_ip or "pending",
            ])
        print_docker_style_table(headers, rows)


@instance.command("start")
@click.argument("snapshot_id")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
def start_instance(snapshot_id, json_mode):
    """Start a new instance from a snapshot"""
    instance = api.Instance.start(snapshot_id=snapshot_id)
    if json_mode:
        click.echo(format_json(instance))
    else:
        click.echo(f"{instance.id}")


@instance.command("stop")
@click.argument("instance_id")
def stop_instance(instance_id):
    """Stop an instance"""
    api.Instance.stop_by_id(instance_id)
    click.echo(f"{instance_id}")


@instance.command("get")
@click.argument("instance_id")
def get_instance(instance_id):
    """Get instance details"""
    instance = api.Instance.get(instance_id)
    click.echo(format_json(instance))


@instance.command("snapshot")
@click.argument("instance_id")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
def snapshot_instance(instance_id, json_mode):
    """Create a snapshot from an instance"""
    instance = api.Instance.get(instance_id)
    snapshot = instance.snapshot()
    if json_mode:
        click.echo(format_json(snapshot))
    else:
        click.echo(f"{snapshot.id}")


@instance.command("branch")
@click.argument("instance_id")
@click.option("--count", type=int, default=1, help="Number of clones to create")
def branch_instance(instance_id, count):
    """Clone an instance"""
    instance = api.Instance.get(instance_id)
    snapshot, clones = instance.branch(count)
    click.echo(format_json(snapshot))
    for clone in clones:
        click.echo(format_json(clone))


@instance.command("expose-http")
@click.argument("instance_id")
@click.argument("name")
@click.argument("port", type=int)
def expose_http_service(instance_id, name, port):
    """Expose an HTTP service"""
    instance = api.Instance.get(instance_id)
    instance.expose_http_service(name, port)
    click.echo(f"Exposed HTTP service {name} on port {port}")


@instance.command("hide-http")
@click.argument("instance_id")
@click.argument("name")
def hide_http_service(instance_id, name):
    """Hide an exposed HTTP service"""
    instance = api.Instance.get(instance_id)
    instance.hide_http_service(name)
    click.echo(f"Delete HTTP service {name}")


@instance.command("exec")
@click.argument("instance_id")
@click.argument("command", nargs=-1)
def exec_command(instance_id, command):
    """Execute a command on an instance"""
    instance = api.Instance.get(instance_id)
    result = instance.exec(list(command))
    click.echo(f"Exit code: {result.exit_code}")
    if result.stdout:
        click.echo(f"Stdout:\n{result.stdout}")
    if result.stderr:
        click.echo(f"Stderr:\n{result.stderr}", err=True)
    sys.exit(result.exit_code)


@instance.command("ssh")
@click.argument("instance_id")
@click.argument("command", nargs=-1, required=False, type=click.UNPROCESSED)
def ssh_portal(instance_id, command):
    """Start an SSH session to an instance

    Pass commands after -- to include flags and options.
    Example: morphcloud instance ssh morphvm_12345 -- python3"""
    MORPH_API_KEY = os.getenv("MORPH_API_KEY", "")
    hostname = "localhost"
    port = 2222
    username = instance_id + ":" + MORPH_API_KEY
    cmd_str = " ".join(command) if command else None
    ssh_connect(hostname, username, port=port, command=cmd_str)


@instance.command("port-forward")
@click.argument("instance_id")
@click.argument("remote_port", type=int)
@click.argument("local_port", type=int, required=False)
def port_forward(instance_id, remote_port, local_port):
    """Forward a port from an instance to your local machine"""
    if not local_port:
        local_port = remote_port

    forward_tunnel(
        local_port=local_port,
        remote_port=remote_port,
        ssh_host="localhost",
        ssh_username=instance_id + ":" + os.getenv("MORPH_API_KEY", ""),
        ssh_port=2222,
    )


@instance.command("crun")
@click.option("--image", help="Container image to deploy", default="python:3.11-slim")
@click.option("--expose-http", "expose_http", multiple=True, help="HTTP service to expose")
@click.option("--vcpus", type=int, help="Number of VCPUs", default=1)
@click.option("--memory", type=int, help="Memory in MB", default=128)
@click.option("--disk-size", type=int, help="Disk size in MB", default=700)
@click.option("--force-rebuild", is_flag=True, help="Force rebuild the container")
@click.option("--verbose/--no-verbose", default=True, help="Enable verbose logging")
@click.option("--json/--no-json", "json_mode", default=False, help="Output in JSON format")
@click.argument("command", nargs=-1, required=False, type=click.UNPROCESSED)
def run_oci_container(image, expose_http, vcpus, memory, disk_size, force_rebuild, verbose, json_mode, command):
    """Run a new instance with a local container

    This command will use your local Docker daemon to build and run a container on a Morph instance.

    The container will be built using the Docker daemon running on your local machine. The container will be
    copied to the Morph instance and run using a minimal OCI runtime (crun)."""

    if verbose:
        click.echo("Starting deployment process...")
        click.echo("Checking snapshots for minimal image")

    # hash the image, vcpus, memory, and disk size to create a unique digest
    digest = hashlib.sha256(
        f"{image}{vcpus}{memory}{disk_size}".encode("utf-8")
    ).hexdigest()

    snapshots = api.Snapshot.list(digest=digest)

    if force_rebuild:
        for snapshot in snapshots:
            snapshot.delete()
        snapshots = []

    if len(snapshots) == 0:
        if verbose:
            click.echo("No matching snapshot found, creating a new one")
        snapshot = api.Snapshot.create(
            image_id="morphvm-minimal",
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            digest=digest,
        )
    else:
        snapshot = snapshots[0]

    if verbose:
        click.echo("Starting a new instance")

    instance = api.Instance.start(snapshot_id=snapshot.id)

    if json_mode:
        click.echo(format_json(instance))
    elif verbose:
        click.echo(f"Instance {instance.id} created successfully")

    if verbose:
        click.echo("Deploying container")

    instance.wait_until_ready()

    if not command:
        command = ["sleep", "infinity"]

    for service in expose_http:
        name, port = service.split(":")
        click.echo(f"Exposing port {port} as {name}")
        instance.expose_http_service(name, int(port))

    deploy_container_to_instance(
        instance,
        image,
        command=command,
    )

    click.echo(instance.id)


@instance.command("chat")
@click.argument("instance_id")
@click.argument("instructions", nargs=-1, required=False, type=click.UNPROCESSED)
def chat(instance_id, instructions):
    """Start an interactive chat session with an instance"""
    if instructions:
        print("Instructions:", instructions)
    from morphcloud._llm import agent_loop
    agent_loop(instance_id, os.getenv("MORPH_API_KEY", ""))


if __name__ == "__main__":
    cli()
