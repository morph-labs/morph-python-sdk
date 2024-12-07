import os
import sys
import json

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
    # Calculate column widths based on content
    widths = []
    for i in range(len(headers)):
        column_values = [str(row[i]) for row in rows]
        widths.append(max(len(str(headers[i])), max(len(val) for val in column_values)))

    # Print headers
    header_line = ""
    separator_line = ""
    for i, header in enumerate(headers):
        header_line += f"{str(header):<{widths[i]}}  "
        separator_line += "-" * widths[i] + "  "

    click.echo(header_line.rstrip())
    click.echo(separator_line.rstrip())

    # Print rows
    for row in rows:
        line = ""
        for i, value in enumerate(row):
            line += f"{str(value):<{widths[i]}}  "
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
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def list_image(json_mode):
    """List all available images"""
    images = api.Image.list()
    if json_mode:
        for image in images:
            click.echo(format_json(image))
    else:
        headers = [
            "ID",
            "Name",
            "Description",
            "Disk Size (MB)",
            "Created At",
            "User ID",
            "Is Preset",
        ]
        rows = []
        for image in images:
            rows.append(
                [
                    image.id,
                    image.name,
                    image.description,
                    image.disk_size,
                    unix_timestamp_to_datetime(image.created),
                    image.user_id,
                    image.is_preset,
                ]
            )
        print_docker_style_table(headers, rows)


# Snapshots
@cli.group()
def snapshot():
    """Manage Morph snapshots"""
    pass


@snapshot.command("list")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
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
            rows.append(
                [
                    snapshot.id,
                    unix_timestamp_to_datetime(snapshot.created),
                    snapshot.status,
                    snapshot.vcpus,
                    snapshot.memory,
                    snapshot.disk_size,
                    snapshot.image_id,
                ]
            )
        print_docker_style_table(headers, rows)


@snapshot.command("create")
@click.option("--image-id", help="ID of the base image")
@click.option("--vcpus", type=int, help="Number of VCPUs")
@click.option("--memory", type=int, help="Memory in MB")
@click.option("--disk-size", type=int, help="Disk size in MB")
@click.option("--digest", help="User provided digest")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
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
    # snapshot = api.Snapshot(
    #     id=snapshot_id,
    #     object="snapshot",
    #     created=0,
    #     status=api.SnapshotStatus.READY,
    #     vcpus=0, memory=0, disk_size=0, image_id=None)
    # snapshot.delete()
    # click.echo(f"Deleted snapshot {snapshot_id}")


# Instances
@cli.group()
def instance():
    """Manage Morph instances"""
    pass


@instance.command("list")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
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
        ]
        rows = []
        for instance in instances:
            rows.append(
                [
                    instance.id,
                    instance.snapshot_id,
                    unix_timestamp_to_datetime(instance.created),
                    instance.status,
                    instance.vcpus,
                    instance.memory,
                    instance.disk_size,
                ]
            )
        print_docker_style_table(headers, rows)


@instance.command("start")
@click.argument("snapshot_id")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
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
    instance = api.Instance.get(instance_id)
    instance.stop()
    click.echo(f"{instance_id}")


@instance.command("get")
@click.argument("instance_id")
def get_instance(instance_id):
    """Get instance details"""
    instance = api.Instance.get(instance_id)
    click.echo(format_json(instance))


@instance.command("snapshot")
@click.argument("instance_id")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def snapshot_instance(instance_id, json_mode):
    """Create a snapshot from an instance"""
    instance = api.Instance.get(instance_id)
    snapshot = instance.snapshot()
    if json_mode:
        click.echo(format_json(snapshot))
    else:
        click.echo(f"{snapshot.id}")


@instance.command("clone")
@click.argument("instance_id")
@click.option("--count", type=int, default=1, help="Number of clones to create")
def clone_instance(instance_id, count):
    """Clone an instance"""
    instance = api.Instance.get(instance_id)
    clones = instance.clone(count)
    for clone in clones:
        click.echo(format_json(clone))


@instance.command("ssh-keys")
@click.argument("instance_id")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def get_ssh_keys(instance_id, json_mode):
    """Get SSH keys for an instance"""
    instance = api.Instance.get(instance_id)
    public_key, private_key = instance.get_ssh_keys()
    if json_mode:
        click.echo(
            json.dumps({"public_key": public_key, "private_key": private_key}, indent=2)
        )
    else:
        click.echo(f"Public key:\n{public_key}\n\nPrivate key:\n{private_key}")


@instance.command("rotate-ssh-keys")
@click.argument("instance_id")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def rotate_ssh_keys(instance_id, json_mode):
    """Rotate SSH keys for an instance"""
    instance = api.Instance.get(instance_id)
    public_key, private_key = instance.rotate_ssh_keys()
    if json_mode:
        click.echo(
            json.dumps({"public_key": public_key, "private_key": private_key}, indent=2)
        )
    else:
        click.echo(f"New public key:\n{public_key}\n\nNew private key:\n{private_key}")


@instance.command("expose-http")
@click.argument("instance_id")
@click.argument("name")
@click.argument("port", type=int)
def expose_http_service(instance_id, name, port):
    """Expose an HTTP service"""
    instance = api.Instance.get(instance_id)
    instance.expose_http_service(name, port)
    click.echo(f"Exposed HTTP service {name} on port {port}")


@instance.command("unexpose-http")
@click.argument("instance_id")
@click.argument("name")
def unexpose_http_service(instance_id, name):
    """Unexpose an HTTP service"""
    instance = api.Instance.get(instance_id)
    instance.unexpose_http_service(name)
    click.echo(f"Unexposed HTTP service {name}")


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

    # Join the command parts if present
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


@instance.command("run")
@click.option("--name", help="Name of the container", default="python:3.11-slim")
@click.option("--verbose/--no-verbose", default=True, help="Enable verbose logging")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
@click.argument("command", nargs=-1, required=False, type=click.UNPROCESSED)
def run_oci_container(name, verbose, json_mode, command):
    """Run a new instance with a local container

    This command will use your local Docker daemon to build and run a container on a Morph instance.

    The container will be built using the Docker daemon running on your local machine. The container will be
    copied to the Morph instance and run using a minimal OCI runtime (crun)."""

    if verbose:
        click.echo("Starting deployment process...")
        click.echo("Checking snapshots for minimal image")

    exit_stack = ExitStack()
    digest = "sha256:1c7b3"
    snapshots = api.Snapshot.list(digest=digest)

    if len(snapshots) == 0:
        if verbose:
            click.echo("No matching snapshot found, creating a new one")
        snapshot = api.Snapshot.create(
            image_id="morphvm-minimal",
            vcpus=1,
            memory=128,
            disk_size=700,
            digest=digest,
        )
    else:
        snapshot = snapshots[0]

    if verbose:
        click.echo("Starting a new instance")
    instance = api.Instance.start(snapshot_id=snapshot.id)
    exit_stack.callback(instance.stop)

    if json_mode:
        click.echo(format_json(instance))
    elif verbose:
        click.echo(f"Instance {instance.id} created successfully")

    if verbose:
        click.echo("Exposing port 8000")
    instance.expose_http_service(name="web", port=8000)
    instance._refresh()

    if json_mode:
        click.echo(format_json(instance))
    elif verbose:
        click.echo("Port 8000 exposed successfully")

    if verbose:
        click.echo("Deploying container")
    instance.wait_until_ready()

    if not command:
        command = ["python3.11", "-m", "http.server", "--bind", "0.0.0.0", "8000"]

    deploy_container_to_instance(
        instance,
        name,
        ports={8000: 8000},
        command=command,
    )

    if verbose:
        click.echo("Container deployed successfully")

    instance._refresh()
    if json_mode:
        click.echo(format_json(instance))

    MORPH_BASE_URL = os.getenv("MORPH_BASE_URL", "http://localhost:9000")

    web_url = f"{MORPH_BASE_URL}/api/instance/{instance.id}/http-service/web/"

    click.echo(web_url)

@instance.command("chat")
@click.argument("instance_id")
def chat(instance_id):
    """Start an interactive chat session with an instance"""
    from morphcloud._llm import agent_loop

    agent_loop(instance_id, os.getenv("MORPH_API_KEY", ""))

if __name__ == "__main__":
    cli()
