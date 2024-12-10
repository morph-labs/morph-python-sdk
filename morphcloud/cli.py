import os
import sys
import json
import hashlib

import click

from . import api


def format_json(obj):
    """Helper to pretty print objects"""
    if hasattr(obj, "dict"):
        return json.dumps(obj.dict(), indent=2)
    return json.dumps(obj, indent=2)


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
    import datetime

    return datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


# Create a global client instance
client = api.MorphCloudClient()


@click.group()
def cli():
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
    images = client.images.list()
    if json_mode:
        for image in images:
            click.echo(format_json(image))
    else:
        headers = ["ID", "Name", "Description", "Disk Size (MB)", "Created At"]
        rows = []
        for image in images:
            rows.append(
                [
                    image.id,
                    image.name,
                    image.description,
                    image.disk_size,
                    unix_timestamp_to_datetime(image.created),
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
    snapshots = client.snapshots.list()
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
                    snapshot.spec.vcpus,
                    snapshot.spec.memory,
                    snapshot.spec.disk_size,
                    snapshot.refs.image_id,
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
    snapshot = client.snapshots.create(
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
    snapshot = client.snapshots.get(snapshot_id)
    snapshot.delete()
    click.echo(f"Deleted snapshot {snapshot_id}")


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
    instances = client.instances.list()
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
            "Http Services",
        ]
        rows = []
        for instance in instances:
            rows.append(
                [
                    instance.id,
                    instance.refs.snapshot_id,
                    unix_timestamp_to_datetime(instance.created),
                    instance.status,
                    instance.spec.vcpus,
                    instance.spec.memory,
                    instance.spec.disk_size,
                    ", ".join(
                        f"{svc.name}:{svc.port}"
                        for svc in instance.networking.http_services
                    ),
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
    instance = client.instances.start(snapshot_id=snapshot_id)
    if json_mode:
        click.echo(format_json(instance))
    else:
        click.echo(f"{instance.id}")


@instance.command("stop")
@click.argument("instance_id")
def stop_instance(instance_id):
    """Stop an instance"""
    client.instances.stop(instance_id)
    click.echo(f"{instance_id}")


@instance.command("get")
@click.argument("instance_id")
def get_instance(instance_id):
    """Get instance details"""
    instance = client.instances.get(instance_id)
    click.echo(format_json(instance))


@instance.command("snapshot")
@click.argument("instance_id")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def snapshot_instance(instance_id, json_mode):
    """Create a snapshot from an instance"""
    instance = client.instances.get(instance_id)
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
    instance = client.instances.get(instance_id)
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
    instance = client.instances.get(instance_id)
    instance.expose_http_service(name, port)
    click.echo(f"Exposed HTTP service {name} on port {port}")


@instance.command("hide-http")
@click.argument("instance_id")
@click.argument("name")
def hide_http_service(instance_id, name):
    """Hide an exposed HTTP service"""
    instance = client.instances.get(instance_id)
    instance.hide_http_service(name)
    click.echo(f"Delete HTTP service {name}")


@instance.command("exec")
@click.argument("instance_id")
@click.argument("command", nargs=-1)
def exec_command(instance_id, command):
    """Execute a command on an instance"""
    instance = client.instances.get(instance_id)
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
    """Start an SSH session to an instance"""
    from morphcloud._ssh import ssh_connect

    instance = client.instances.get(instance_id)
    ssh_client = instance.ssh_connect()

    cmd_str = " ".join(command) if command else None
    ssh_connect(ssh_client, command=cmd_str)


@instance.command("port-forward")
@click.argument("instance_id")
@click.argument("remote_port", type=int)
@click.argument("local_port", type=int, required=False)
def port_forward(instance_id, remote_port, local_port):
    """Forward a port from an instance to your local machine"""
    from morphcloud._ssh import forward_tunnel

    if not local_port:
        local_port = remote_port

    instance = client.instances.get(instance_id)

    ssh_client = instance.ssh_connect()

    forward_tunnel(
        ssh_client,
        local_port=local_port,
        remote_port=remote_port,
    )


@instance.command("crun")
@click.option("--image", help="Container image to deploy", default="python:3.11-slim")
@click.option(
    "--expose-http", "expose_http", multiple=True, help="HTTP service to expose"
)
@click.option("--vcpus", type=int, help="Number of VCPUs", default=1)
@click.option("--memory", type=int, help="Memory in MB", default=128)
@click.option("--disk-size", type=int, help="Disk size in MB", default=700)
@click.option("--force-rebuild", is_flag=True, help="Force rebuild the container")
@click.option("--instance-id", default=None, help="Instance ID to deploy the container. If set will use the existing instance")
@click.option("--verbose/--no-verbose", default=True, help="Enable verbose logging")
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
@click.argument("command", nargs=-1, required=False, type=click.UNPROCESSED)
def run_oci_container(
    image,
    expose_http,
    vcpus,
    memory,
    disk_size,
    force_rebuild,
    instance_id,
    verbose,
    json_mode,
    command,
):
    """Run an OCI container on a Morph instance. If instance_id is not provided, a new instance will be created."""
    from morphcloud._oci import deploy_container_to_instance

    if verbose:
        click.echo("Starting deployment process...")
        click.echo("Checking snapshots for minimal image")

    if not instance_id:
        digest = hashlib.sha256(
            f"{image}{vcpus}{memory}{disk_size}".encode("utf-8")
        ).hexdigest()

        snapshots = client.snapshots.list(digest=digest)

        if force_rebuild:
            for snapshot in snapshots:
                snapshot.delete()
            snapshots = []

        if len(snapshots) == 0:
            if verbose:
                click.echo("No matching snapshot found, creating a new one")
            snapshot = client.snapshots.create(
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

        instance = client.instances.start(snapshot_id=snapshot.id)

        instance.wait_until_ready()

        for service in expose_http:
            name, port = service.split(":")
            click.echo(f"Exposing port {port} as {name}")
            instance.expose_http_service(name, int(port))
    else:
        instance = client.instances.get(instance_id)

        # Check if the instance is running
        instance.wait_until_ready()

        # Add the HTTP services if provided and not already exposed
        for service in expose_http:
            name, port = service.split(":")
            if not any(
                svc.name == name and svc.port == int(port)
                for svc in instance.networking.http_services
            ):
                click.echo(f"Exposing port {port} as {name}")
                instance.expose_http_service(name, int(port))

    if json_mode:
        click.echo(format_json(instance))
    elif verbose:
        click.echo(f"Instance {instance.id} created successfully")

    if verbose:
        click.echo("Deploying container")

    if not command:
        command = ["sleep", "infinity"]

    deploy_container_to_instance(instance, image, command=command)
    click.echo(instance.id)


@instance.command("chat")
@click.argument("instance_id")
@click.argument("instructions", nargs=-1, required=False, type=click.UNPROCESSED)
def chat(instance_id, instructions):
    """Start an interactive chat session with an instance"""
    if instructions:
        print("Instructions:", instructions)
    from morphcloud._llm import agent_loop


    instance = client.instances.get(instance_id)

    agent_loop(instance)


if __name__ == "__main__":
    cli()
