import sys
import json

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
    "--metadata",
    "-m",
    help="Filter snapshots by metadata (format: key=value)",
    multiple=True,
)
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def list_snapshots(metadata, json_mode):
    """List all snapshots"""
    metadata_dict = {}
    for meta in metadata:
        key, value = meta.split("=", 1)
        metadata_dict[key] = value
    snapshots = client.snapshots.list(metadata=metadata_dict)
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


@snapshot.command("get")
@click.argument("snapshot_id")
def get_snapshot(snapshot_id):
    """Get snapshot details"""
    snapshot = client.snapshots.get(snapshot_id)
    click.echo(format_json(snapshot))


@snapshot.command("set-metadata")
@click.argument("snapshot_id")
@click.argument("metadata", nargs=-1)
def set_snapshot_metadata(snapshot_id, metadata):
    """Set metadata on a snapshot

    Example:

        morph snapshot set-metadata <id> key1=value "key2=with spaces"
    """
    snapshot = client.snapshots.get(snapshot_id)
    metadata_dict = {}
    for meta in metadata:
        key, value = meta.split("=", 1)
        metadata_dict[key] = value
    snapshot.set_metadata(metadata_dict)
    snapshot._refresh()
    click.echo(format_json(snapshot))


# Instances
@cli.group()
def instance():
    """Manage Morph instances"""
    pass


@instance.command("sync")
@click.argument("source")
@click.argument("destination")
@click.option(
    "--delete", "-d", is_flag=True, help="Delete extraneous files from destination"
)
@click.option(
    "--dry-run",
    "-n",
    is_flag=True,
    help="Show what would be done without making changes",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity (can be used multiple times)",
)
def sync_files(source, destination, delete, dry_run, verbose):
    """Synchronize files to or from a Morph instance.

    Similar to rsync, this command synchronizes files between local and remote directories.
    Only changed files are transferred. Supports both directions:

    - From local to instance: morph instance sync ./local/dir instance_id:/remote/dir
    - From instance to local: morph instance sync instance_id:/remote/dir ./local/dir

    Verbosity levels:
        -v: Show INFO messages (basic progress)
        -vv: Show DEBUG messages (detailed file operations)
        -vvv: Show all debug information including SFTP operations

    Examples:
        morph instance sync ./local/dir morphvm_1234:/remote/dir
        morph instance sync morphvm_1234:/remote/dir ./local/dir
        morph instance sync --delete ./local/dir morphvm_1234:/remote/dir
        morph instance sync --dry-run ./local/dir morphvm_1234:/remote/dir
        morph instance sync -vv ./local/dir morphvm_1234:/remote/dir
    """
    import logging

    # Set up logging based on verbosity
    logger = logging.getLogger("morph.sync")
    if verbose == 0:
        logger.setLevel(logging.WARNING)
    elif verbose == 1:
        logger.setLevel(logging.INFO)
    elif verbose >= 2:
        logger.setLevel(logging.DEBUG)
        if verbose >= 3:
            logging.getLogger("paramiko").setLevel(logging.DEBUG)

    def parse_instance_path(path):
        if ":" not in path:
            return None, path
        instance_id, remote_path = path.split(":", 1)
        return instance_id, remote_path

    source_instance, source_path = parse_instance_path(source)
    dest_instance, dest_path = parse_instance_path(destination)

    # Validate that exactly one side is a remote path
    if (source_instance and dest_instance) or (
        not source_instance and not dest_instance
    ):
        raise click.UsageError(
            "One (and only one) path must be a remote path in the format instance_id:/path"
        )

    # Get the instance
    instance_id = source_instance or dest_instance
    assert instance_id is not None
    instance = client.instances.get(instance_id)

    try:
        instance.sync(source, destination, delete=delete, dry_run=dry_run)
    except Exception as e:
        raise click.ClickException(str(e))


@instance.command("list")
@click.option(
    "--metadata",
    "-m",
    help="Filter instances by metadata (format: key=value)",
    multiple=True,
)
@click.option(
    "--json/--no-json", "json_mode", default=False, help="Output in JSON format"
)
def list_instances(metadata, json_mode):
    """List all instances"""
    metadata_dict = {}
    for meta in metadata:
        key, value = meta.split("=", 1)
        metadata_dict[key] = value
    instances = client.instances.list(metadata=metadata_dict)
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


@instance.command("pause")
@click.argument("instance_id")
def pause_instance(instance_id):
    """Pause an instance"""
    instance = client.instances.get(instance_id)
    instance.pause()
    click.echo(f"{instance_id}")


@instance.command("resume")
@click.argument("instance_id")
def resume_instance(instance_id):
    """Resume a paused instance"""
    instance = client.instances.get(instance_id)
    instance.resume()
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
@click.option(
    "--auth-mode", 
    help="Authentication mode (use 'api_key' to require API key authentication)"
)
def expose_http_service(instance_id, name, port, auth_mode):
    """Expose an HTTP service
    
    When using --auth-mode=api_key, the service will require API key authentication
    via Authorization: Bearer MORPH_API_KEY in HTTP headers.
    """
    instance = client.instances.get(instance_id)
    instance.expose_http_service(name, port, auth_mode)
    url = f"https://{name}-{instance_id.replace('_', '-')}.http.cloud.morph.so"
    click.echo(url)
    if auth_mode == "api_key":
        click.echo("API key authentication required for this service")



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


@instance.command("set-metadata")
@click.argument("instance_id")
@click.argument("metadata", nargs=-1)
def set_instance_metadata(instance_id, metadata):
    """Set metadata on an instance

    Example:

        morph instance set-metadata <id> key1=value "key2=with spaces"
    """
    instance = client.instances.get(instance_id)
    metadata_dict = {}
    for meta in metadata:
        key, value = meta.split("=", 1)
        metadata_dict[key] = value
    instance.set_metadata(metadata_dict)
    instance._refresh()
    click.echo(format_json(instance))


@instance.command("ssh")
@click.argument("instance_id")
@click.option("--rm", is_flag=True, help="Remove the instance after exiting")
@click.option("--snapshot", is_flag=True, help="Create a snapshot before exiting")
@click.argument("command", nargs=-1, required=False, type=click.UNPROCESSED)
def ssh_portal(instance_id, rm, snapshot, command):
    """Start an SSH session to an instance"""
    instance = client.instances.get(instance_id)
    import sys

    non_interactive = not sys.stdin.isatty()

    instance.wait_until_ready()

    try:
        with instance.ssh() as ssh:
            cmd_str = " ".join(command) if command else None
            if non_interactive:
                assert (
                    cmd_str is not None
                ), "Command must be provided in non-interactive mode"
                result = ssh.run(cmd_str)
                if result.stdout:
                    click.echo(f"{result.stdout}")
                if result.stderr:
                    click.echo(f"{result.stderr}", err=True)
                sys.exit(result.exit_code)
            else:
                sys.exit(ssh.interactive_shell(command=cmd_str))
    finally:
        if snapshot:
            snapshot = instance.snapshot()
            click.echo(f"Created snapshot:")
            click.echo(f"{snapshot.id}")
        if rm:
            instance.stop()


@instance.command("port-forward")
@click.argument("instance_id")
@click.argument("remote_port", type=int)
@click.argument("local_port", type=int, required=False)
def port_forward(instance_id, remote_port, local_port):
    """Forward a port from an instance to your local machine"""
    if not local_port:
        local_port = remote_port

    instance = client.instances.get(instance_id)
    with (
        instance.ssh() as ssh,
        ssh.tunnel(local_port=local_port, remote_port=remote_port) as tunnel,
    ):
        click.echo(f"Local server listening on localhost:{local_port}")
        click.echo(f"Forwarding to {remote_port}")
        tunnel.wait()


@instance.command("copy")
@click.argument("source")
@click.argument("destination")
@click.option("--recursive", "-r", is_flag=True, help="Copy directories recursively")
def copy_files(source, destination, recursive):
    """Copy files to or from a Morph instance.

    Supports copying in both directions:
    - From instance to local: morph instance copy instance_id:/remote/path /local/path
    - From local to instance: morph instance copy /local/path instance_id:/remote/path

    The destination can be:
    - A full path including filename
    - A directory path (ending with '/' or an existing directory)
    - Just the instance (instance_id:): files will be copied to home directory

    Use -r or --recursive to copy directories recursively.

    Examples:
        morph instance copy morphvm_1234:/etc/config.json ./config.json
        morph instance copy ./local/file.txt morphvm_1234:/remote/path/
        morph instance copy morphvm_1234:.bashrc .
        morph instance copy README.md morphvm_1234:
        morph instance copy -r ./local/dir morphvm_1234:/remote/dir/
    """
    import os
    import os.path
    import stat
    import pathlib

    def is_remote_dir(sftp, path):
        """Check if remote path is a directory"""
        try:
            return stat.S_ISDIR(sftp.stat(path).st_mode)
        except IOError:
            return False

    def copy_recursive_to_remote(sftp, local_path, remote_path):
        """Recursively copy a local directory to remote"""
        local_path = pathlib.Path(local_path)

        if not local_path.exists():
            raise click.UsageError(f"Local path does not exist: {local_path}")

        # If source is a file, just copy it directly
        if local_path.is_file():
            try:
                sftp.put(str(local_path), remote_path)
            except IOError as e:
                # Create parent directories if they don't exist
                parent_dir = os.path.dirname(remote_path)
                if parent_dir:
                    try:
                        sftp.mkdir(parent_dir)
                    except IOError:
                        # Directory might already exist or need parent directories
                        sftp.makedirs(parent_dir)
                sftp.put(str(local_path), remote_path)
            return

        # For directories, create the remote directory if it doesn't exist
        try:
            sftp.mkdir(remote_path)
        except IOError:
            # Directory might already exist, ignore the error
            pass

        # Recursively copy contents
        for item in local_path.iterdir():
            remote_item_path = os.path.join(remote_path, item.name)
            if item.is_dir():
                copy_recursive_to_remote(sftp, item, remote_item_path)
            else:
                sftp.put(str(item), remote_item_path)

    def copy_recursive_from_remote(sftp, remote_path, local_path):
        """Recursively copy a remote directory to local"""
        # Convert local path to Path object for easier manipulation
        local_path = pathlib.Path(local_path)

        try:
            # Try to get remote path attributes
            remote_attr = sftp.stat(remote_path)
        except IOError as e:
            raise click.UsageError(f"Remote path does not exist: {remote_path}")

        # If source is a file, just copy it directly
        if stat.S_ISREG(remote_attr.st_mode):
            # Create parent directories if they don't exist
            local_path.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote_path, str(local_path))
            return

        # For directories, create the local directory if it doesn't exist
        local_path.mkdir(parents=True, exist_ok=True)

        # Recursively copy contents
        for item in sftp.listdir_attr(remote_path):
            remote_item_path = os.path.join(remote_path, item.filename)
            local_item_path = local_path / item.filename

            if stat.S_ISDIR(item.st_mode):
                copy_recursive_from_remote(sftp, remote_item_path, local_item_path)
            else:
                sftp.get(remote_item_path, str(local_item_path))

    # Parse instance ID and path from source/destination
    def parse_instance_path(path):
        if ":" not in path:
            return None, path
        instance_id, remote_path = path.split(":", 1)
        return instance_id, remote_path

    source_instance, source_path = parse_instance_path(source)
    dest_instance, dest_path = parse_instance_path(destination)

    # Validate that exactly one side is a remote path
    if (source_instance and dest_instance) or (
        not source_instance and not dest_instance
    ):
        raise click.UsageError(
            "One (and only one) path must be a remote path in the format instance_id:/path"
        )

    # Get the instance
    instance_id = source_instance or dest_instance
    assert instance_id is not None
    instance = client.instances.get(instance_id)

    with instance.ssh() as ssh:
        sftp = ssh._client.open_sftp()
        try:
            if source_instance:
                # Downloading from instance
                click.echo(
                    f"Downloading from {instance_id}:{source_path} to {dest_path}"
                )
                if recursive:
                    copy_recursive_from_remote(sftp, source_path, dest_path)
                else:
                    dest_path = pathlib.Path(dest_path)
                    if dest_path.is_dir():
                        dest_path = dest_path / os.path.basename(source_path)
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    sftp.get(source_path, str(dest_path))
            else:
                # Uploading to instance
                # Handle destination path
                if not dest_path:
                    # Empty destination, use source filename
                    dest_path = os.path.basename(source_path)
                elif dest_path.endswith("/") or is_remote_dir(sftp, dest_path):
                    # Destination is a directory (either by '/' or by checking)
                    dest_path = os.path.join(
                        dest_path.rstrip("/"), os.path.basename(source_path)
                    )

                click.echo(f"Uploading from {source_path} to {instance_id}:{dest_path}")
                if recursive:
                    copy_recursive_to_remote(sftp, source_path, dest_path)
                else:
                    try:
                        sftp.put(source_path, dest_path)
                    except IOError:
                        # Try creating parent directory if it doesn't exist
                        parent_dir = os.path.dirname(dest_path)
                        if parent_dir:
                            try:
                                sftp.mkdir(parent_dir)
                            except IOError:
                                sftp.makedirs(parent_dir)
                        sftp.put(source_path, dest_path)
        finally:
            sftp.close()


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
