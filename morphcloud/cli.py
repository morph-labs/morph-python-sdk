import click
from . import api
import json
from typing import Optional
import sys

def format_json(obj):
    """Helper to pretty print objects"""
    if hasattr(obj, "dict"):
        return json.dumps(obj.dict(), indent=2)
    return json.dumps(obj, indent=2)

@click.group()
@click.option('--debug/--no-debug', default=False, help='Enable debug mode')
def cli(debug):
    """Morph Cloud CLI"""
    pass

# Images
@cli.group()
def images():
    """Manage Morph images"""
    pass

@images.command("list")
def list_images():
    """List all available images"""
    images = api.Image.list()
    for image in images:
        click.echo(format_json(image))

# Snapshots
@cli.group()
def snapshots():
    """Manage Morph snapshots"""
    pass

@snapshots.command("list")
def list_snapshots():
    """List all snapshots"""
    snapshots = api.Snapshot.list()
    for snapshot in snapshots:
        click.echo(format_json(snapshot))

@snapshots.command("create")
@click.option('--image-name', help='Name of the base image')
@click.option('--image-id', help='ID of the base image')
@click.option('--vcpus', type=int, help='Number of VCPUs')
@click.option('--memory', type=int, help='Memory in MB')
@click.option('--disk-size', type=int, help='Disk size in MB')
@click.option('--digest', help='User provided digest')
def create_snapshot(image_name, image_id, vcpus, memory, disk_size, digest):
    """Create a new snapshot"""
    snapshot = api.Snapshot.create(
        image_name=image_name,
        image_id=image_id,
        vcpus=vcpus,
        memory=memory,
        disk_size=disk_size,
        digest=digest
    )
    click.echo(format_json(snapshot))

@snapshots.command("delete")
@click.argument('snapshot_id')
def delete_snapshot(snapshot_id):
    """Delete a snapshot"""
    snapshot = api.Snapshot(id=snapshot_id, object="snapshot", created=0, status=api.SnapshotStatus.READY,
                          vcpus=0, memory=0, disk_size=0, image_id=None)
    snapshot.delete()
    click.echo(f"Deleted snapshot {snapshot_id}")

# Instances
@cli.group()
def instances():
    """Manage Morph instances"""
    pass

@instances.command("list")
def list_instances():
    """List all instances"""
    instances = api.Instance.list()
    for instance in instances:
        click.echo(format_json(instance))

@instances.command("start")
@click.argument('snapshot_id')
def start_instance(snapshot_id):
    """Start a new instance from a snapshot"""
    instance = api.Instance.start(snapshot_id=snapshot_id)
    click.echo(format_json(instance))

@instances.command("stop")
@click.argument('instance_id')
def stop_instance(instance_id):
    """Stop an instance"""
    instance = api.Instance.get(instance_id)
    instance.stop()
    click.echo(f"Stopped instance {instance_id}")

@instances.command("get")
@click.argument('instance_id')
def get_instance(instance_id):
    """Get instance details"""
    instance = api.Instance.get(instance_id)
    click.echo(format_json(instance))

@instances.command("snapshot")
@click.argument('instance_id')
def snapshot_instance(instance_id):
    """Create a snapshot from an instance"""
    instance = api.Instance.get(instance_id)
    snapshot = instance.snapshot()
    click.echo(format_json(snapshot))

@instances.command("clone")
@click.argument('instance_id')
@click.option('--count', type=int, default=1, help='Number of clones to create')
def clone_instance(instance_id, count):
    """Clone an instance"""
    instance = api.Instance.get(instance_id)
    clones = instance.clone(count)
    for clone in clones:
        click.echo(format_json(clone))

@instances.command("ssh-keys")
@click.argument('instance_id')
def get_ssh_keys(instance_id):
    """Get SSH keys for an instance"""
    instance = api.Instance.get(instance_id)
    public_key, private_key = instance.get_ssh_keys()
    click.echo(f"Public key:\n{public_key}\n\nPrivate key:\n{private_key}")

@instances.command("rotate-ssh-keys")
@click.argument('instance_id')
def rotate_ssh_keys(instance_id):
    """Rotate SSH keys for an instance"""
    instance = api.Instance.get(instance_id)
    public_key, private_key = instance.rotate_ssh_keys()
    click.echo(f"New public key:\n{public_key}\n\nNew private key:\n{private_key}")

@instances.command("expose-http")
@click.argument('instance_id')
@click.argument('name')
@click.argument('port', type=int)
def expose_http_service(instance_id, name, port):
    """Expose an HTTP service"""
    instance = api.Instance.get(instance_id)
    instance.expose_http_service(name, port)
    click.echo(f"Exposed HTTP service {name} on port {port}")

@instances.command("unexpose-http")
@click.argument('instance_id')
@click.argument('name')
def unexpose_http_service(instance_id, name):
    """Unexpose an HTTP service"""
    instance = api.Instance.get(instance_id)
    instance.unexpose_http_service(name)
    click.echo(f"Unexposed HTTP service {name}")

@instances.command("exec")
@click.argument('instance_id')
@click.argument('command', nargs=-1)
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

if __name__ == '__main__':
    cli()
