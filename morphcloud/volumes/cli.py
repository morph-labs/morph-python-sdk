from __future__ import annotations

import mimetypes
import pathlib
import sys
import typing
from dataclasses import dataclass

import click
from rich.console import Console
from rich.tree import Tree

from morphcloud._utils import Spinner
from morphcloud.cli_helpers import (
    format_json,
    get_client,
    handle_api_error,
    print_docker_style_table,
)

from .client import VolumeBucket, VolumeListing, VolumeObject, validate_bucket_name


@dataclass(frozen=True)
class VolumeRef:
    bucket: str
    key: str = ""

    @property
    def uri(self) -> str:
        if self.key:
            return f"s3://{self.bucket}/{self.key}"
        return f"s3://{self.bucket}"


def _format_bytes(size: int) -> str:
    if not isinstance(size, int) or size <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    decimals = 0 if unit_index == 0 or value >= 100 else 1 if value >= 10 else 2
    return f"{value:.{decimals}f} {units[unit_index]}"


def _normalize_key(key: str | None) -> str:
    return str(key or "").strip().lstrip("/")


def _normalize_prefix(prefix: str | None) -> str:
    normalized = _normalize_key(prefix)
    if not normalized:
        return ""
    return normalized if normalized.endswith("/") else f"{normalized}/"


def _parse_ref(
    value: str,
    *,
    allow_shorthand: bool,
) -> VolumeRef:
    raw = str(value or "").strip()
    if not raw:
        raise click.ClickException("A volume path is required.")

    if raw.startswith("s3://"):
        remainder = raw[5:]
        bucket, _, key = remainder.partition("/")
        if not bucket:
            raise click.ClickException("Remote paths must include a bucket name.")
        return VolumeRef(bucket=bucket, key=_normalize_key(key))

    if not allow_shorthand:
        raise click.ClickException(
            "Remote paths for this command must use the form s3://bucket/path."
        )

    bucket, _, key = raw.partition("/")
    if not bucket:
        raise click.ClickException("A bucket name is required.")
    return VolumeRef(bucket=bucket, key=_normalize_key(key))


def _resolve_target(
    volumes_client,
    ref: VolumeRef,
) -> tuple[str, str, VolumeObject | None]:
    if not ref.key:
        return "bucket", "", None
    if ref.key.endswith("/"):
        return "prefix", _normalize_prefix(ref.key), None

    exact = volumes_client.head_object(ref.bucket, ref.key)
    if exact is not None:
        return "object", ref.key, exact
    return "prefix", _normalize_prefix(ref.key), None


def _print_bucket_rows(buckets: list[VolumeBucket]) -> None:
    headers = ["Bucket", "Created"]
    rows = [[bucket.name, bucket.created_at or "-"] for bucket in buckets]
    print_docker_style_table(headers, rows)


def _print_listing_rows(listing: VolumeListing) -> None:
    headers = ["Type", "Name", "Size", "Modified"]
    rows: list[list[str]] = []
    for prefix in listing.prefixes:
        rows.append(["DIR", f"{prefix.name}/", "-", "-"])
    for obj in listing.objects:
        rows.append(
            [
                "FILE",
                obj.name,
                _format_bytes(obj.size),
                obj.last_modified or "-",
            ]
        )
    print_docker_style_table(headers, rows)


def _print_recursive_rows(objects: list[VolumeObject]) -> None:
    headers = ["Key", "Size", "Modified"]
    rows = [
        [obj.key, _format_bytes(obj.size), obj.last_modified or "-"] for obj in objects
    ]
    print_docker_style_table(headers, rows)


def _build_tree(objects: list[VolumeObject], *, root_label: str, prefix: str) -> Tree:
    tree = Tree(root_label)
    root: dict[str, typing.Any] = {"dirs": {}, "files": []}

    for obj in objects:
        relative = obj.key
        if prefix and relative.startswith(prefix):
            relative = relative[len(prefix) :]
        relative = relative.lstrip("/")
        if not relative:
            continue
        parts = relative.split("/")
        cursor = root
        for part in parts[:-1]:
            cursor = cursor["dirs"].setdefault(part, {"dirs": {}, "files": []})
        cursor["files"].append(obj.model_copy(update={"name": parts[-1]}))

    def render(node: dict[str, typing.Any], rich_tree: Tree) -> None:
        for name in sorted(node["dirs"].keys(), key=str.casefold):
            child = rich_tree.add(f"[bold cyan]{name}/[/bold cyan]")
            render(node["dirs"][name], child)
        for obj in sorted(node["files"], key=lambda item: item.name.casefold()):
            rich_tree.add(f"{obj.name} [dim]{_format_bytes(obj.size)}[/dim]")

    render(root, tree)
    if not root["dirs"] and not root["files"]:
        tree.add("[dim](empty)[/dim]")
    return tree


def _get_volumes_client():
    client = get_client()
    return client.volumes


@click.group()
def volumes():
    """Manage Morph Volumes via the S3-compatible gateway."""


@volumes.command("ls")
@click.argument("target", required=False)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="List all objects recursively under the given prefix.",
)
@click.option("--json", "json_mode", is_flag=True, default=False)
def list_volumes(target: str | None, recursive: bool, json_mode: bool) -> None:
    """List buckets, prefixes, or objects.

    `TARGET` may be omitted, `bucket`, `bucket/prefix`, or `s3://bucket/prefix`.
    """

    volumes_client = _get_volumes_client()
    try:
        if not target:
            buckets = volumes_client.list_buckets()
            if json_mode:
                click.echo(format_json([bucket.model_dump() for bucket in buckets]))
                return
            _print_bucket_rows(buckets)
            return

        ref = _parse_ref(target, allow_shorthand=True)
        target_kind, resolved_key, exact_object = _resolve_target(volumes_client, ref)

        if recursive:
            if target_kind == "object" and exact_object is not None:
                objects = [exact_object]
            else:
                objects = volumes_client.list_all_objects(ref.bucket, prefix=resolved_key)
            if json_mode:
                click.echo(format_json([obj.model_dump() for obj in objects]))
                return
            _print_recursive_rows(objects)
            return

        if target_kind == "object" and exact_object is not None:
            objects = [exact_object]
            if json_mode:
                click.echo(format_json([obj.model_dump() for obj in objects]))
                return
            _print_recursive_rows(objects)
            return

        listing = volumes_client.list_directory(ref.bucket, prefix=resolved_key)
        if json_mode:
            click.echo(format_json(listing))
            return
        _print_listing_rows(listing)
    except Exception as exc:
        handle_api_error(exc)


@volumes.command("tree")
@click.argument("target", required=False)
@click.option("--json", "json_mode", is_flag=True, default=False)
def tree_volumes(target: str | None, json_mode: bool) -> None:
    """Render a file-explorer style tree for a bucket or prefix."""

    volumes_client = _get_volumes_client()
    console = Console()

    try:
        if not target:
            buckets = volumes_client.list_buckets()
            if json_mode:
                click.echo(format_json([bucket.model_dump() for bucket in buckets]))
                return
            root_tree = Tree("s3://")
            if not buckets:
                root_tree.add("[dim](no buckets)[/dim]")
            for bucket in buckets:
                root_tree.add(f"[bold]{bucket.name}[/bold]")
            console.print(root_tree)
            return

        ref = _parse_ref(target, allow_shorthand=True)
        target_kind, resolved_key, exact_object = _resolve_target(volumes_client, ref)
        if target_kind == "object" and exact_object is not None:
            if json_mode:
                click.echo(format_json(exact_object))
                return
            tree = Tree(ref.uri)
            tree.add(f"{exact_object.name} [dim]{_format_bytes(exact_object.size)}[/dim]")
            console.print(tree)
            return

        prefix = resolved_key
        objects = volumes_client.list_all_objects(ref.bucket, prefix=prefix)
        if json_mode:
            click.echo(format_json([obj.model_dump() for obj in objects]))
            return
        console.print(
            _build_tree(
                objects,
                root_label=ref.uri if prefix else f"s3://{ref.bucket}",
                prefix=prefix,
            )
        )
    except Exception as exc:
        handle_api_error(exc)


@volumes.command("mb")
@click.argument("bucket")
def make_bucket(bucket: str) -> None:
    """Create a bucket."""

    validate_bucket_name(bucket)
    volumes_client = _get_volumes_client()
    try:
        with Spinner(
            text=f"Creating bucket {bucket}...",
            success_text=f"Bucket created: {bucket}",
            success_emoji="🪣",
        ):
            volumes_client.create_bucket(bucket)
        click.echo(f"s3://{bucket}")
    except Exception as exc:
        handle_api_error(exc)


@volumes.command("rb")
@click.argument("bucket")
def remove_bucket(bucket: str) -> None:
    """Remove an empty bucket."""

    ref = _parse_ref(bucket, allow_shorthand=True)
    if ref.key:
        raise click.ClickException("Bucket removal expects only a bucket name.")

    volumes_client = _get_volumes_client()
    try:
        with Spinner(
            text=f"Removing bucket {ref.bucket}...",
            success_text=f"Bucket removed: {ref.bucket}",
            success_emoji="🗑",
        ):
            volumes_client.delete_bucket(ref.bucket)
        click.echo(f"Removed s3://{ref.bucket}")
    except Exception as exc:
        handle_api_error(exc)


@volumes.command("cat")
@click.argument("target")
def cat_volume_object(target: str) -> None:
    """Print an object's contents to stdout."""

    ref = _parse_ref(target, allow_shorthand=True)
    if not ref.key:
        raise click.ClickException("cat expects an object path, not a bucket.")

    volumes_client = _get_volumes_client()
    try:
        target_kind, _, exact_object = _resolve_target(volumes_client, ref)
        if target_kind != "object" or exact_object is None:
            raise click.ClickException("cat expects an existing object path.")
        data = volumes_client.get_object(ref.bucket, exact_object.key)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except Exception as exc:
        handle_api_error(exc)


def _is_remote_path(value: str) -> bool:
    return str(value or "").strip().startswith("s3://")


def _upload_files(
    volumes_client,
    *,
    local_path: pathlib.Path,
    remote_ref: VolumeRef,
    recursive: bool,
) -> list[tuple[pathlib.Path, str, int]]:
    if not local_path.exists():
        raise click.ClickException(f"Local path does not exist: {local_path}")

    uploads: list[tuple[pathlib.Path, str, int]] = []

    if local_path.is_dir():
        if not recursive:
            raise click.ClickException(
                "Uploading a directory requires --recursive."
            )
        if remote_ref.key and not remote_ref.key.endswith("/"):
            raise click.ClickException(
                "Remote destination for directory uploads must end with '/'."
            )
        destination_prefix = _normalize_prefix(remote_ref.key)
        files = sorted(path for path in local_path.rglob("*") if path.is_file())
        for file_path in files:
            relative = file_path.relative_to(local_path).as_posix()
            uploads.append((file_path, f"{destination_prefix}{relative}", file_path.stat().st_size))
        return uploads

    if not remote_ref.key or remote_ref.key.endswith("/"):
        destination_key = f"{_normalize_prefix(remote_ref.key)}{local_path.name}"
    else:
        destination_key = remote_ref.key
    uploads.append((local_path, destination_key, local_path.stat().st_size))
    return uploads


def _download_targets(
    volumes_client,
    *,
    remote_ref: VolumeRef,
    local_path: pathlib.Path,
    recursive: bool,
) -> list[tuple[str, pathlib.Path]]:
    target_kind, resolved_key, exact_object = _resolve_target(volumes_client, remote_ref)
    if target_kind == "object" and exact_object is not None:
        if local_path.exists() and local_path.is_dir():
            destination = local_path / pathlib.Path(exact_object.key).name
        else:
            destination = local_path
        return [(exact_object.key, destination)]

    if not recursive:
        raise click.ClickException(
            "Downloading a prefix requires --recursive."
        )

    prefix = resolved_key
    objects = volumes_client.list_all_objects(remote_ref.bucket, prefix=prefix)
    if not objects:
        raise click.ClickException(f"No objects found under {remote_ref.uri}")

    targets: list[tuple[str, pathlib.Path]] = []
    for obj in objects:
        relative = obj.key[len(prefix) :] if prefix and obj.key.startswith(prefix) else obj.key
        relative = relative.lstrip("/")
        targets.append((obj.key, local_path / relative))
    return targets


@volumes.command("cp")
@click.argument("source")
@click.argument("destination")
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Copy directories or prefixes recursively.",
)
def copy_objects(source: str, destination: str, recursive: bool) -> None:
    """Copy between local paths and volumes.

    Exactly one side must use an `s3://bucket/path` remote URI.
    """

    source_is_remote = _is_remote_path(source)
    destination_is_remote = _is_remote_path(destination)
    if source_is_remote == destination_is_remote:
        raise click.ClickException(
            "Exactly one side of cp must be a remote s3:// path."
        )

    volumes_client = _get_volumes_client()
    try:
        if destination_is_remote:
            remote_ref = _parse_ref(destination, allow_shorthand=False)
            local_path = pathlib.Path(source).expanduser()
            uploads = _upload_files(
                volumes_client,
                local_path=local_path,
                remote_ref=remote_ref,
                recursive=recursive,
            )
            total_bytes = sum(size for _, _, size in uploads)
            with Spinner(
                text=f"Uploading {len(uploads)} file(s)...",
                success_text=f"Uploaded {len(uploads)} file(s)",
                success_emoji="⬆️",
            ):
                for file_path, key, _ in uploads:
                    content_type = (
                        mimetypes.guess_type(file_path.name)[0]
                        or "application/octet-stream"
                    )
                    volumes_client.put_object(
                        remote_ref.bucket,
                        key,
                        file_path.read_bytes(),
                        content_type=content_type,
                    )
            for file_path, key, _ in uploads:
                click.echo(f"{file_path} -> s3://{remote_ref.bucket}/{key}")
            click.echo(f"{len(uploads)} file(s), {_format_bytes(total_bytes)} uploaded")
            return

        remote_ref = _parse_ref(source, allow_shorthand=False)
        local_path = pathlib.Path(destination).expanduser()
        targets = _download_targets(
            volumes_client,
            remote_ref=remote_ref,
            local_path=local_path,
            recursive=recursive,
        )
        total_bytes = 0
        with Spinner(
            text=f"Downloading {len(targets)} file(s)...",
            success_text=f"Downloaded {len(targets)} file(s)",
            success_emoji="⬇️",
        ):
            for key, destination_path in targets:
                data = volumes_client.get_object(remote_ref.bucket, key)
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                destination_path.write_bytes(data)
                total_bytes += len(data)
        for key, destination_path in targets:
            click.echo(f"s3://{remote_ref.bucket}/{key} -> {destination_path}")
        click.echo(f"{len(targets)} file(s), {_format_bytes(total_bytes)} downloaded")
    except Exception as exc:
        handle_api_error(exc)


@volumes.command("rm")
@click.argument("target")
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Delete every object under a prefix.",
)
@click.option("--yes", "-y", is_flag=True, help="Skip recursive delete confirmation.")
def remove_objects(target: str, recursive: bool, yes: bool) -> None:
    """Delete an object or a prefix worth of objects."""

    ref = _parse_ref(target, allow_shorthand=True)
    if not ref.key:
        raise click.ClickException(
            "rm deletes objects or prefixes. Use 'morphcloud volumes rb BUCKET' for buckets."
        )

    volumes_client = _get_volumes_client()
    try:
        target_kind, resolved_key, exact_object = _resolve_target(volumes_client, ref)
        if target_kind == "object" and exact_object is not None and not recursive:
            with Spinner(
                text=f"Deleting {ref.uri}...",
                success_text=f"Deleted {ref.uri}",
                success_emoji="🗑",
            ):
                volumes_client.delete_object(ref.bucket, exact_object.key)
            click.echo(f"Deleted {ref.uri}")
            return

        if target_kind == "object" and exact_object is not None and recursive:
            with Spinner(
                text=f"Deleting {ref.uri}...",
                success_text=f"Deleted {ref.uri}",
                success_emoji="🗑",
            ):
                volumes_client.delete_object(ref.bucket, exact_object.key)
            click.echo(f"Deleted {ref.uri}")
            return

        if not recursive:
            raise click.ClickException(
                "Target looks like a prefix. Re-run with --recursive to remove matching objects."
            )

        prefix = resolved_key
        objects = volumes_client.list_all_objects(ref.bucket, prefix=prefix)
        if not objects:
            click.echo(f"No objects found under {ref.uri}")
            return

        if not yes:
            click.confirm(
                f"Delete {len(objects)} object(s) under {ref.uri}?",
                abort=True,
            )

        with Spinner(
            text=f"Deleting {len(objects)} object(s)...",
            success_text=f"Deleted {len(objects)} object(s)",
            success_emoji="🗑",
        ):
            for obj in objects:
                volumes_client.delete_object(ref.bucket, obj.key)
        click.echo(f"Deleted {len(objects)} object(s) under {ref.uri}")
    except Exception as exc:
        handle_api_error(exc)


def register_cli_plugin(cli_group: click.Group) -> None:
    """Register the first-party `morphcloud volumes` command group."""

    cli_group.add_command(volumes, name="volumes")
    cli_group.add_command(volumes, name="volume")
