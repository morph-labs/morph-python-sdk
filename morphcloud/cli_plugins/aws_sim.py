import json
import os
import pathlib
from typing import Any

import click
import httpx


DEFAULT_SIM_AWS_BASE_URL = "https://sim-aws.svc.cloud.morph.so"
DEFAULT_CONNECTOR_IMAGE = "ghcr.io/morph-labs/sim-aws-connector:latest"
DEFAULT_CONNECT_BUNDLE_FILENAME = "aws-sim-connect-bundle.json"
SRC_VALID_MARK_SYSCTL = "net.ipv4.conf.all.src_valid_mark=1"


def _get_sim_aws_base_url() -> str:
    return os.environ.get("SIM_AWS_BASE_URL", DEFAULT_SIM_AWS_BASE_URL).rstrip("/")


def _get_morph_api_key() -> str:
    key = os.environ.get("MORPH_API_KEY")
    if not key:
        raise click.ClickException(
            "Error: MORPH_API_KEY environment variable is not set. "
            "Set it (export MORPH_API_KEY='...') and retry."
        )
    return key


def _http_client() -> httpx.Client:
    return httpx.Client(
        base_url=_get_sim_aws_base_url(),
        headers={"Authorization": f"Bearer {_get_morph_api_key()}"},
        timeout=httpx.Timeout(30.0),
    )


def _raise_for_status(resp: httpx.Response) -> None:
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        body = ""
        try:
            body = resp.text
        except Exception:
            body = ""
        msg = f"Sim-AWS request failed: {resp.status_code} {resp.reason_phrase}"
        if body:
            msg = f"{msg}\n{body}"
        raise click.ClickException(msg) from e


def _request_json(method: str, path: str, *, json_body: Any | None = None) -> Any:
    with _http_client() as client:
        resp = client.request(method, path, json=json_body)
    _raise_for_status(resp)
    if resp.status_code == 204:
        return None
    return resp.json()


def _ensure_group(cli_group: click.Group, name: str, help_text: str) -> click.Group:
    existing = cli_group.commands.get(name)
    if isinstance(existing, click.Group):
        return existing
    if existing is not None:
        raise click.ClickException(
            f"Cannot install aws-sim plugin: command '{name}' already exists and is not a group."
        )
    new_group = click.Group(name=name, help=help_text)
    cli_group.add_command(new_group)
    return new_group


def _print_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, sort_keys=True))


def _docker_run_template(bundle_path: str) -> str:
    bundle_path_abs = str(pathlib.Path(bundle_path).expanduser().resolve())
    image = os.environ.get("AWS_SIM_CONNECTOR_IMAGE", DEFAULT_CONNECTOR_IMAGE)
    return (
        "docker run --rm -it "
        "--cap-add=NET_ADMIN "
        "--device /dev/net/tun "
        f"--sysctl {SRC_VALID_MARK_SYSCTL} "
        "-e MORPH_API_KEY "
        f"-v {bundle_path_abs}:/bundle.json:ro "
        f"{image} "
        "--bundle /bundle.json"
    )


def _split_csv_args(values: tuple[str, ...]) -> list[str]:
    items: list[str] = []
    for raw in values:
        for part in raw.split(","):
            part = part.strip()
            if part:
                items.append(part)
    return items


def _default_regions() -> list[str]:
    raw = os.environ.get("SIM_AWS_REGIONS", "").strip()
    if raw:
        return _split_csv_args((raw,))
    return ["us-east-1"]


def _default_services() -> list[str]:
    raw = os.environ.get("SIM_AWS_SERVICES", "").strip()
    if raw:
        return _split_csv_args((raw,))
    return ["s3", "ec2"]


def load(cli_group: click.Group) -> None:
    """
    Entry point for the `morphcloud.cli_plugins` group.

    Registers: `morphcloud env aws-sim ...`
    """

    env_group = _ensure_group(cli_group, "env", "Manage external environments.")
    aws_sim_group = _ensure_group(env_group, "aws-sim", "Manage Sim-AWS environments.")

    @aws_sim_group.command(name="create")
    @click.option(
        "--region",
        "regions",
        multiple=True,
        help="Region(s); repeatable and/or comma-separated.",
    )
    @click.option(
        "--service",
        "services",
        multiple=True,
        help="Service(s); repeatable and/or comma-separated.",
    )
    @click.option(
        "--ttl-seconds",
        "ttl_seconds",
        type=int,
        default=None,
        help="Environment TTL in seconds.",
    )
    @click.option(
        "--name",
        "name",
        type=str,
        default=None,
        help="Optional environment name.",
    )
    def create(regions: tuple[str, ...], services: tuple[str, ...], ttl_seconds: int | None, name: str | None) -> None:
        """Create a Sim-AWS environment."""
        create_body: dict[str, Any] = {
            "regions": _split_csv_args(regions) or _default_regions(),
            "services": _split_csv_args(services) or _default_services(),
        }
        if ttl_seconds is not None:
            create_body["ttl_seconds"] = ttl_seconds
        if name:
            create_body["name"] = name
        _print_json(_request_json("POST", "/v1/envs", json_body=create_body))

    @aws_sim_group.command(name="list")
    def list_() -> None:
        """List Sim-AWS environments."""
        _print_json(_request_json("GET", "/v1/envs"))

    @aws_sim_group.command(name="get")
    @click.argument("env_id")
    def get(env_id: str) -> None:
        """Get a Sim-AWS environment."""
        _print_json(_request_json("GET", f"/v1/envs/{env_id}"))

    @aws_sim_group.command(name="start")
    @click.argument("env_id")
    def start(env_id: str) -> None:
        """Start a Sim-AWS environment."""
        _print_json(_request_json("POST", f"/v1/envs/{env_id}/start"))

    @aws_sim_group.command(name="pause")
    @click.argument("env_id")
    def pause(env_id: str) -> None:
        """Pause a Sim-AWS environment."""
        _print_json(_request_json("POST", f"/v1/envs/{env_id}/pause"))

    @aws_sim_group.command(name="snapshot")
    @click.argument("env_id")
    def snapshot(env_id: str) -> None:
        """Snapshot a Sim-AWS environment."""
        _print_json(_request_json("POST", f"/v1/envs/{env_id}/snapshot"))

    @aws_sim_group.command(name="restore")
    @click.argument("env_id")
    @click.argument("snapshot_id")
    def restore(env_id: str, snapshot_id: str) -> None:
        """Restore a Sim-AWS environment from a snapshot_id."""
        _print_json(_request_json("POST", f"/v1/envs/{env_id}/restore", json_body={"snapshot_id": snapshot_id}))

    @aws_sim_group.command(name="delete")
    @click.argument("env_id")
    def delete(env_id: str) -> None:
        """Delete a Sim-AWS environment."""
        _print_json(_request_json("DELETE", f"/v1/envs/{env_id}"))

    @aws_sim_group.command(name="connect")
    @click.argument("env_id")
    @click.option(
        "--output",
        "output_path",
        default=DEFAULT_CONNECT_BUNDLE_FILENAME,
        show_default=True,
        help="Write the connect bundle to this path.",
    )
    def connect(env_id: str, output_path: str) -> None:
        """
        Fetch a connect bundle, write it to a file, and print a connector `docker run` command.

        The connect bundle is sensitive (WireGuard private key); keep the output file safe.
        """

        bundle = _request_json("POST", f"/v1/envs/{env_id}/connect")
        output = pathlib.Path(output_path).expanduser()
        output.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(output, 0o600)
        except Exception:
            pass
        click.echo(f"Wrote connect bundle to: {output}")
        click.echo(_docker_run_template(str(output)))
