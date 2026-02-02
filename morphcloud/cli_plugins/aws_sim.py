import json
import os
import pathlib
import subprocess
from typing import Any

import click
import httpx


DEFAULT_SIM_AWS_BASE_URL = "https://sim-aws.svc.cloud.morph.so"
DEFAULT_CONNECTOR_IMAGE = "ghcr.io/morph-labs/sim-aws-connector:latest"
DEFAULT_CONNECT_BUNDLE_FILENAME = "aws-sim-connect-bundle.json"
SRC_VALID_MARK_SYSCTL = "net.ipv4.conf.all.src_valid_mark=1"
DEFAULT_CONNECTOR_CONTAINER_NAME = "sim-aws-connector"
DEFAULT_CONNECT_HELPERS_ENV = "aws-env.sh"
DEFAULT_CONNECT_HELPERS_WRAPPER = "aws"


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
    timeout_s = float(os.environ.get("SIM_AWS_HTTP_TIMEOUT_S", "180"))
    return httpx.Client(
        base_url=_get_sim_aws_base_url(),
        headers={"Authorization": f"Bearer {_get_morph_api_key()}"},
        timeout=httpx.Timeout(timeout_s),
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
    bundle_container_path = "/run/connect-bundle.json"
    return (
        "docker run --rm -it "
        "--cap-add=NET_ADMIN "
        "--device /dev/net/tun "
        f"--sysctl {SRC_VALID_MARK_SYSCTL} "
        "-e MORPH_API_KEY "
        f"-v {bundle_path_abs}:{bundle_container_path}:ro "
        f"{image} "
        "bash"
    )


def _docker_run_detached_template(bundle_path: str, *, container_name: str = "sim-aws-connector") -> str:
    bundle_path_abs = str(pathlib.Path(bundle_path).expanduser().resolve())
    image = os.environ.get("AWS_SIM_CONNECTOR_IMAGE", DEFAULT_CONNECTOR_IMAGE)
    bundle_container_path = "/run/connect-bundle.json"
    return (
        f"docker run -d --name {container_name} "
        "--cap-add=NET_ADMIN "
        "--device /dev/net/tun "
        f"--sysctl {SRC_VALID_MARK_SYSCTL} "
        "-e MORPH_API_KEY "
        "-e AWS_PAGER= "
        "-e AWS_EC2_METADATA_DISABLED=true "
        "-e AWS_ACCESS_KEY_ID=test "
        "-e AWS_SECRET_ACCESS_KEY=test "
        f"-v {bundle_path_abs}:{bundle_container_path}:ro "
        f"{image} "
        "sleep infinity"
    )


def _default_region_from_bundle(bundle: Any) -> str:
    aws = bundle.get("aws") if isinstance(bundle, dict) else None
    if not isinstance(aws, dict):
        return ""
    regions = aws.get("regions")
    if not isinstance(regions, list) or not regions:
        return ""
    return str(regions[0] or "").strip()


def _emit_connect_helpers(
    *,
    dir_path: pathlib.Path,
    container_name: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    dir_path.mkdir(parents=True, exist_ok=True)

    env_path = dir_path / DEFAULT_CONNECT_HELPERS_ENV
    wrapper_path = dir_path / DEFAULT_CONNECT_HELPERS_WRAPPER

    env_path.write_text(
        "\n".join(
            [
                "# Source this file to make `aws` call the local ./aws wrapper (relative to this file).",
                '_simaws_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"',
                f'export AWS_SIM_CONNECTOR_CONTAINER="${{AWS_SIM_CONNECTOR_CONTAINER:-{container_name}}}"',
                'aws() { "$_simaws_dir/aws" "$@"; }',
            ]
        ),
        encoding="utf-8",
    )

    wrapper_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "",
                'CONTAINER="${AWS_SIM_CONNECTOR_CONTAINER:-sim-aws-connector}"',
                "",
                'if ! docker ps --format "{{.Names}}" | grep -qx "$CONTAINER"; then',
                '  echo "ERROR: connector container \'$CONTAINER\' is not running." >&2',
                "  exit 1",
                "fi",
                "",
                "tty=()",
                '[[ -t 0 && -t 1 ]] && tty=(-t)',
                "",
                'exec docker exec -i "${tty[@]}" "$CONTAINER" bash -lc \'',
                "  set -euo pipefail",
                "  # Import AWS_* (and CA bundle vars) from PID1 env (set by connector entrypoint).",
                "  while IFS= read -r kv; do",
                "    case \"$kv\" in",
                "      AWS_*=*|SSL_CERT_FILE=*|REQUESTS_CA_BUNDLE=*|CURL_CA_BUNDLE=*)",
                "        export \"$kv\"",
                "        ;;",
                "    esac",
                "  done < <(tr \"\\0\" \"\\n\" </proc/1/environ)",
                "",
                '  exec aws "$@"',
                "' -- \"$@\"",
                "",
            ]
        ),
        encoding="utf-8",
    )
    try:
        os.chmod(wrapper_path, 0o755)
    except Exception:
        pass

    return env_path, wrapper_path


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
        default=None,
        show_default=False,
        help="Optional: write the connect bundle to this path (sensitive).",
    )
    @click.option(
        "--container-name",
        default=DEFAULT_CONNECTOR_CONTAINER_NAME,
        show_default=True,
        help="Name for the detached connector container.",
    )
    @click.option(
        "--replace",
        is_flag=True,
        help="If set, delete any existing container with --container-name before starting.",
    )
    @click.option(
        "--no-run",
        is_flag=True,
        help="If set, do not start the detached connector container; only print commands and emit helper scripts.",
    )
    @click.option(
        "--emit-dir",
        default="./run",
        show_default=True,
        help="Directory to write helper scripts (aws-env.sh + aws wrapper).",
    )
    def connect(
        env_id: str,
        output_path: str | None,
        container_name: str,
        replace: bool,
        no_run: bool,
        emit_dir: str,
    ) -> None:
        """
        Fetch a connect bundle and start a detached connector container.

        By default this does NOT write the bundle to disk. Instead, it passes the bundle to the
        connector via the CONNECT_BUNDLE_JSON environment variable.

        If you want a bundle file for debugging, pass --output.
        """

        bundle = _request_json("POST", f"/v1/envs/{env_id}/connect")

        output = None
        if output_path:
            output = pathlib.Path(output_path).expanduser()
            output.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
            try:
                os.chmod(output, 0o600)
            except Exception:
                pass
            click.echo(f"Wrote connect bundle to: {output}")

        default_region = _default_region_from_bundle(bundle)

        image = os.environ.get("AWS_SIM_CONNECTOR_IMAGE", DEFAULT_CONNECTOR_IMAGE)
        requires_morph_api_key = bool(bundle.get("auth")) if isinstance(bundle, dict) else True

        # Always include dummy creds + pager off for smoother UX.
        run_args: list[str] = [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "--cap-add=NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "--sysctl",
            SRC_VALID_MARK_SYSCTL,
            "-e",
            "CONNECT_BUNDLE_JSON",
            "-e",
            "AWS_PAGER=",
            "-e",
            "AWS_EC2_METADATA_DISABLED=true",
            "-e",
            "AWS_ACCESS_KEY_ID=test",
            "-e",
            "AWS_SECRET_ACCESS_KEY=test",
        ]
        if requires_morph_api_key:
            run_args += ["-e", "MORPH_API_KEY"]
        if default_region:
            run_args += [
                "-e",
                f"AWS_REGION={default_region}",
                "-e",
                f"AWS_DEFAULT_REGION={default_region}",
            ]
        run_args += [
            image,
            "sleep",
            "infinity",
        ]

        helpers_dir = pathlib.Path(emit_dir).expanduser().resolve()
        env_path, wrapper_path = _emit_connect_helpers(
            dir_path=helpers_dir,
            container_name=container_name,
        )
        click.echo(f"Wrote helper scripts: {env_path} and {wrapper_path}")
        click.echo(f"To enable `aws ...` in your current shell: source {env_path}")

        if replace:
            subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if no_run:
            return

        try:
            env = dict(os.environ)
            # Compact JSON to avoid newlines; passed to docker via `-e CONNECT_BUNDLE_JSON`.
            env["CONNECT_BUNDLE_JSON"] = json.dumps(bundle, separators=(",", ":"), sort_keys=True)
            p = subprocess.run(run_args, text=True, capture_output=True, env=env)
        except FileNotFoundError as e:
            raise click.ClickException("docker is required but was not found on PATH") from e

        if p.returncode != 0:
            msg = (p.stderr or p.stdout or "").strip()
            raise click.ClickException(f"Failed to start connector container (docker run exit {p.returncode}):\n{msg}")

        container_id = (p.stdout or "").strip()
        if container_id:
            click.echo(f"Started connector container: {container_name} ({container_id[:12]})")

        # If the entrypoint fails fast, docker still returns a container id. Catch that here and
        # surface container logs to the user.
        insp = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            text=True,
            capture_output=True,
        )
        if insp.returncode == 0 and (insp.stdout or "").strip() != "true":
            logs = subprocess.run(
                ["docker", "logs", "--tail", "200", container_name],
                text=True,
                capture_output=True,
            )
            tail = (logs.stdout or logs.stderr or "").strip()
            raise click.ClickException(
                f"Connector container '{container_name}' exited immediately.\n"
                f"Try: docker logs {container_name}\n\n"
                f"{tail}"
            )
