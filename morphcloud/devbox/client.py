"""Extended Devbox client with custom methods."""

import os
import time
import typing
import urllib.parse

import paramiko

from .gen.client import AsyncMorphLabsApi, MorphLabsApi
from .gen.types.devbox_response import DevboxResponse
from .terminals import AsyncDevboxTerminals, DevboxTerminals


class CodexSessionError(Exception):
    """Raised when codex session setup fails."""

    pass


class DevboxClient(MorphLabsApi):
    """Extended Devbox client with custom convenience methods."""

    @property
    def terminals(self) -> DevboxTerminals:
        """
        Devbox "terminals" (tmux sessions).

        This is a thin convenience wrapper around `self.tmux.*`.
        """

        existing = getattr(self, "_terminals", None)
        if existing is None:
            existing = DevboxTerminals(self)
            setattr(self, "_terminals", existing)
        return typing.cast(DevboxTerminals, existing)

    def start(
        self,
        template_id: str,
        *,
        name: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> DevboxResponse:
        """
        Start an "instant devbox" from a template.

        This uses a devbox-service endpoint that is not currently part of the
        published OpenAPI spec.
        """

        payload: typing.Dict[str, typing.Any] = {}
        if name:
            payload["name"] = name
        if metadata:
            payload["metadata"] = {k: str(v) for k, v in metadata.items()}
        if "template_id" not in payload.get("metadata", {}):
            payload.setdefault("metadata", {})["template_id"] = str(template_id)

        path = f"api/templates/{_encode_template_id(template_id)}/instant-devbox"
        response = self._client_wrapper.httpx_client.request(
            path, method="POST", json=payload or None
        )
        if response.status_code >= 400:
            _raise_instant_error(response, context="start request")

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "Instant devbox start did not return JSON payload."
            ) from exc
        return DevboxResponse.model_validate(data)

    def codex(
        self,
        devbox_id: str,
        openai_secret_name: str,
        tmux_session_name: str = "codex",
        *,
        verify_timeout: int = 30,
    ) -> typing.Dict[str, typing.Any]:
        """
        Set up a codex session on a devbox.

        This method:
        1. Gets SSH credentials for the devbox
        2. Establishes SSH connection
        3. Verifies/installs tmux and codex
        4. Creates a tmux session
        5. Injects OPENAI_API_KEY from user secrets
        6. Starts codex in the session

        Parameters
        ----------
        devbox_id : str
            ID of the devbox to set up codex on
        openai_secret_name : str
            Name of the user secret containing the OpenAI API key
        tmux_session_name : str
            Name for the tmux session (default: "codex")
        verify_timeout : int
            Timeout in seconds for SSH connection and command execution

        Returns
        -------
        dict
            Information about the created session including:
            - devbox_id: The devbox ID
            - tmux_session: The tmux session name
            - ssh_host: The SSH host
            - status: "ready" if successful

        Raises
        ------
        CodexSessionError
            If any step of the setup fails

        Examples
        --------
        from morphcloud import MorphCloudClient

        client = MorphCloudClient()

        session = client.devbox.codex(
            devbox_id="devbox_123",
            openai_secret_name="OPENAI_API_KEY"
        )
        print(f"Codex session ready on {session['ssh_host']}")
        """

        # Step 1: Get SSH credentials
        try:
            creds = self.admin.get_devbox_ssh_credentials(devbox_id)
        except Exception as e:
            raise CodexSessionError(f"Failed to get SSH credentials: {e}")

        # Step 2: Construct SSH hostname and username
        ssh_hostname = (
            getattr(self, "ssh_hostname", None)
            or os.environ.get("MORPH_SSH_HOSTNAME")
            or "ssh.cloud.morph.so"
        )
        ssh_host = f"{devbox_id}.{ssh_hostname}"
        ssh_username = creds.access_token
        ssh_port = getattr(self, "ssh_port", None)
        if not isinstance(ssh_port, int):
            try:
                ssh_port = int(os.environ.get("MORPH_SSH_PORT", "22"))
            except Exception:
                ssh_port = 22

        # Step 3: Get OpenAI API key from user secrets
        try:
            secret_response = self.user_secrets.get_user_secret(openai_secret_name)
            openai_api_key = secret_response.value
        except Exception as e:
            raise CodexSessionError(f"Failed to get OpenAI API key from secrets: {e}")

        # Step 4: Establish SSH connection
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh_client.connect(
                hostname=ssh_host,
                port=ssh_port,
                username=ssh_username,
                password=creds.password,
                timeout=verify_timeout,
            )
        except Exception as e:
            raise CodexSessionError(f"Failed to establish SSH connection: {e}")

        try:
            # Step 5: Verify/install tmux
            _ensure_command_installed(
                ssh_client, "tmux", "apt-get update && apt-get install -y tmux"
            )

            # Step 6: Verify/install codex
            _ensure_command_installed(
                ssh_client, "codex", "npm install -g @openai/codex"
            )

            # Step 7: Find an available tmux session name
            final_session_name = _find_available_tmux_session(
                ssh_client, tmux_session_name
            )

            # Step 8: Create tmux session
            _execute_ssh_command(
                ssh_client, f"tmux new-session -d -s {final_session_name}"
            )

            # Step 9: Inject OPENAI_API_KEY into the session
            export_cmd = f"export OPENAI_API_KEY='{openai_api_key}'"
            _execute_ssh_command(
                ssh_client,
                f"tmux send-keys -t {final_session_name} '{export_cmd}' Enter",
            )

            # Step 10: Start codex
            _execute_ssh_command(
                ssh_client, f"tmux send-keys -t {final_session_name} 'codex' Enter"
            )

            # Give codex a moment to start
            time.sleep(2)

            return {
                "devbox_id": devbox_id,
                "tmux_session": final_session_name,
                "ssh_host": ssh_host,
                "ssh_connection": f"{ssh_username}@{ssh_host}",
                "status": "ready",
            }

        finally:
            ssh_client.close()


class AsyncDevboxClient(AsyncMorphLabsApi):
    """Extended async Devbox client with custom convenience methods."""

    @property
    def terminals(self) -> AsyncDevboxTerminals:
        """
        Devbox "terminals" (tmux sessions), async.

        This is a thin convenience wrapper around `self.tmux.*`.
        """

        existing = getattr(self, "_terminals", None)
        if existing is None:
            existing = AsyncDevboxTerminals(self)
            setattr(self, "_terminals", existing)
        return typing.cast(AsyncDevboxTerminals, existing)

    async def start(
        self,
        template_id: str,
        *,
        name: typing.Optional[str] = None,
        metadata: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> DevboxResponse:
        """Async version of `DevboxClient.start`."""

        payload: typing.Dict[str, typing.Any] = {}
        if name:
            payload["name"] = name
        if metadata:
            payload["metadata"] = {k: str(v) for k, v in metadata.items()}
        if "template_id" not in payload.get("metadata", {}):
            payload.setdefault("metadata", {})["template_id"] = str(template_id)

        path = f"api/templates/{_encode_template_id(template_id)}/instant-devbox"
        response = await self._client_wrapper.httpx_client.request(
            path, method="POST", json=payload or None
        )
        if response.status_code >= 400:
            _raise_instant_error(response, context="start request")

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "Instant devbox start did not return JSON payload."
            ) from exc
        return DevboxResponse.model_validate(data)

    async def codex(
        self,
        devbox_id: str,
        openai_secret_name: str,
        tmux_session_name: str = "codex",
        *,
        verify_timeout: int = 30,
    ) -> typing.Dict[str, typing.Any]:
        """
        Async version of codex setup.

        Note: SSH operations are still synchronous as paramiko doesn't have native async support.
        Consider using asyncssh library for fully async implementation.

        See DevboxClient.codex for parameter documentation.
        """

        # Step 1: Get SSH credentials
        try:
            creds = await self.admin.get_devbox_ssh_credentials(devbox_id)
        except Exception as e:
            raise CodexSessionError(f"Failed to get SSH credentials: {e}")

        # Step 2: Construct SSH hostname and username
        ssh_hostname = (
            getattr(self, "ssh_hostname", None)
            or os.environ.get("MORPH_SSH_HOSTNAME")
            or "ssh.cloud.morph.so"
        )
        ssh_host = f"{devbox_id}.{ssh_hostname}"
        ssh_username = creds.access_token
        ssh_port = getattr(self, "ssh_port", None)
        if not isinstance(ssh_port, int):
            try:
                ssh_port = int(os.environ.get("MORPH_SSH_PORT", "22"))
            except Exception:
                ssh_port = 22

        # Step 3: Get OpenAI API key
        try:
            secret_response = await self.user_secrets.get_user_secret(
                openai_secret_name
            )
            openai_api_key = secret_response.value
        except Exception as e:
            raise CodexSessionError(f"Failed to get OpenAI API key: {e}")

        # SSH operations remain synchronous
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh_client.connect(
                hostname=ssh_host,
                port=ssh_port,
                username=ssh_username,
                password=creds.password,
                timeout=verify_timeout,
            )

            _ensure_command_installed(
                ssh_client, "tmux", "apt-get update && apt-get install -y tmux"
            )
            _ensure_command_installed(ssh_client, "codex", "pip install codex-cli")

            # Find an available tmux session name
            final_session_name = _find_available_tmux_session(
                ssh_client, tmux_session_name
            )

            _execute_ssh_command(
                ssh_client, f"tmux new-session -d -s {final_session_name}"
            )

            export_cmd = f"export OPENAI_API_KEY='{openai_api_key}'"
            _execute_ssh_command(
                ssh_client,
                f"tmux send-keys -t {final_session_name} '{export_cmd}' Enter",
            )

            _execute_ssh_command(
                ssh_client, f"tmux send-keys -t {final_session_name} 'codex' Enter"
            )

            time.sleep(2)

            return {
                "devbox_id": devbox_id,
                "tmux_session": final_session_name,
                "ssh_host": ssh_host,
                "ssh_connection": f"{ssh_username}@{ssh_host}",
                "status": "ready",
            }

        finally:
            ssh_client.close()


# Helper functions
def _find_available_tmux_session(
    ssh_client: paramiko.SSHClient,
    base_name: str,
    max_attempts: int = 100,
) -> str:
    """
    Find an available tmux session name.

    If base_name is taken, tries base_name_1, base_name_2, etc.
    """
    # Check if base name is available
    stdin, stdout, stderr = ssh_client.exec_command(
        f"tmux has-session -t {base_name} 2>/dev/null"
    )
    exit_status = stdout.channel.recv_exit_status()

    if exit_status != 0:
        # Session doesn't exist, base name is available
        return base_name

    # Try numbered variants
    for i in range(1, max_attempts + 1):
        candidate_name = f"{base_name}_{i}"
        stdin, stdout, stderr = ssh_client.exec_command(
            f"tmux has-session -t {candidate_name} 2>/dev/null"
        )
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            # Session doesn't exist, this name is available
            return candidate_name

    # If we've exhausted all attempts, raise an error
    raise CodexSessionError(
        f"Could not find an available tmux session name after {max_attempts} attempts"
    )


def _ensure_command_installed(
    ssh_client: paramiko.SSHClient,
    command: str,
    install_cmd: str,
) -> None:
    """Verify command exists, install if not."""
    stdin, stdout, stderr = ssh_client.exec_command(f"which {command}")
    exit_status = stdout.channel.recv_exit_status()

    if exit_status != 0:
        # Command not found, install it
        stdin, stdout, stderr = ssh_client.exec_command(install_cmd)
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            error_output = stderr.read().decode()
            raise CodexSessionError(f"Failed to install {command}: {error_output}")


def _execute_ssh_command(
    ssh_client: paramiko.SSHClient,
    command: str,
) -> str:
    """Execute SSH command and return output."""
    stdin, stdout, stderr = ssh_client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()

    if exit_status != 0:
        error_output = stderr.read().decode()
        raise CodexSessionError(f"Command failed: {command}\nError: {error_output}")

    return stdout.read().decode()


def _encode_template_id(template_id: str) -> str:
    return urllib.parse.quote(str(template_id), safe="")


def _raise_instant_error(response, *, context: str) -> None:
    message = f"Instant devbox {context} failed (status {getattr(response, 'status_code', 'unknown')})"
    detail: typing.Optional[str] = None
    try:
        body = response.json()
    except ValueError:
        detail = getattr(response, "text", None) or None
    else:
        if isinstance(body, dict):
            raw_detail = body.get("detail")
            if isinstance(raw_detail, str):
                detail = raw_detail
            elif isinstance(raw_detail, dict):
                detail = raw_detail.get("message") or raw_detail.get("detail")
            if not detail and isinstance(body.get("message"), str):
                detail = body["message"]
        elif isinstance(body, str):
            detail = body
    raise RuntimeError(f"{message}: {detail or getattr(response, 'text', '')}")
