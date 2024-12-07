import os
import sys
import json
import logging
import tempfile
import subprocess

from typing import List, Dict, Optional

import paramiko


def setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True,
    )
    # Ensure stdout is unbuffered
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)


class ContainerConfig:
    def __init__(
        self,
        image: str,
        name: str,
        ports: Optional[Dict[int, int]] = None,  # host_port: container_port
        volumes: Optional[Dict[str, str]] = None,  # host_path: container_path
        environment: Optional[Dict[str, str]] = None,
        command: Optional[List[str]] = None,
        working_dir: Optional[str] = None,
    ):
        self.image = image
        self.name = name
        self.ports = ports or {}
        self.volumes = volumes or {}
        self.environment = environment or {}
        self.command = command
        self.working_dir = working_dir


SERVICE_CONTENT_TEMPLATE = """[Unit]
Description={container_name} container service
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/containers/{container_name}
ExecStart=/usr/bin/crun run {container_name}
ExecStop=/usr/bin/crun delete -f {container_name}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/containers/{container_name}.stdout.log
StandardError=append:/var/log/containers/{container_name}.stderr.log

[Install]
WantedBy=multi-user.target
"""


def deploy_container(
    ssh_client: paramiko.SSHClient,
    container_config: ContainerConfig,
    container_cmd='docker',
):
    log = logging.getLogger("DeployContainer")

    try:
        # Stop the service if it exists
        log.info(f"Stopping service {container_config.name} if it exists")
        try:
            execute_remote_command(
                ssh_client, f"systemctl stop {container_config.name}", ignore_errors=True
            )
        except Exception as e:
            log.debug(f"Service {container_config.name} may not exist yet: {e}")

        # Create temporary container
        create_cmd = [container_cmd, "create", "--name", "temp_container"]

        for host_port, container_port in container_config.ports.items():
            create_cmd.extend(["-p", f"{host_port}:{container_port}"])

        for key, value in container_config.environment.items():
            create_cmd.extend(["-e", f"{key}={value}"])

        for host_path, container_path in container_config.volumes.items():
            create_cmd.extend(["-v", f"{host_path}:{container_path}"])

        if container_config.working_dir:
            create_cmd.extend(["-w", container_config.working_dir])

        create_cmd.append(container_config.image)

        if container_config.command:
            create_cmd.extend(container_config.command)

        log.info(f"Creating temporary container with command: {' '.join(create_cmd)}")
        subprocess.run(create_cmd, check=True, capture_output=True, text=True)

        # Get container configuration
        log.info("Getting container configuration")
        container_info = get_container_config(container_cmd, "temp_container")

        # Prepare OCI spec
        oci_spec = prepare_oci_spec(container_info, container_config)

        # Upload OCI spec to remote host
        upload_oci_spec(ssh_client, oci_spec, container_config.name)

        # Export container and stream to remote host
        export_proc = export_container(container_cmd)
        stream_container_export(ssh_client, export_proc, container_config.name)

        # Setup systemd service on remote host
        setup_systemd_service(ssh_client, container_config.name)

        log.info("Container deployed successfully")

    except Exception as e:
        log.error(f"Deployment failed: {e}")
        # Clean up if necessary
        try:
            cleanup_service(ssh_client, container_config.name)
        except Exception as cleanup_error:
            log.error(f"Cleanup after deployment failure also failed: {cleanup_error}")
        raise
    finally:
        remove_temporary_container(container_cmd)


def execute_remote_command(
    ssh_client: paramiko.SSHClient, command: str
) -> str:
    log = logging.getLogger("ExecuteRemoteCommand")
    log.info(f"Executing: {command}")

    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")

    exit_status = stdout.channel.recv_exit_status()

    if exit_status != 0:
        raise Exception(f"Command ({command}) failed (exit code {exit_status}): {error}")

    sys.stdout.write(output)
    sys.stdout.flush()

    return output


def get_container_config(container_cmd: str, container_name: str) -> dict:
    """Extract container configuration from Docker/Podman."""
    inspect_cmd = [container_cmd, "inspect", container_name]
    result = subprocess.run(
        inspect_cmd, capture_output=True, text=True, check=True
    )
    config = json.loads(result.stdout)[0]

    return {
        "Cmd": config.get("Config", {}).get("Cmd"),
        "Entrypoint": config.get("Config", {}).get("Entrypoint"),
        "Env": config.get("Config", {}).get("Env", []),
        "WorkingDir": config.get("Config", {}).get("WorkingDir"),
        "ExposedPorts": config.get("Config", {}).get("ExposedPorts", {}),
    }


def prepare_oci_spec(container_info, container_config: ContainerConfig) -> dict:
    # Merge environment variables
    env_vars = container_info.get("Env", [])
    env_dict = dict(var.split("=", 1) for var in env_vars)

    # Update with environment variables from container_config
    env_dict.update(container_config.environment)

    # Convert back to list format
    env_list = [f"{key}={value}" for key, value in env_dict.items()]

    command = []
    if container_info["Entrypoint"]:
        command.extend(container_info["Entrypoint"])
    if container_info["Cmd"]:
        command.extend(container_info["Cmd"])

    if not command:
        raise Exception("No command specified for container")

    log = logging.getLogger("PrepareOCISpec")
    log.info("Preparing OCI spec")
    oci_spec = {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": command,
            "env": env_list,
            "cwd": container_info["WorkingDir"] or "/",
            "capabilities": {
                "bounding": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE",
                ],
                "effective": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE",
                ],
                "permitted": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE",
                ],
                "ambient": [
                    "CAP_AUDIT_WRITE",
                    "CAP_KILL",
                    "CAP_NET_BIND_SERVICE",
                ],
            },
            "noNewPrivileges": True,
        },
        "root": {
            "path": "rootfs",
            "readonly": False,
        },
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
            },
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": [
                    "nosuid",
                    "noexec",
                    "newinstance",
                    "ptmxmode=0666",
                    "mode=0620",
                    "gid=5",
                ],
            },
            {
                "destination": "/dev/shm",
                "type": "tmpfs",
                "source": "shm",
                "options": [
                    "nosuid",
                    "noexec",
                    "nodev",
                    "mode=1777",
                    "size=65536k",
                ],
            },
            {
                "destination": "/dev/mqueue",
                "type": "mqueue",
                "source": "mqueue",
                "options": ["nosuid", "noexec", "nodev"],
            },
            {"destination": "/sys", "type": "sysfs", "source": "sysfs"},
            {
                "destination": "/sys/fs/cgroup",
                "type": "cgroup",
                "source": "cgroup",
                "options": ["nosuid", "noexec", "nodev", "relatime", "ro"],
            },
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ]
        },
    }
    return oci_spec


# def prepare_oci_spec(container_info, container_config: ContainerConfig) -> dict:
#     log = logging.getLogger("PrepareOCISpec")
#     log.info("Preparing OCI spec")
#
#     config = container_info.get("Config", {})
#     host_config = container_info.get("HostConfig", {})
#
#     # Merge environment variables
#     env_vars = config.get("Env", [])
#     env_dict = dict(var.split("=", 1) for var in env_vars)
#
#     # Update with environment variables from container_config
#     env_dict.update(container_config.environment)
#
#     # Convert back to list format
#     env_list = [f"{key}={value}" for key, value in env_dict.items()]
#
#     # Command to execute
#     if container_config.command:
#         command = container_config.command
#     else:
#         command = config.get("Entrypoint") or []
#         command += config.get("Cmd") or []
#
#     if not command:
#         raise Exception("No command specified for container")
#
#     # Get user
#     user = container_config.environment.get("USER") or config.get("User", "")
#     if user:
#         if ":" in user:
#             uid, gid = user.split(":")
#         else:
#             uid, gid = user, '0'
#     else:
#         uid, gid = '0', '0'
#
#     # Prepare capabilities (include all for less restriction)
#     all_capabilities = [
#         "CAP_AUDIT_CONTROL", "CAP_AUDIT_READ", "CAP_AUDIT_WRITE", "CAP_BLOCK_SUSPEND",
#         "CAP_BPF", "CAP_CHECKPOINT_RESTORE", "CAP_CHOWN", "CAP_DAC_OVERRIDE",
#         "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_IPC_LOCK",
#         "CAP_IPC_OWNER", "CAP_KILL", "CAP_LEASE", "CAP_LINUX_IMMUTABLE",
#         "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_MKNOD", "CAP_NET_ADMIN",
#         "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_PERFMON",
#         "CAP_SETGID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_ADMIN",
#         "CAP_SYS_BOOT", "CAP_SYS_CHROOT", "CAP_SYS_MODULE", "CAP_SYS_NICE",
#         "CAP_SYS_PACCT", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_SYS_RESOURCE",
#         "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_SYSLOG", "CAP_WAKE_ALARM"
#     ]
#
#     # Prepare namespaces (include network namespace for isolation)
#     namespaces = [
#         {"type": "pid"},
#         {"type": "ipc"},
#         {"type": "uts"},
#         {"type": "mount"},
#         {"type": "network"},
#     ]
#
#     # Prepare mounts
#     mounts = [
#         {"destination": "/proc", "type": "proc", "source": "proc"},
#         {
#             "destination": "/dev",
#             "type": "tmpfs",
#             "source": "tmpfs",
#             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
#         },
#         {
#             "destination": "/dev/pts",
#             "type": "devpts",
#             "source": "devpts",
#             "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"],
#         },
#         {
#             "destination": "/dev/shm",
#             "type": "tmpfs",
#             "source": "shm",
#             "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
#         },
#         {
#             "destination": "/dev/mqueue",
#             "type": "mqueue",
#             "source": "mqueue",
#             "options": ["nosuid", "noexec", "nodev"],
#         },
#         {"destination": "/sys", "type": "sysfs", "source": "sysfs"},
#         {
#             "destination": "/sys/fs/cgroup",
#             "type": "cgroup",
#             "source": "cgroup",
#             "options": ["nosuid", "noexec", "nodev", "relatime", "ro"],
#         },
#     ]
#
#     # Include volume mounts from container_config
#     for host_path, container_path in container_config.volumes.items():
#         mounts.append({
#             "destination": container_path,
#             "type": "bind",
#             "source": host_path,
#             "options": ["rbind", "rw"]
#         })
#
#     # Include volumes from the original container spec
#     volumes = config.get("Volumes", {})
#     for container_path in volumes.keys():
#         # Mount as tmpfs to avoid conflicts
#         mounts.append({
#             "destination": container_path,
#             "type": "tmpfs",
#             "source": "tmpfs",
#             "options": ["rw", "nosuid", "nodev", "noexec", "relatime", "size=65536k"]
#         })
#
#     # Prepare OCI spec
#     oci_spec = {
#         "ociVersion": "1.0.0",
#         "process": {
#             "terminal": False,
#             "user": {"uid": int(uid), "gid": int(gid)},
#             "args": command,
#             "env": env_list,
#             "cwd": container_config.working_dir or config.get("WorkingDir") or "/",
#             "capabilities": {
#                 "bounding": all_capabilities,
#                 "effective": all_capabilities,
#                 "permitted": all_capabilities,
#                 "inheritable": all_capabilities,
#                 "ambient": all_capabilities,
#             },
#             "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1048576, "soft": 1048576}],
#             "noNewPrivileges": False,
#         },
#         "root": {"path": "rootfs", "readonly": False},
#         "mounts": mounts,
#         "linux": {
#             "namespaces": namespaces,
#             "maskedPaths": [],
#             "readonlyPaths": [],
#         },
#     }
#
#     return oci_spec
#

def upload_oci_spec(ssh_client: paramiko.SSHClient, oci_spec: dict, container_name: str):
    container_path = f"/root/containers/{container_name}"
    log = logging.getLogger("UploadOCISpec")
    log.info(f"Uploading OCI spec to {container_path}")

    execute_remote_command(
        ssh_client, f"rm -rf {container_path} && mkdir -p {container_path}"
    )

    with ssh_client.open_sftp() as sftp, tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        json.dump(oci_spec, tmp, indent=2)
        tmp.flush()
        remote_path = f"{container_path}/config.json"
        sftp.put(tmp.name, remote_path)
        log.info(f"Uploaded OCI spec to {remote_path}")
    os.remove(tmp.name)  # Clean up the temporary file


def export_container(container_cmd: str) -> subprocess.Popen:
    log = logging.getLogger("ExportContainer")
    log.info("Starting container export")
    export_proc = subprocess.Popen(
        [container_cmd, "export", "temp_container"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    return export_proc


def stream_container_export(
    ssh_client: paramiko.SSHClient, export_proc: subprocess.Popen, container_name: str
):
    container_path = f"/root/containers/{container_name}"
    rootfs_path = f"{container_path}/rootfs"

    log = logging.getLogger("StreamContainerExport")
    log.info("Starting remote tar extraction")
    execute_remote_command(ssh_client, f"mkdir -p {rootfs_path}")

    channel = ssh_client.get_transport().open_session()
    channel.exec_command(f"cd {rootfs_path} && tar -xf -")

    log.info("Streaming container data")
    try:
        while True:
            data = export_proc.stdout.read(4096)
            if not data:
                break
            channel.sendall(data)
        export_proc.wait()
        error = export_proc.stderr.read().decode()
        if export_proc.returncode != 0:
            raise Exception(f"Container export failed: {error}")
    except Exception as e:
        log.error(f"Error during data transfer: {e}")
        raise

    log.info("Finalizing data transfer")
    channel.shutdown_write()

    exit_status = channel.recv_exit_status()
    if exit_status != 0:
        error = channel.recv_stderr(4096).decode()
        raise Exception(
            f"Failed to extract container (exit status {exit_status}): {error}"
        )

    log.info("Finished streaming container data")


def setup_systemd_service(ssh_client: paramiko.SSHClient, container_name: str):
    log = logging.getLogger("SystemdServiceManager")
    try:
        log.info("Creating logs directory")
        execute_remote_command(ssh_client, "mkdir -p /var/log/containers")

        service_file = f"/etc/systemd/system/{container_name}.service"
        log.info(f"Creating systemd service file: {service_file}")
        service_content = SERVICE_CONTENT_TEMPLATE.format(
            container_name=container_name
        )
        cmd = f'cat > {service_file} << "EOF"\n{service_content}EOF'
        execute_remote_command(ssh_client, cmd)

        execute_remote_command(ssh_client, f"chmod 644 {service_file}")

        log.info("Reloading systemd daemon")
        execute_remote_command(ssh_client, "systemctl daemon-reload")

        log.info(f"Enabling {container_name} service")
        execute_remote_command(ssh_client, f"systemctl enable {container_name}")

        log.info(f"Starting {container_name} service")
        execute_remote_command(ssh_client, f"systemctl start {container_name}")

        log.info("Waiting for service to become active...")
        execute_remote_command(
            ssh_client, f"systemctl is-active --wait {container_name}"
        )

        # log.info("Service status:")
        # execute_remote_command(ssh_client, f"systemctl status {container_name}")

    except Exception as e:
        log.error(f"Failed to setup systemd service: {e}")
        raise


def cleanup_service(ssh_client: paramiko.SSHClient, container_name: str):
    log = logging.getLogger("CleanupService")
    try:
        log.info(f"Stopping service {container_name}")
        execute_remote_command(ssh_client, f"systemctl stop {container_name}")

        log.info(f"Disabling service {container_name}")
        execute_remote_command(ssh_client, f"systemctl disable {container_name}")

        log.info(f"Removing service file")
        execute_remote_command(
            ssh_client, f"rm -f /etc/systemd/system/{container_name}.service"
        )

        log.info("Reloading systemd daemon")
        execute_remote_command(ssh_client, "systemctl daemon-reload")

        log.info("Cleaning up container directory")
        execute_remote_command(
            ssh_client, f"rm -rf /root/containers/{container_name}"
        )

        log.info("Cleaning up log files")
        execute_remote_command(
            ssh_client, f"rm -f /var/log/containers/{container_name}.*"
        )

    except Exception as e:
        log.error(f"Error during service cleanup: {e}")
        raise


def remove_temporary_container(container_cmd: str):
    log = logging.getLogger("RemoveTemporaryContainer")
    try:
        subprocess.run([container_cmd, "rm", "temp_container"], check=True, capture_output=True, text=True)
        log.info("Removed temporary container")
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to remove temporary container: {e}")

from .api import Instance

def get_ssh_client_for_instance(instance: Instance) -> paramiko.SSHClient:
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        "localhost",
        port=2222,
        username=instance.id + ":" + os.environ.get("MORPH_API_KEY", ""),
    )
    return ssh_client

def deploy_container_to_instance(
    instance: Instance,
    image: str,
    ports: Optional[Dict[int, int]] = None,
    environment: Optional[Dict[str, str]] = None,
    command: Optional[List[str]] = None,
):
    log = logging.getLogger("DeployContainerToInstance")
    ssh_client = get_ssh_client_for_instance(instance)

    try:
        config = ContainerConfig(
            image=image,
            name="app",
            ports=ports,
            environment=environment,
            command=command,
        )

        deploy_container(ssh_client, config)

    except Exception as e:
        log.error(f"Deployment failed: {e}")
        raise
    finally:
        ssh_client.close()


def main():
    setup_logging(True)
    log = logging.getLogger("Main")
    remote_host = "localhost"
    remote_user = "morphvm_yqcsj5kd:" + os.environ.get("MORPH_API_KEY", "")
    remote_port = 2222
    container_cmd = "docker"

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log.info(f"Connecting to {remote_host}:{remote_port}")
        ssh_client.connect(
            remote_host, port=remote_port, username=remote_user
        )

        config = ContainerConfig(
            image="python:3.11-slim",
            name="python-app",
            ports={8080: 8080},
            environment={
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHONPATH": "/usr/local/lib/python3.11/site-packages:/usr/local/lib/python3.11",
            },
            command=["python3.11", "-m", "http.server", "--bind", "0.0.0.0", "8080"],
        )

        deploy_container(ssh_client, config, container_cmd=container_cmd)

    except Exception as e:
        log.error(f"Deployment failed: {e}")
        sys.exit(1)
    finally:
        ssh_client.close()

if __name__ == "__main__":
    main()
