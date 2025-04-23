import shlex

import fire

from morphcloud.api import \
    Snapshot  # Make sure this import matches your project structure
from morphcloud.computer import Computer


def escape_single_quotes(s: str) -> str:
    """
    Escapes single quotes within a string so it can be safely embedded
    within a single-quoted shell command string (like for 'su -c').
    Replaces ' with '\''
    """
    return s.replace("'", "'\\''")


def exec_as_user(snapshot: Snapshot, username: str, command: str, **kwargs) -> Snapshot:
    """
    Executes a command within the snapshot as a specified user using 'su'.

    This function wraps the provided command in `su - <username> -c '<command>'`.
    It handles basic escaping for single quotes within the command string.

    Args:
        snapshot: The MorphCloud Snapshot object to operate on.
        username: The username within the snapshot to execute the command as.
                   This user must exist in the snapshot.
        command: The command string to execute as the specified user.
                 Complex commands with heavy shell metacharacters might require
                 careful quoting by the caller *before* passing to this function.
        **kwargs: Additional keyword arguments to pass directly to the underlying
                  snapshot.exec() method (e.g., env, cwd). Note that `su -`
                  typically changes the environment and working directory.

    Returns:
        A new Snapshot object representing the state after the command execution.

    Raises:
        Will propagate exceptions from snapshot.exec() if the command fails
        (e.g., user doesn't exist, command returns non-zero exit code).
    """
    if not isinstance(command, str):
        raise TypeError("The 'command' argument must be a single string.")

    # Escape single quotes within the command string to safely embed it
    # within the single quotes required by `su -c '...'`
    escaped_command = escape_single_quotes(command)

    # Construct the full command to be run by the default (likely root) user
    # `su - <user>` attempts to start a login shell (sets environment, HOME, cwd)
    # `-c '<cmd>'` executes the command within that user's shell
    full_su_command = f"su - {username} -c '{escaped_command}'"

    print(f"INFO: Executing as user '{username}': {command}")
    # print(f"DEBUG: Full su command: {full_su_command}") # Optional debug logging

    # Call the original exec method with the constructed 'su' command
    # Pass through any extra keyword arguments
    new_snapshot = snapshot.exec(full_su_command, **kwargs)

    return new_snapshot


def _main():
    # create an ephemeral computer that is destroyed after
    # the context manager exits
    print("starting the computer")
    with Computer.new() as computer:
        print("started the computer")
        base_snapshot = computer._instance.snapshot()
        print("snapshotted the computer")

    snapshot = base_snapshot.exec_as_user(
        "echo 'blah blah blah install whatever u need here'"
    ).upload("demo_fnf.py", "/root/demo_fnf.py")
    # base_snapshot.upload("my_python_file_2.py", "/root/my_python_file_2.py")

    from morphcloud.api import MorphCloudClient

    client = MorphCloudClient()

    with client.instances.start(snapshot.id) as vm:
        print(f"{vm.networking.http_services=}")
        breakpoint()


if __name__ == "__main__":
    fire.Fire(_main)
