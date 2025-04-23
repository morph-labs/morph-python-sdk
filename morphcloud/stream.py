def run_in_background_with_streaming(instance, command):
    """
    Execute a command over SSH with real-time output streaming

    Parameters:
    - instance: Instance object that provides an ssh() method
    - command: str, the command to execute

    Returns:
    - dict with keys: exit_code, stdout, stderr
    """
    # ANSI color codes for output formatting
    COLORS = {
        "TEXT": "\033[39m",
        "HIGHLIGHT": "\033[31m",
        "OUTPUT_HEADER": "\033[34m",
        "SUCCESS": "\033[32m",
        "ERROR": "\033[31m",
        "RESET": "\033[0m",
        "SECONDARY": "\033[90m",
    }

    print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")
    print(f"\n{COLORS['OUTPUT_HEADER']}Output:{COLORS['RESET']}")

    last_stdout = ""
    last_stderr = ""

    # Run the command in background to get real-time output
    with instance.ssh() as ssh:
        with ssh.run(command, background=True, get_pty=True) as process:
            while True:
                # Print stdout in real-time
                current_stdout = process.stdout
                if current_stdout != last_stdout:
                    new_output = current_stdout[len(last_stdout) :]
                    print(
                        f"{COLORS['TEXT']}{new_output}{COLORS['RESET']}",
                        end="",
                        flush=True,
                    )
                    last_stdout = current_stdout

                # Print stderr in real-time
                current_stderr = process.stderr
                if current_stderr != last_stderr:
                    new_stderr = current_stderr[len(last_stderr) :]
                    print(
                        f"{COLORS['HIGHLIGHT']}[stderr] {new_stderr}{COLORS['RESET']}",
                        end="",
                        flush=True,
                    )
                    last_stderr = current_stderr

                # Check if process is done
                if process.completed:
                    break

                import time

                time.sleep(0.01)

            # Get final output from the process
            final_stdout = process.stdout
            final_stderr = process.stderr

            # Get returncode from the channel
            returncode = process.channel.recv_exit_status()

            # Print status
            status_color = COLORS["SUCCESS"] if returncode == 0 else COLORS["ERROR"]

            print(f"\n{COLORS['OUTPUT_HEADER']}Status:{COLORS['RESET']}")
            print(
                f"{status_color}{'✓ Command succeeded' if returncode == 0 else '✗ Command failed'} (exit code: {returncode}){COLORS['RESET']}"
            )
            if final_stderr:
                print(
                    f"{COLORS['ERROR']}Command produced error output - see [stderr] messages above{COLORS['RESET']}"
                )
            print(f"\n{COLORS['SECONDARY']}{'─' * 50}{COLORS['RESET']}")

            # Reset terminal settings
            print(
                "\033[?25h"  # Show cursor
                "\033[?7h"  # Enable line wrapping
                "\033[?47l"  # Restore screen
                "\033[!p"  # Soft reset
                "\033[?1l"  # Reset cursor keys to default
                "\033[?12l"  # Stop blinking cursor
                "\033[?25h",  # Ensure cursor is visible
                end="",
                flush=True,
            )

            return {
                "exit_code": returncode,
                "stdout": final_stdout,
                "stderr": final_stderr,
            }


if __name__ == "__main__":
    from morphcloud.api import MorphCloudClient

    client = MorphCloudClient()
    vm = client.instances.get("morphvm_ik0wc38u")  # replace with your VM ID
    print(run_in_background_with_streaming(vm, "apt update"))
