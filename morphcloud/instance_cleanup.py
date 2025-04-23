#!/usr/bin/env python3

import os
import sys
import typing
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
# List of HTTP service names. Instances exposing ANY of these services will NOT be stopped.
# Modify this list according to your needs.
KEEP_ALIVE_SERVICE_NAMES: typing.List[str] = [
    "slackbot-webhook",
    "listener",
    "grafana-proxy",
]

# Maximum number of concurrent stop operations
MAX_WORKERS = 10
# --- End Configuration ---

try:
    from rich.console import Console

    from morphcloud.api import (ApiError, Instance, InstanceStatus,
                                MorphCloudClient)
except ImportError:
    print(
        "Error: Could not import MorphCloud modules. "
        "Make sure 'morphcloud-sdk' is installed (`pip install morphcloud-sdk`) "
        "and the library is in your Python path.",
        file=sys.stderr,
    )
    sys.exit(1)

# Initialize console for rich output
console = Console()


def stop_instance_worker(
    instance: Instance,
) -> typing.Tuple[str, bool, typing.Optional[str]]:
    """
    Worker function to stop a single instance.
    Designed to be run in a ThreadPoolExecutor.

    Args:
        instance: The MorphCloud Instance object to stop.

    Returns:
        A tuple containing: (instance_id, success_flag, error_message_or_None)
    """
    instance_id = instance.id
    try:
        console.print(
            f"[yellow]Attempting to stop instance {instance_id}"
            f" (Current status: {instance.status.value})..."
        )
        # Ensure we don't try to stop an already stopped/stopping instance if needed
        # The API might handle this, but an explicit check can be clearer.
        # Refreshing status just before stop isn't strictly necessary but can avoid
        # unnecessary API calls if status changed recently.
        # instance._refresh() # Optional: uncomment if needed, adds latency
        if instance.status not in [
            InstanceStatus.READY,
        ]:
            console.print(
                f"[cyan]Skipping stop for instance {instance_id}: Status is '{instance.status.value}', "
                f"not suitable for stopping."
            )
            # Consider this a "success" in the context of the script's goal (not stopping it)
            # Or change to False if you only want successful *API calls* counted.
            return instance_id, True, "Instance not in a stoppable state."

        instance.stop()  # This is the actual API call
        console.print(f"[green]Successfully stopped instance {instance_id}[/green]")
        return instance_id, True, None
    except ApiError as e:
        console.print(
            f"[bold red]API Error stopping instance {instance_id}:[/bold red] "
            f"Status {e.status_code} - {e.response_body}",
            style="error",
        )
        return instance_id, False, f"API Error: {e.status_code}"
    except Exception as e:
        console.print(
            f"[bold red]Unexpected Error stopping instance {instance_id}:[/bold red] {e}",
            style="error",
        )
        return instance_id, False, f"Unexpected Error: {str(e)}"


def main():
    """
    Main function to list instances, filter them based on exposed services,
    and stop the appropriate ones concurrently.
    """
    console.print("[bold blue]Starting MorphCloud Instance Cleanup Script[/bold blue]")

    # --- Get API Key and Initialize Client ---
    api_key = os.environ.get("MORPH_API_KEY")
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] MORPH_API_KEY environment variable not set.",
            style="error",
        )
        sys.exit(1)

    try:
        client = MorphCloudClient(api_key=api_key)
        console.print("MorphCloud client initialized.")
    except Exception as e:
        console.print(
            f"[bold red]Error initializing MorphCloud client:[/bold red] {e}",
            style="error",
        )
        sys.exit(1)

    # --- List All Instances ---
    try:
        console.print("Fetching list of all instances...")
        all_instances = client.instances.list()
        console.print(f"Found {len(all_instances)} total instances.")
        if not all_instances:
            console.print("[green]No instances found. Exiting.[/green]")
            sys.exit(0)
    except ApiError as e:
        console.print(
            f"[bold red]API Error listing instances:[/bold red] "
            f"Status {e.status_code} - {e.response_body}",
            style="error",
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            f"[bold red]Error listing instances:[/bold red] {e}", style="error"
        )
        sys.exit(1)

    # --- Filter Instances ---
    instances_to_stop: typing.List[Instance] = []
    instances_to_keep: typing.List[Instance] = []

    console.print(
        f"\nFiltering instances. Keeping instances exposing any of these services: "
        f"[cyan]{', '.join(KEEP_ALIVE_SERVICE_NAMES) or 'None specified'}[/cyan]"
    )

    for instance in all_instances:
        keep_this_instance = False
        # Check only instances that are potentially running
        if instance.status in [
            InstanceStatus.READY,
            InstanceStatus.PAUSED,
            InstanceStatus.PENDING,
        ]:
            # Get names of services exposed by *this* instance
            exposed_service_names = {
                service.name for service in instance.networking.http_services
            }

            # Check if any of the instance's exposed services are in our keep-alive list
            if any(name in KEEP_ALIVE_SERVICE_NAMES for name in exposed_service_names):
                keep_this_instance = True
                instances_to_keep.append(instance)
                console.print(
                    f"  - [green]Keeping instance {instance.id}[/green]: Exposes services "
                    f"({', '.join(exposed_service_names.intersection(KEEP_ALIVE_SERVICE_NAMES))})"
                )
            else:
                # Only mark for stopping if it's in a stoppable state and doesn't match keep criteria
                instances_to_stop.append(instance)
                console.print(
                    f"  - [yellow]Marking instance {instance.id} for stopping[/yellow]: No matching services exposed."
                    f" (Exposed: {', '.join(exposed_service_names) or 'None'})"
                )
        else:
            console.print(
                f"  - [dim]Ignoring instance {instance.id}: Not in a running/stoppable state ({instance.status.value})[/dim]"
            )

    if not instances_to_stop:
        console.print("\n[green]No instances marked for stopping.[/green]")
        sys.exit(0)

    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  - Instances to keep: {len(instances_to_keep)}")
    console.print(f"  - Instances to stop: {len(instances_to_stop)}")

    input("Press any key to continue")

    # --- Stop Instances Concurrently ---
    console.print(
        f"\nStarting concurrent stop operation (max_workers={MAX_WORKERS})..."
    )
    stopped_successfully = 0
    stopped_failed = 0
    stop_results: typing.List[typing.Tuple[str, bool, typing.Optional[str]]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Create a dictionary mapping futures to instance IDs for easier tracking
        future_to_instance = {
            executor.submit(stop_instance_worker, instance): instance.id
            for instance in instances_to_stop
        }

        # Process futures as they complete
        for future in as_completed(future_to_instance):
            instance_id = future_to_instance[future]
            try:
                result = (
                    future.result()
                )  # Get the tuple (instance_id, success, error_msg)
                stop_results.append(result)
                if result[1]:  # Check the success flag
                    stopped_successfully += 1
                else:
                    stopped_failed += 1
            except Exception as exc:
                # This catches errors *within* the future execution itself,
                # though stop_instance_worker should ideally catch most things.
                console.print(
                    f"[bold red]Critical Error processing stop for instance {instance_id}:[/bold red] {exc}",
                    style="error",
                )
                stop_results.append(
                    (instance_id, False, f"Future Execution Error: {str(exc)}")
                )
                stopped_failed += 1

    # --- Final Report ---
    console.print("\n[bold blue]Cleanup Operation Complete[/bold blue]")
    console.print(f"  - Successfully stopped: {stopped_successfully}")
    console.print(f"  - Failed to stop: {stopped_failed}")

    if stopped_failed > 0:
        console.print("\n[bold red]Failures occurred:[/bold red]")
        for res_id, res_success, res_error in stop_results:
            if not res_success:
                console.print(
                    f"  - Instance {res_id}: {res_error or 'Unknown failure'}"
                )
        sys.exit(1)  # Exit with error code if failures occurred
    else:
        console.print(
            "[bold green]All targeted instances stopped successfully (or were skipped appropriately).[/bold green]"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
