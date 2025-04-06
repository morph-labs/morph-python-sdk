import threading
import time
from typing import Any

import click


def to_camel_case(snake_str: str) -> str:
    """Convert snake_case to camelCase"""
    components = snake_str.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def to_snake_case(camel_str: str) -> str:
    """Convert camelCase to snake_case"""
    return "".join(["_" + c.lower() if c.isupper() else c for c in camel_str]).lstrip(
        "_"
    )


def is_jupyter_notebook() -> bool:
    """
    Detect whether we're in a Jupyter notebook environment.
    """
    try:
        shell = get_ipython().__class__.__name__
        if shell == "ZMQInteractiveShell":
            return True  # Jupyter notebook or qtconsole
        elif shell == "TerminalInteractiveShell":
            return False  # Terminal running IPython
        else:
            return False  # Other type (?)
    except NameError:
        return False  # Probably standard Python interpreter


def get_iframe_object_from_instance_id(
    base_url: str, instance_id: str, width: int = 1280 // 2, height=720 // 2
) -> Any:
    """
    Get the iframe object from the instance id.
    """
    from IPython.display import IFrame

    # Display the iframe
    return IFrame(
        src=f"{base_url}/static/vnc_lite.html?path=instance%2F{instance_id}%2Fvnc&scale=scale",
        width=width,
        height=height,
    )


# ─────────────────────────────────────────────────────────────
#  Spinner Definition
# ─────────────────────────────────────────────────────────────
import click


class Spinner:
    """A context manager that shows an animated spinner with a status message."""

    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, text, success_text=None, success_emoji="✅", color="green"):
        self.text = text
        self.success_text = success_text
        self.success_emoji = success_emoji
        self.color = color
        self.stop_event = threading.Event()
        self.thread = None

    def _spinner_task(self):
        frame_index = 0
        while not self.stop_event.is_set():
            frame = self.SPINNER_FRAMES[frame_index % len(self.SPINNER_FRAMES)]
            click.echo(f"\r{frame} {self.text}", nl=False)
            time.sleep(0.1)
            frame_index += 1

        # Once stopping, overwrite the spinner line with spaces, then carriage-return
        clear_line = "\r" + " " * (len(self.text) + 4) + "\r"
        click.echo(clear_line, nl=False)

    def __enter__(self):
        self.thread = threading.Thread(target=self._spinner_task, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_event.set()
        self.thread.join()
        if exc_type is None and self.success_text:
            # Ensure there's a space between emoji and text:
            click.secho(f"{self.success_emoji}  {self.success_text}", fg=self.color)
        elif exc_type is not None:
            # On error, you can also add a space if needed:
            click.secho("❌ Operation failed!", fg="red")
        # Let exceptions pass through
        return False


try:
    from enum import StrEnum
except ImportError:
    from enum import Enum

    class StrEnum(str, Enum):
        """String enumeration with nicer repr and comparison behavior."""

        def __repr__(self):
            return self.value

        def __str__(self):
            return self.value
