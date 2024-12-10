from typing import Any


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
