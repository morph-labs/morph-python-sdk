def to_camel_case(snake_str: str) -> str:
    """Convert snake_case to camelCase"""
    components = snake_str.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def to_snake_case(camel_str: str) -> str:
    """Convert camelCase to snake_case"""
    return "".join(["_" + c.lower() if c.isupper() else c for c in camel_str]).lstrip(
        "_"
    )
