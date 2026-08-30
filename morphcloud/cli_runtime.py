"""Morph CLI application context and third-party extension policy."""
from __future__ import annotations
import importlib.metadata
import sys
import click
from pydantic import BaseModel

class MorphRuntimeContext(dict[str, object], object):
    """Values shared by generated commands and first-party CLI extensions."""

    def __init__(self, *, json_output: bool=False, profile: str | None=None) -> None:
        super().__init__(profile=profile)
        self.json_output = json_output
        self.profile = profile

    def resolve(self, resource_type: type[BaseModel], token: str) -> BaseModel:
        client = self.client
        resource_name = resource_type.__name__.lower()
        api = getattr(client, f'{resource_name}s', None)
        if api is None or not hasattr(api, 'get'):
            raise click.ClickException(f'{resource_type.__name__} does not support identity lookup')
        return api.get(token)

    @property
    def client(self):
        public_cli = sys.modules.get(f'{__package__}.cli')
        public_factory = getattr(public_cli, 'get_client', None)
        if callable(public_factory):
            return public_factory()
        from .cli_helpers import get_client
        return get_client(self.profile)

def load_cli_plugins(app: click.Group) -> None:
    """Load independently distributed CLI extensions from public entry points."""
    callback_module_name = getattr(app.callback, '__module__', None)
    callback_module = sys.modules.get(callback_module_name)
    if callback_module is not None and callback_module.__name__.endswith('.cli'):
        from ._utils import Spinner
        from .cli_helpers import get_client
        callback_module.get_client = get_client
        callback_module.Spinner = Spinner
        callback_module.load_cli_plugins = load_cli_plugins
    try:
        plugin_entry_points = importlib.metadata.entry_points(group='morphcloud.cli_plugins')
    except Exception:
        return
    for entry_point in plugin_entry_points:
        try:
            plugin_loader = entry_point.load()
            plugin_loader(app)
        except Exception:
            continue
