"""Ontology declarations for Morph Volumes CLI workflows."""
from __future__ import annotations
from typing import Annotated, Any
from .volumes import cli as implementation
from .volumes.client import VolumeBucket

def _call(command: Any, **values: Any) -> None:
    command.callback(**values)

def list_volumes(target: str | None=None, recursive: bool=False, json_mode: bool=False) -> None:
    """List buckets, prefixes, or objects."""
    _call(implementation.list_volumes, target=target, recursive=recursive, json_mode=json_mode)

def tree_volumes(target: str | None=None, json_mode: bool=False) -> None:
    """Render a file-explorer style tree for a bucket or prefix."""
    _call(implementation.tree_volumes, target=target, json_mode=json_mode)

def make_bucket(bucket: str) -> None:
    """Create a bucket."""
    _call(implementation.make_bucket, bucket=bucket)

def remove_bucket(bucket: str) -> None:
    """Remove an empty bucket."""
    _call(implementation.remove_bucket, bucket=bucket)

def cat_volume_object(target: str) -> None:
    """Print an object's contents to stdout."""
    _call(implementation.cat_volume_object, target=target)

def copy_volume_objects(source: str, destination: str, recursive: bool=False) -> None:
    """Copy between local paths and volumes."""
    _call(implementation.copy_objects, source=source, destination=destination, recursive=recursive)

def remove_volume_objects(target: str, recursive: bool=False, yes: bool=False) -> None:
    """Delete an object or a prefix worth of objects."""
    _call(implementation.remove_objects, target=target, recursive=recursive, yes=yes)
