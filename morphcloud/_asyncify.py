"""
Asyncify - A Python module for transparent synchronous to asynchronous code conversion.

This module provides utilities to convert synchronous code to asynchronous code through
either AST rewriting or thread-based execution. It includes decorators and registration
functions to handle both function and class conversions.

Main components:
- register_async_equivalent: Maps sync functions to their async equivalents
- asyncify_transparent: Marks functions for AST-based rewriting
- asyncify: Main decorator for converting sync to async code
"""

# Standard library imports
import ast
import asyncio
import functools
import glob
import inspect
import json
import os
import shutil
import sqlite3
import subprocess
import textwrap
import time
import urllib.request
from types import FunctionType
from typing import Any, Callable, Dict, Optional

# Third-party imports
import requests

###############################################################################
# GLOBAL SYNC-TO-ASYNC REGISTRY
###############################################################################

# Global registry mapping synchronous functions to their async equivalents
SYNC_TO_ASYNC_MAP: Dict[str, Callable[..., Any]] = {}


def register_async_equivalent(sync_obj: Callable, async_obj: Callable):
    """
    Register a synchronous function and its asynchronous equivalent.

    Args:
        sync_obj: The synchronous function to register
        async_obj: The corresponding asynchronous function
    """
    mod = sync_obj.__module__
    qname = sync_obj.__qualname__
    key = f"{mod}.{qname}"
    SYNC_TO_ASYNC_MAP[key] = async_obj


###############################################################################
# ASYNCIFY_TRANSPARENT DECORATOR
###############################################################################


def asyncify_transparent(func: Callable):
    """
    Mark a function as transparent for AST-based rewriting.

    This decorator marks a function for potential AST rewriting when @asyncify
    is later applied. No async function is created at this stage.

    Args:
        func: The function to mark as transparent

    Returns:
        The original function with _asyncify_transparent attribute set
    """
    setattr(func, "_asyncify_transparent", True)
    return func


###############################################################################
# AST REWRITING LOGIC
###############################################################################

# Global storage for async functions created during rewriting
__ASYNCIFY_GLOBAL_MAP__ = {}


def store_async_callable(async_func: Callable) -> str:
    """Store an async function in the global map and return its identifier."""
    name = f"__asyncify_func_{id(async_func)}"
    __ASYNCIFY_GLOBAL_MAP__[name] = async_func
    return name


def resolve_qualified_name(node: ast.expr, globals_dict: dict) -> Optional[str]:
    """
    Attempt to resolve a fully qualified name for the function call in the AST node.

    Args:
        node: The AST node to analyze
        globals_dict: Global namespace dictionary

    Returns:
        Optional[str]: The fully qualified name if found, None otherwise
    """
    # Build the name parts from the AST node
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.insert(0, current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.insert(0, current.id)
    else:
        return None

    dotted_name = ".".join(parts)

    # Check for direct match in the async map
    if dotted_name in SYNC_TO_ASYNC_MAP:
        return dotted_name

    # Handle single-part names (local/global functions)
    if len(parts) == 1:
        name = parts[0]
        if name in globals_dict:
            obj = globals_dict[name]
            if callable(obj):
                mod = getattr(obj, "__module__", None)
                qn = getattr(obj, "__qualname__", None)
                if mod and qn:
                    full_key = f"{mod}.{qn}"
                    if full_key in SYNC_TO_ASYNC_MAP:
                        return full_key
    return None


class AsyncifyTransformer(ast.NodeTransformer):
    """AST transformer that converts sync function calls to async equivalents."""

    def __init__(self, sync_to_async_map: Dict[str, Callable], globals_dict: dict):
        self.sync_to_async_map = sync_to_async_map
        self.globals_dict = globals_dict
        self.found_async_calls = False
        super().__init__()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Transform function definitions to async if they contain async calls."""
        self.generic_visit(node)
        if self.found_async_calls:
            return ast.AsyncFunctionDef(
                name=node.name,
                args=node.args,
                body=node.body,
                decorator_list=node.decorator_list,
                returns=node.returns,
                type_comment=node.type_comment,
            )
        return node

    def visit_Call(self, node: ast.Call):
        """Transform sync function calls to their async equivalents if available."""
        self.generic_visit(node)
        full_name = resolve_qualified_name(node.func, self.globals_dict)
        if full_name and full_name in self.sync_to_async_map:
            async_func = self.sync_to_async_map[full_name]
            new_name = store_async_callable(async_func)
            new_func = ast.Name(id=new_name, ctx=ast.Load())
            new_call = ast.Await(
                value=ast.Call(func=new_func, args=node.args, keywords=node.keywords)
            )
            self.found_async_calls = True
            return new_call
        return node


def try_ast_rewrite(
    func: Callable, sync_to_async_map: Dict[str, Callable]
) -> Optional[Callable]:
    """
    Attempt to rewrite a function's AST to convert sync calls to async.

    Args:
        func: The function to rewrite
        sync_to_async_map: Map of sync functions to their async equivalents

    Returns:
        Optional[Callable]: The rewritten async function if successful, None otherwise
    """
    try:
        source = inspect.getsource(func)
    except (OSError, TypeError):
        return None

    source = textwrap.dedent(source)
    tree = ast.parse(source)

    transformer = AsyncifyTransformer(sync_to_async_map, func.__globals__)
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)

    if not transformer.found_async_calls:
        return None

    code = compile(new_tree, filename="<asyncify>", mode="exec")
    new_globals = func.__globals__.copy()
    new_globals.update(__ASYNCIFY_GLOBAL_MAP__)
    exec(code, new_globals)

    new_func = new_globals.get(func.__name__, None)
    if new_func and asyncio.iscoroutinefunction(new_func):
        new_func.__name__ = func.__name__
        new_func.__doc__ = func.__doc__
        return new_func
    return None


###############################################################################
# ASYNCIFY DECORATOR
###############################################################################


def asyncify(obj: Any):
    """
    Main decorator for converting sync code to async.

    When applied to a function:
    - Creates async_{fn_name} globally
    - If transparent, attempts AST rewriting
    - Falls back to to_thread if needed

    When applied to a class:
    - Creates new class Async{ClassName}
    - Converts methods to async_{method}
    - Uses AST rewriting or to_thread as appropriate

    Args:
        obj: Function or class to convert

    Returns:
        The original object (function) or new async class

    Raises:
        TypeError: If applied to anything other than a function or class
    """
    if inspect.isclass(obj):
        return _asyncify_class(obj)
    elif isinstance(obj, FunctionType):
        return _asyncify_function(obj)
    else:
        raise TypeError("asyncify can only be applied to functions or classes")


def _asyncify_function(func: Callable):
    """Helper function to asyncify a single function."""
    async_func = None
    if getattr(func, "_asyncify_transparent", False):
        # Try AST rewriting for transparent functions
        async_func = try_ast_rewrite(func, SYNC_TO_ASYNC_MAP)
        if async_func is not None:
            # Register successful rewrite
            register_async_equivalent(func, async_func)
        else:
            # Fallback to to_thread
            @functools.wraps(func)
            async def async_func(*args, **kwargs):
                return await asyncio.to_thread(func, *args, **kwargs)

    else:
        # Not transparent, always use to_thread
        @functools.wraps(func)
        async def async_func(*args, **kwargs):
            return await asyncio.to_thread(func, *args, **kwargs)

    # Register in globals
    async_name = f"async_{func.__name__}"
    globals()[async_name] = async_func
    return func


def _asyncify_class(cls: type):
    """Helper function to asyncify a class."""
    new_attrs = {}
    for name, value in cls.__dict__.items():
        if callable(value) and not (name.startswith("__") and name.endswith("__")):
            if getattr(value, "_asyncify_transparent", False):
                # Try rewriting transparent methods
                maybe_async = try_ast_rewrite(value, SYNC_TO_ASYNC_MAP)
                if maybe_async is not None:
                    async_method = maybe_async
                else:
                    # Fallback to thread
                    @functools.wraps(value)
                    async def async_method(*args, __value=value, **kwargs):
                        return await asyncio.to_thread(__value, *args, **kwargs)

            else:
                # Not transparent, use thread
                @functools.wraps(value)
                async def async_method(*args, __value=value, **kwargs):
                    return await asyncio.to_thread(__value, *args, **kwargs)

            async_name = f"async_{name}"
            new_attrs[async_name] = async_method
        else:
            new_attrs[name] = value

    new_cls_name = f"Async{cls.__name__}"
    new_cls = type(new_cls_name, cls.__bases__, new_attrs)

    # Register in globals
    globals()[new_cls_name] = new_cls
    return new_cls


###############################################################################
# ASYNC EQUIVALENTS REGISTRATION
###############################################################################


# Standard library async equivalents
async def async_requests_get(url, **kwargs):
    """Async equivalent for requests.get using aiohttp."""
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, **kwargs) as response:
            return await response.text()


async def async_open(*args, **kwargs):
    """Async equivalent for open using aiofiles."""
    import aiofiles

    return aiofiles.open(*args, **kwargs)


async def async_subprocess_run(*cmd, **kwargs):
    """Async equivalent for subprocess.run."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **kwargs
    )
    stdout, stderr = await proc.communicate()
    return stdout, stderr, proc.returncode


async def async_urlopen(url, **kwargs):
    """Async equivalent for urllib.request.urlopen using aiohttp."""
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, **kwargs) as response:
            return await response.read()


async def async_sqlite_connect(database, **kwargs):
    """Async equivalent for sqlite3.connect using aiosqlite."""
    import aiosqlite

    return await aiosqlite.connect(database, **kwargs)


async def async_glob(pattern):
    """Async equivalent for glob.glob using to_thread."""
    return await asyncio.to_thread(glob.glob, pattern)


async def async_listdir(path="."):
    """Async equivalent for os.listdir using to_thread."""
    return await asyncio.to_thread(os.listdir, path)


async def async_copyfile(src, dst, *, chunk_size=65536):
    """Async equivalent for shutil.copyfile using aiofiles."""
    import aiofiles

    async with aiofiles.open(src, "rb") as fsrc, aiofiles.open(dst, "wb") as fdst:
        while True:
            chunk = await fsrc.read(chunk_size)
            if not chunk:
                break
            await fdst.write(chunk)
    return None


async def async_json_load(file):
    """Async equivalent for json.load using aiofiles."""
    import aiofiles

    async with aiofiles.open(file, "r") as f:
        content = await f.read()
        return json.loads(content)


async def async_json_dump(obj, file):
    """Async equivalent for json.dump using aiofiles."""
    import aiofiles

    async with aiofiles.open(file, "w") as f:
        await f.write(json.dumps(obj))


# Register all async equivalents
register_async_equivalent(time.sleep, asyncio.sleep)
register_async_equivalent(requests.get, async_requests_get)
register_async_equivalent(open, async_open)
register_async_equivalent(subprocess.run, async_subprocess_run)
register_async_equivalent(urllib.request.urlopen, async_urlopen)
register_async_equivalent(sqlite3.connect, async_sqlite_connect)
register_async_equivalent(glob.glob, async_glob)
register_async_equivalent(os.listdir, async_listdir)
register_async_equivalent(shutil.copyfile, async_copyfile)
register_async_equivalent(json.load, async_json_load)
register_async_equivalent(json.dump, async_json_dump)
