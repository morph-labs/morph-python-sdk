"""
Copyright (c) 2024 Morph Labs. All rights reserved.
Released under the license as described in the file LICENSE.
"""

import importlib.metadata

try:
    __version__ = importlib.metadata.version("morphcloud")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0-dev"
__all__ = []
