"""
MPP Archive inspection and compatibility parsing.
"""

from .mpp_archive import MppArchive
from .compatibility import DiscoveredApp, discover_compatible_apps

__all__ = ["MppArchive", "DiscoveredApp", "discover_compatible_apps"]
