"""
Redundancy and compatibility filtering for root and LSPosed environments.
"""

from .root_filter import is_patch_redundant, filter_redundant_patches

__all__ = ["is_patch_redundant", "filter_redundant_patches"]
