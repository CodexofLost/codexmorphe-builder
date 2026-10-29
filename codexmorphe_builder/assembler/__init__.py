"""
Per-App Bundle Assembly and Manifest Generation Subsystem.
"""

from .d8_merger import merge_dex_files
from .aapt_compiler import compile_resources
from .apk_packager import assemble_bundle_apk
from .manifest_gen import BundleManifestGenerator

__all__ = [
    "merge_dex_files",
    "compile_resources",
    "assemble_bundle_apk",
    "BundleManifestGenerator"
]
