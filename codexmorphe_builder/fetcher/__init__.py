"""
Fetcher subsystem for discovering, downloading, and caching .mpp archives.
"""

from .source_model import SourceDescriptor, load_all_sources
from .cache_ledger import CacheLedger
from .release_client import ReleaseClient

__all__ = ["SourceDescriptor", "load_all_sources", "CacheLedger", "ReleaseClient"]
