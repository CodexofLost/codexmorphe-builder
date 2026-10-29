import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..config import RELEASE_REPO, RELEASE_TAG
from .apk_packager import compute_sha256


@dataclass
class PatchCatalogItem:
    id: str
    name: str
    description: str
    default: bool
    key: str


@dataclass
class ProviderBundleInfo:
    source_id: str
    author: str
    version: str
    bundle_file: str
    download_url: str
    description: str
    sha256: str
    size_bytes: int
    patches: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AppCatalogEntry:
    package_name: str
    app_name: str
    default_provider: str
    providers: Dict[str, ProviderBundleInfo] = field(default_factory=dict)


class BundleManifestGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.catalog: Dict[str, AppCatalogEntry] = {}

    def load_existing(self, filename: str = "bundle-manifest.json") -> None:
        """
        Load an existing manifest from disk so incremental builds can preserve unchanged providers.
        """
        manifest_path = self.output_dir / filename
        if not manifest_path.exists():
            return
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for pkg, app_data in data.get("apps", {}).items():
                    entry = AppCatalogEntry(
                        package_name=pkg,
                        app_name=app_data.get("app_name", pkg),
                        default_provider=app_data.get("default_provider", "")
                    )
                    for src_id, prov_data in app_data.get("providers", {}).items():
                        entry.providers[src_id] = ProviderBundleInfo(**prov_data)
                    self.catalog[pkg] = entry
        except Exception as e:
            print(f"[WARN] Failed to load existing manifest: {e}")

    def register_bundle(
        self,
        package_name: str,
        app_name: str,
        source_id: str,
        author: str,
        version: str,
        bundle_file: Path,
        description: str,
        patches: List[Dict[str, Any]],
        download_url: str = "",
        is_default: bool = False
    ) -> None:
        sha256 = compute_sha256(bundle_file)
        size_bytes = bundle_file.stat().st_size

        if package_name not in self.catalog:
            self.catalog[package_name] = AppCatalogEntry(
                package_name=package_name,
                app_name=app_name,
                default_provider=source_id
            )

        if is_default or not self.catalog[package_name].default_provider:
            self.catalog[package_name].default_provider = source_id

        # Approach C: Use canonical permanent download URL under rolling 'bundles' release
        canonical_url = download_url or f"https://github.com/{RELEASE_REPO}/releases/download/{RELEASE_TAG}/{bundle_file.name}"

        self.catalog[package_name].providers[source_id] = ProviderBundleInfo(
            source_id=source_id,
            author=author,
            version=version,
            bundle_file=bundle_file.name,
            download_url=canonical_url,
            description=description,
            sha256=sha256,
            size_bytes=size_bytes,
            patches=patches
        )

    def write_manifest(self, filename: str = "bundle-manifest.json") -> Path:
        manifest_path = self.output_dir / filename
        data = {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "apps": {}
        }

        for pkg, app_entry in self.catalog.items():
            data["apps"][pkg] = {
                "app_name": app_entry.app_name,
                "default_provider": app_entry.default_provider,
                "providers": {
                    src_id: asdict(prov) for src_id, prov in app_entry.providers.items()
                }
            }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return manifest_path
