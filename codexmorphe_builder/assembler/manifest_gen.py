import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from .apk_packager import compute_sha256


@dataclass
class ProviderBundleInfo:
    source_id: str
    name: str
    version: str
    bundle_file: str
    description: str
    sha256: str
    size_bytes: int


@dataclass
class AppCatalogEntry:
    package_name: str
    default_provider: str
    providers: Dict[str, ProviderBundleInfo] = field(default_factory=dict)


class BundleManifestGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.catalog: Dict[str, AppCatalogEntry] = {}

    def register_bundle(
        self,
        package_name: str,
        source_id: str,
        source_name: str,
        version: str,
        bundle_file: Path,
        description: str,
        is_default: bool = False
    ) -> None:
        sha256 = compute_sha256(bundle_file)
        size_bytes = bundle_file.stat().st_size

        if package_name not in self.catalog:
            self.catalog[package_name] = AppCatalogEntry(
                package_name=package_name,
                default_provider=source_id
            )

        if is_default:
            self.catalog[package_name].default_provider = source_id

        self.catalog[package_name].providers[source_id] = ProviderBundleInfo(
            source_id=source_id,
            name=source_name,
            version=version,
            bundle_file=bundle_file.name,
            description=description,
            sha256=sha256,
            size_bytes=size_bytes
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
                "default": app_entry.default_provider,
                "providers": {
                    src_id: asdict(prov) for src_id, prov in app_entry.providers.items()
                }
            }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return manifest_path
