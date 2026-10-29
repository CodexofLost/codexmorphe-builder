import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TargetAppsFilter:
    include: List[str] = field(default_factory=lambda: ["*"])
    exclude: List[str] = field(default_factory=list)

    def is_allowed(self, package_name: str) -> bool:
        if package_name in self.exclude:
            return False
        if "*" in self.include:
            return True
        return package_name in self.include


@dataclass
class SourceDescriptor:
    id: str
    name: str
    type: str  # "github_release", "github_artifact", "direct_url", "local_file"
    repository: Optional[str] = None  # e.g. "MorpheApp/morphe-patches"
    direct_url: Optional[str] = None
    local_path: Optional[str] = None
    asset_pattern: str = r".*\.mpp$"
    include_prerelease: bool = False
    priority: int = 50
    enabled: bool = True
    description: str = ""
    target_apps: TargetAppsFilter = field(default_factory=TargetAppsFilter)

    @classmethod
    def from_file(cls, path: Path) -> "SourceDescriptor":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        target_apps_raw = data.get("target_apps", {})
        target_apps = TargetAppsFilter(
            include=target_apps_raw.get("include", ["*"]),
            exclude=target_apps_raw.get("exclude", [])
        )

        return cls(
            id=data["id"],
            name=data["name"],
            type=data.get("type", "github_release"),
            repository=data.get("repository"),
            direct_url=data.get("direct_url"),
            local_path=data.get("local_path"),
            asset_pattern=data.get("asset_pattern", r".*\.mpp$"),
            include_prerelease=data.get("include_prerelease", False),
            priority=data.get("priority", 50),
            enabled=data.get("enabled", True),
            description=data.get("description", ""),
            target_apps=target_apps
        )

    def matches_asset(self, asset_name: str) -> bool:
        return bool(re.match(self.asset_pattern, asset_name, re.IGNORECASE))


def load_all_sources(sources_dir: Path) -> Dict[str, SourceDescriptor]:
    sources: Dict[str, SourceDescriptor] = {}
    if not sources_dir.exists():
        return sources

    for json_file in sorted(sources_dir.glob("*.json")):
        try:
            source = SourceDescriptor.from_file(json_file)
            sources[source.id] = source
        except Exception as e:
            print(f"[WARN] Failed to load source {json_file.name}: {e}")

    return sources
