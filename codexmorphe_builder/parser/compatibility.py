import re
from dataclasses import dataclass, field
from typing import Dict, List, Set
from .mpp_archive import MppArchive


# Known standard package mappings for Morphe patch namespaces
KNOWN_NAMESPACE_MAPPINGS = {
    "youtube": "com.google.android.youtube",
    "music": "com.google.android.apps.youtube.music",
    "reddit": "com.reddit.frontpage",
    "instagram": "com.instagram.android",
    "twitter": "com.twitter.android",
    "telegram": "org.telegram.messenger",
    "amznmusic": "com.amazon.mp3",
    "altosadventure": "com.altosadventure",
    "altosodyssey": "com.altosodyssey",
    "duolingo": "com.duolingo",
    "strava": "com.strava",
    "tiktok": "com.zhiliaoapp.musically",
    "spotify": "com.spotify.music"
}


@dataclass
class DiscoveredApp:
    package_name: str
    app_tag: str
    patch_classes: List[str] = field(default_factory=list)


def discover_compatible_apps(archive: MppArchive) -> Dict[str, DiscoveredApp]:
    """
    Inspect the patch classes in classes.dex and group them by target application.
    """
    discovered: Dict[str, DiscoveredApp] = {}

    for cls in archive.dex_classes:
        # Look for Patch classes: e.g. Lapp/morphe/patches/youtube/.../HideAdsPatchKt;
        # or Lapp/crimera/patches/instagram/...
        # or Lapp/template/patches/telegram/...
        if not ("patches/" in cls and "PatchKt" in cls and "$" not in cls):
            continue

        clean = cls.strip("L;").replace("\\", "/")
        parts = clean.split("/")

        # Extract app tag (e.g. 'youtube', 'reddit', 'instagram', 'twitter', 'amznmusic')
        try:
            p_idx = parts.index("patches")
            if p_idx + 1 < len(parts):
                app_tag = parts[p_idx + 1]
                if app_tag in ("all", "shared", "util"):
                    continue

                pkg = KNOWN_NAMESPACE_MAPPINGS.get(app_tag, f"com.{app_tag}.app")
                if pkg not in discovered:
                    discovered[pkg] = DiscoveredApp(package_name=pkg, app_tag=app_tag)
                discovered[pkg].patch_classes.append(clean)
        except ValueError:
            pass

    return discovered
