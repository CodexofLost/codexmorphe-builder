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

KNOWN_APP_NAMES = {
    "com.google.android.youtube": "YouTube",
    "com.google.android.apps.youtube.music": "YouTube Music",
    "com.reddit.frontpage": "Reddit",
    "com.instagram.android": "Instagram",
    "com.twitter.android": "Twitter / X",
    "org.telegram.messenger": "Telegram",
    "com.amazon.mp3": "Amazon Music",
    "com.altosadventure": "Alto's Adventure",
    "com.altosodyssey": "Alto's Odyssey",
    "com.duolingo": "Duolingo",
    "com.strava": "Strava",
    "com.zhiliaoapp.musically": "TikTok",
    "com.spotify.music": "Spotify"
}


@dataclass
class PatchInfo:
    id: str
    name: str
    description: str
    default: bool
    key: str
    patch_class: str


def clean_patch_name(cls_name: str) -> str:
    base = cls_name.split("/")[-1].replace("PatchKt", "").replace("Patch", "")
    name = re.sub(r"([A-Z])", r" \1", base).strip()
    return name or "Custom Patch"


def make_patch_key(name: str) -> str:
    return "morphe_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


@dataclass
class DiscoveredApp:
    package_name: str
    app_name: str
    app_tag: str
    patch_classes: List[str] = field(default_factory=list)
    patches: List[PatchInfo] = field(default_factory=list)


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

        try:
            p_idx = parts.index("patches")
            if p_idx + 1 < len(parts):
                app_tag = parts[p_idx + 1]
                if app_tag in ("all", "shared", "util"):
                    continue

                pkg = KNOWN_NAMESPACE_MAPPINGS.get(app_tag, f"com.{app_tag}.app")
                app_display_name = KNOWN_APP_NAMES.get(pkg, app_tag.title())

                if pkg not in discovered:
                    discovered[pkg] = DiscoveredApp(
                        package_name=pkg,
                        app_name=app_display_name,
                        app_tag=app_tag
                    )

                patch_name = clean_patch_name(clean)
                patch_key = make_patch_key(patch_name)
                patch_id = re.sub(r"[^a-z0-9]+", "_", patch_name.lower()).strip("_")
                desc = f"Enables options to customize and enhance {patch_name.lower()}."

                patch_info = PatchInfo(
                    id=patch_id,
                    name=patch_name,
                    description=desc,
                    default=True,
                    key=patch_key,
                    patch_class=clean
                )

                discovered[pkg].patch_classes.append(clean)
                discovered[pkg].patches.append(patch_info)
        except ValueError:
            pass

    return discovered
