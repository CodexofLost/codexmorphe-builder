import re
from typing import List, Tuple, Dict

# The 6 strictly redundant or harmful patch categories under in-memory LSPosed hooking.
# NOTE: PairIP license/installer bypasses, in-app update blockers, Play Store update blockers,
# code transparency checks, and certificate pinning overrides are DELIBERATELY RETAINED
# to ensure manual sideloading of supported APK versions works flawlessly without crashes or popups.
CATEGORIZED_REDUNDANT_PATTERNS: Dict[str, List[str]] = {
    "1. Custom Branding & Launcher Icons": [
        r".*custombranding.*",
        r".*changeheader.*",
        r".*addbrandlicense.*",
        r".*appicon(?:resource)?patch.*",
        r".*pickappicon.*",
        r".*themedicon.*",
    ],
    "2. GmsCore / MicroG Redirection": [
        r".*gmscore.*",
        r".*microg.*",
        r".*accountcredentialsinvalidtext.*",
        r".*devicecompliancecheck.*",
        r".*gms.*linkhandling.*",
        r".*playservice.*versioncheck.*",
    ],
    "3. Package Renaming, Cloning & Coexistence": [
        r".*clone(?:app)?patch.*",
        r".*changepackage.*",
        r".*installnextto.*",
        r".*renamesharedpermissions.*",
    ],
    "4. AndroidManifest Static Repackaging Shims": [
        r".*removeshareduserid.*",
        r".*fixduplicatepermissions.*",
        r".*exportallactivities.*",
    ],
    "5. Cloned Content / File Provider Shims": [
        r".*fixcontentprovider.*",
        r".*fileproviderpatch.*",
        r".*fixpreferenceicon.*",
    ],
    "6. Developer / Debugging Mode Clutter": [
        r".*enable(?:android)?debugging.*",
        r".*debugmode.*",
        r".*debugcomment.*",
        r".*debugoverflow.*",
    ]
}


def is_patch_redundant(patch_class: str) -> Tuple[bool, str]:
    """
    Check if a given patch class is strictly redundant for an in-memory LSPosed engine.
    Returns (is_redundant, category_and_pattern).
    """
    normalized = patch_class.lower().replace("/", ".").replace("$", "")
    for category, patterns in CATEGORIZED_REDUNDANT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, normalized):
                return True, f"[{category}] Matched pattern: {pattern}"
    return False, ""


def filter_redundant_patches(patch_classes: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Filter a list of patch classes, returning (retained_patches, dropped_patches_with_reason).
    """
    retained = []
    dropped = []
    for cls in patch_classes:
        redundant, reason = is_patch_redundant(cls)
        if redundant:
            dropped.append((cls, reason))
        else:
            retained.append(cls)
    return retained, dropped
