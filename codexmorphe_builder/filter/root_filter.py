import re
from typing import List, Tuple

# Patterns identifying patches that are strictly redundant or harmful when running under LSPosed
REDUNDANT_PATCH_PATTERNS = [
    # GmsCore / MicroG redirection
    r".*gmscore.*",
    r".*microg.*",
    r".*playservice.*versioncheck.*",
    # App cloning and package name modifications
    r".*cloneapp.*",
    r".*changepackage.*",
    r".*installnextto.*",
    r".*renamesharedpermissions.*",
    # Signature spoofing & integrity verification bypasses
    r".*spoof.*signature.*",
    r".*spoof.*cert.*",
    r".*provideoriginalappcert.*",
    r".*bypassintegritycheck.*",
    r".*aapadsecuritybypass.*",
    # PairIP anti-tamper (preserves feature bypasses like PairipUnlock)
    r".*pairip.*antitamper.*",
    r".*pairip.*signature.*",
    r".*pairip.*vmgate.*",
    r".*pairip.*licensecheck.*",
    # Play store updates blocker (unneeded because DexKit adapts across versions)
    r".*disableplaystoreupdates.*",
    r".*disableautoupdate.*"
]


def is_patch_redundant(patch_class: str) -> Tuple[bool, str]:
    """
    Check if a given patch class is redundant for an in-memory LSPosed engine.
    Returns (is_redundant, reason).
    """
    normalized = patch_class.lower().replace("/", ".").replace("$", "")
    for pattern in REDUNDANT_PATCH_PATTERNS:
        if re.search(pattern, normalized):
            return True, f"Matched redundant pattern: {pattern}"
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
