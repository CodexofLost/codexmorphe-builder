import re
from typing import List, Tuple, Dict

# 9 Categories of Patches that are strictly redundant or harmful under LSPosed in-memory hooking
CATEGORIZED_REDUNDANT_PATTERNS: Dict[str, List[str]] = {
    "1. Custom Branding & Launcher Icons": [
        r".*custombranding.*",
        r".*changeheader.*",
        r".*addbrandlicense.*",
        r".*appicon(?:resource)?patch.*",
        r".*pickappicon.*",
        r".*themedicon.*",
    ],
    "2. Signature, Cert & Integrity Bypasses": [
        r".*spoof.*(?:signature|cert|hash).*",
        r".*overridecertificatepinning.*",
        r".*signaturecompatibility.*",
        r".*signaturedetection.*",
        r".*certseed.*",
        r".*bypasscodetransparency.*",
        r".*bypassintegritycheck.*",
        r".*disablesignaturecheck.*",
        r".*aapadsecuritybypass.*",
        r".*messengersignature.*",
        r".*picturemushroom/signature.*",
    ],
    "3. GmsCore / MicroG Redirection": [
        r".*gmscore.*",
        r".*microg.*",
        r".*accountcredentialsinvalidtext.*",
        r".*devicecompliancecheck.*",
        r".*gms.*linkhandling.*",
        r".*playservice.*versioncheck.*",
    ],
    "4. Package Renaming, Cloning & Coexistence": [
        r".*clone(?:app)?patch.*",
        r".*changepackage.*",
        r".*installnextto.*",
        r".*renamesharedpermissions.*",
    ],
    "5. Update Blocking & Version Code Spoofing": [
        r".*disableplaystoreupdates.*",
        r".*disablelayoutupdates.*",
        r".*disableautoupdate.*",
        r".*blockupdatescreen.*",
        r".*hideupdatescreen.*",
        r".*hideupdatepopup.*",
        r".*truecloudupdate.*",
    ],
    "6. AndroidManifest & SharedUserId Shims": [
        r".*removeshareduserid.*",
        r".*fixduplicatepermissions.*",
        r".*exportallactivities.*",
    ],
    "7. PairIP Anti-Tamper & Native Kill Gates": [
        r".*pairip.*(?:antitamper|signature|vmgate|licensecheck|removal|bypass).*",
        r".*nativekillgate.*",
    ],
    "8. Content / File Provider Shims": [
        r".*fixcontentprovider.*",
        r".*fileproviderpatch.*",
        r".*fixpreferenceicon.*",
    ],
    "9. Developer / Debugging Mode Shims": [
        r".*enable(?:android)?debugging.*",
        r".*debugmode.*",
        r".*debugcomment.*",
        r".*debugoverflow.*",
    ]
}


def is_patch_redundant(patch_class: str) -> Tuple[bool, str]:
    """
    Check if a given patch class is redundant for an in-memory LSPosed engine.
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
