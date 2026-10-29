import os
import shutil
import sys
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCES_DIR = PROJECT_ROOT / "sources"
CACHE_DIR = PROJECT_ROOT / ".cache"
MPP_CACHE_DIR = CACHE_DIR / "mpp"
BUILD_TMP_DIR = CACHE_DIR / "tmp"
OUTPUT_DIR = PROJECT_ROOT / "dist"
LEDGER_FILE = CACHE_DIR / "build-ledger.json"

# Release Settings (Approach C: Rolling Release)
RELEASE_REPO = os.environ.get("RELEASE_REPO", "CodexMorphe/codexmorphe-builder")
RELEASE_TAG = os.environ.get("RELEASE_TAG", "bundles")

# Ensure essential directories exist
for directory in (SOURCES_DIR, CACHE_DIR, MPP_CACHE_DIR, BUILD_TMP_DIR, OUTPUT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

def find_tool(name: str, sdk_subpath: str = "build-tools") -> Path | None:
    """
    Search for a tool binary in PATH or within the Android SDK directory.
    Supports Termux, standard Linux, and GitHub Actions runners.
    """
    # 1. System PATH
    found = shutil.which(name)
    if found:
        return Path(found)

    # 2. Check ANDROID_HOME / ANDROID_SDK_ROOT
    sdk_roots = []
    if "ANDROID_HOME" in os.environ:
        sdk_roots.append(Path(os.environ["ANDROID_HOME"]))
    if "ANDROID_SDK_ROOT" in os.environ:
        sdk_roots.append(Path(os.environ["ANDROID_SDK_ROOT"]))

    # 3. Known Termux / User SDK locations
    home = Path.home()
    sdk_roots.extend([
        home / "android-sdk",
        home / "Android" / "Sdk",
        Path("/usr/lib/android-sdk")
    ])

    for root in sdk_roots:
        if not root.exists():
            continue
        tools_dir = root / sdk_subpath
        if tools_dir.exists():
            # Search newest version first
            for version_dir in sorted(tools_dir.iterdir(), reverse=True):
                candidate = version_dir / name
                if candidate.exists() and os.access(candidate, os.X_OK):
                    return candidate

    return None

D8_BIN = find_tool("d8")
AAPT2_BIN = find_tool("aapt2")
JAVA_BIN = find_tool("java")
ZIPALIGN_BIN = find_tool("zipalign")
APKSIGNER_BIN = find_tool("apksigner")


def find_android_jar() -> Path | None:
    """
    Search for android.jar in platforms/ directories under known SDK roots.
    Prefers the highest platform version available (e.g. android-37 > android-35).
    """
    home = Path.home()
    sdk_roots = []
    if "ANDROID_HOME" in os.environ:
        sdk_roots.append(Path(os.environ["ANDROID_HOME"]))
    if "ANDROID_SDK_ROOT" in os.environ:
        sdk_roots.append(Path(os.environ["ANDROID_SDK_ROOT"]))
    sdk_roots.extend([
        home / "android-sdk",
        home / "Android" / "Sdk",
        Path("/usr/lib/android-sdk")
    ])

    candidates = []
    for root in sdk_roots:
        platforms_dir = root / "platforms"
        if platforms_dir.exists():
            for p in platforms_dir.iterdir():
                jar = p / "android.jar"
                if jar.exists():
                    candidates.append(jar)

    if candidates:
        return sorted(candidates, key=lambda p: p.parent.name, reverse=True)[0]
    return None


ANDROID_JAR = find_android_jar()


def get_toolchain_status() -> dict:
    return {
        "d8": str(D8_BIN) if D8_BIN else "MISSING",
        "aapt2": str(AAPT2_BIN) if AAPT2_BIN else "MISSING",
        "android_jar": str(ANDROID_JAR) if ANDROID_JAR else "MISSING",
        "java": str(JAVA_BIN) if JAVA_BIN else "MISSING",
        "zipalign": str(ZIPALIGN_BIN) if ZIPALIGN_BIN else "MISSING",
        "apksigner": str(APKSIGNER_BIN) if APKSIGNER_BIN else "MISSING",
    }
