#!/usr/bin/env python3
"""
Purge orphaned and obsolete bundle APK assets from the GitHub rolling release.
Compares assets in the 'bundles' release against bundle-manifest.json and deletes
any asset not referenced in the manifest.
"""

import json
import subprocess
import sys
from pathlib import Path


def main():
    # Always prioritize latest-manifest.json or download fresh from GitHub release
    manifest_path = Path("latest-manifest.json")
    if not manifest_path.exists():
        print("[INFO] Downloading bundle-manifest.json from GitHub release 'bundles'...")
        res = subprocess.run(
            ["gh", "release", "download", "bundles", "-p", "bundle-manifest.json", "-O", "latest-manifest.json"],
            capture_output=True,
            text=True
        )

    if not manifest_path.exists():
        print("[ERROR] Cannot find or download bundle-manifest.json. Aborting.")
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    valid_files = {"bundle-manifest.json"}
    for app_data in manifest.get("apps", {}).values():
        for provider in app_data.get("providers", {}).values():
            if "bundle_file" in provider:
                valid_files.add(provider["bundle_file"])

    print(f"[INFO] Authoritative manifest contains {len(valid_files)} valid asset(s).")
    if len(valid_files) < 100:
        print(f"[CRITICAL ERROR] Manifest has suspiciously few valid assets ({len(valid_files)}). Refusing to purge to prevent data loss.")
        sys.exit(1)

    # Fetch current assets on GitHub release
    try:
        out = subprocess.check_output(
            ["gh", "release", "view", "bundles", "--json", "assets"],
            text=True
        )
        release_data = json.loads(out)
    except Exception as e:
        print(f"[ERROR] Failed to query GitHub release: {e}")
        sys.exit(1)

    assets = release_data.get("assets", [])
    orphans = [a["name"] for a in assets if a["name"] not in valid_files]

    if not orphans:
        print("[SUCCESS] Zero orphaned assets found. Release is 100% clean!")
        return

    print(f"[ACTION] Found {len(orphans)} orphaned/obsolete asset(s) to purge from 'bundles' release.")
    purged_count = 0
    for name in orphans:
        print(f"  Deleting orphaned asset: {name}...")
        del_res = subprocess.run(
            ["gh", "release", "delete-asset", "bundles", name, "-y"],
            capture_output=True,
            text=True
        )
        if del_res.returncode == 0:
            purged_count += 1
        else:
            print(f"    [WARN] Failed to delete {name}: {del_res.stderr.strip()}")

    print(f"\n[SUCCESS] Successfully purged {purged_count}/{len(orphans)} orphaned asset(s) from 'bundles' release.")


if __name__ == "__main__":
    main()
