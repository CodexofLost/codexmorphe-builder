import argparse
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .assembler.apk_packager import assemble_bundle_apk
from .assembler.d8_merger import merge_dex_files
from .assembler.manifest_gen import BundleManifestGenerator
from .config import BUILD_TMP_DIR, CACHE_DIR, LEDGER_FILE, MPP_CACHE_DIR, OUTPUT_DIR, SOURCES_DIR, get_toolchain_status
from .fetcher.cache_ledger import CacheLedger
from .fetcher.release_client import ReleaseClient
from .fetcher.source_model import SourceDescriptor, load_all_sources
from .filter.root_filter import filter_redundant_patches
from .parser.compatibility import discover_compatible_apps
from .parser.mpp_archive import MppArchive


def cmd_list(args: argparse.Namespace) -> None:
    sources = load_all_sources(SOURCES_DIR)
    ledger = CacheLedger(LEDGER_FILE)
    print("\n" + "=" * 70)
    print("CODEXMORPHE-BUILDER: CONFIGURED MPP SOURCES")
    print("=" * 70)

    for src_id, src in sorted(sources.items(), key=lambda x: x[1].priority, reverse=True):
        status = "ENABLED" if src.enabled else "DISABLED"
        entry = ledger.get(src_id)
        cached_info = f"Cached ({entry.release_tag})" if (entry and Path(entry.file_path).exists()) else "Not Cached"
        print(f"[{status}] {src.name} ({src.id})")
        print(f"  Repo:     {src.repository or src.direct_url or src.local_path}")
        print(f"  Priority: {src.priority} | Status: {cached_info}")
        if src.description:
            print(f"  Info:     {src.description}")
        print()


def cmd_fetch(args: argparse.Namespace) -> None:
    sources = load_all_sources(SOURCES_DIR)
    ledger = CacheLedger(LEDGER_FILE)
    client = ReleaseClient(MPP_CACHE_DIR, ledger)

    target_sources = sources
    if args.source:
        if args.source not in sources:
            print(f"[ERROR] Source '{args.source}' not found in {SOURCES_DIR}")
            sys.exit(1)
        target_sources = {args.source: sources[args.source]}

    print(f"\n[START] Fetching {len(target_sources)} source(s)...")
    for src in target_sources.values():
        client.fetch_source(src, force=args.force)

    print("\n✓ Fetch cycle complete.")


def cmd_build(args: argparse.Namespace) -> None:
    sources = load_all_sources(SOURCES_DIR)
    ledger = CacheLedger(LEDGER_FILE)
    manifest_gen = BundleManifestGenerator(OUTPUT_DIR)

    # Check toolchain
    status = get_toolchain_status()
    if status["d8"] == "MISSING":
        print("[ERROR] Cannot build: Android SDK 'd8' tool is missing.")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("CODEXMORPHE-BUILDER: COMPILING PER-APP BUNDLES")
    print("=" * 70)

    # Sort sources by priority descending
    sorted_sources = sorted(sources.values(), key=lambda s: s.priority, reverse=True)
    built_apps = set()

    for src in sorted_sources:
        if args.source and src.id != args.source:
            continue

        entry = ledger.get(src.id)
        if not entry or not Path(entry.file_path).exists():
            print(f"[SKIP] Source '{src.id}' has no cached .mpp file. Run 'fetch' first.")
            continue

        mpp_path = Path(entry.file_path)
        print(f"\n---> Processing Source: {src.name} ({entry.release_tag})")
        archive = MppArchive.from_file(mpp_path)
        discovered_apps = discover_compatible_apps(archive)

        print(f"  Discovered {len(discovered_apps)} target applications in {mpp_path.name}:")
        for pkg, app_info in discovered_apps.items():
            if args.app and pkg != args.app:
                continue
            if not src.target_apps.is_allowed(pkg):
                print(f"    [EXCLUDED] {pkg} (Filtered by source target_apps)")
                continue

            print(f"\n  [APP] {pkg} (tag: {app_info.app_tag})")
            retained_patches, dropped = filter_redundant_patches(app_info.patch_classes)
            print(f"    Patches: {len(retained_patches)} active ({len(dropped)} non-root redundant filtered)")

            # Workspace for this app
            app_tmp_dir = BUILD_TMP_DIR / f"{pkg}_{src.id}"
            if app_tmp_dir.exists():
                shutil.rmtree(app_tmp_dir)
            app_tmp_dir.mkdir(parents=True, exist_ok=True)

            # Step 1: Extract extension .mpe files
            ext_dir = app_tmp_dir / "extensions"
            extracted_mpe = archive.extract_extensions_for_app(app_info.app_tag, ext_dir)
            print(f"    Extracted {len(extracted_mpe)} extension .mpe file(s)")

            # Step 2: Package bundle APK as standard MultiDex
            if not extracted_mpe:
                print("    [WARN] No .mpe extensions matched for this app tag.")
                continue

            bundle_filename = f"{pkg}-{src.id}-bundle.apk"
            output_bundle_apk = OUTPUT_DIR / bundle_filename
            assemble_bundle_apk(extracted_mpe, None, output_bundle_apk)
            print(f"    ✓ Emitted MultiDex bundle: {bundle_filename} ({output_bundle_apk.stat().st_size // 1024} KB)")

            # If this is the highest priority source for this app, also emit canonical bundle
            is_canonical = pkg not in built_apps
            if is_canonical:
                canonical_apk = OUTPUT_DIR / f"{pkg}-bundle.apk"
                shutil.copy2(output_bundle_apk, canonical_apk)
                print(f"    ★ Emitted canonical default: {canonical_apk.name}")
                built_apps.add(pkg)

            # Register in manifest
            manifest_gen.register_bundle(
                package_name=pkg,
                source_id=src.id,
                source_name=src.name,
                version=entry.release_tag,
                bundle_file=output_bundle_apk,
                description=src.description,
                is_default=is_canonical
            )

    # Write final manifest
    manifest_file = manifest_gen.write_manifest()
    print(f"\n✓ Published bundle manifest: {manifest_file.resolve()}")
    print("=" * 70)


def cmd_clean(args: argparse.Namespace) -> None:
    print("[CLEAN] Cleaning build temporary directory and outputs...")
    if BUILD_TMP_DIR.exists():
        shutil.rmtree(BUILD_TMP_DIR)
        BUILD_TMP_DIR.mkdir(parents=True, exist_ok=True)
    if args.all:
        if OUTPUT_DIR.exists():
            shutil.rmtree(OUTPUT_DIR)
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        if CACHE_DIR.exists():
            shutil.rmtree(CACHE_DIR)
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
    print("✓ Clean completed.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="codexmorphe-builder",
        description="CodexMorphe Automated MPP Ingestion and Per-App Bundle Builder"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    subparsers.add_parser("list", help="List all configured patch sources and local cache status")

    # fetch
    fetch_parser = subparsers.add_parser("fetch", help="Fetch latest .mpp releases from sources")
    fetch_parser.add_argument("--source", type=str, help="Specific source ID to fetch")
    fetch_parser.add_argument("--force", action="store_true", help="Force re-download even if cached")

    # build
    build_parser = subparsers.add_parser("build", help="Build per-app bundles from cached .mpp archives")
    build_parser.add_argument("--all", action="store_true", help="Build all discovered applications")
    build_parser.add_argument("--app", type=str, help="Specific application package name to build")
    build_parser.add_argument("--source", type=str, help="Specific source ID to build from")

    # clean
    clean_parser = subparsers.add_parser("clean", help="Clean build temporary files")
    clean_parser.add_argument("--all", action="store_true", help="Also wipe output and downloaded caches")

    args = parser.parse_args()
    if args.command == "list":
        cmd_list(args)
    elif args.command == "fetch":
        cmd_fetch(args)
    elif args.command == "build":
        cmd_build(args)
    elif args.command == "clean":
        cmd_clean(args)


if __name__ == "__main__":
    main()
