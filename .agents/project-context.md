---
context_version: 1.0.1
synced_commit: "c3ca0e627219b5d08d31fd4eb3cf5880ea74bac3"
synced_at: "2026-10-29T18:52:14Z"
---

# Project Context: codexmorphe-builder

## 1. Quick Specs & Project Cockpit

| Property | Details / Specification |
| :--- | :--- |
| **Identifier** | `codexmorphe-builder` |
| **Runtime / Platform** | Python 3.10+ / Linux & Android Termux (`aarch64`) |
| **Toolchain & Prerequisites** | `d8` (Android SDK 30+), `aapt2`, `java` (OpenJDK 17/21), `git` |
| **Environment & Config** | `codexmorphe_builder/config.py` (resolves toolchain paths and defaults) |
| **Core Stack** | Standard Library (`zipfile`, `json`, `urllib`, `subprocess`), Python `argparse` |
| **Security & Auth** | `GITHUB_TOKEN` for CI release fetching; Ed25519 / Android V2 APK signing |
| **Primary Commands** | `Fetch: python3 -m codexmorphe_builder fetch` \| `Build: python3 -m codexmorphe_builder build` \| `Test: pytest` |

## 2. Component Ownership & Architecture Map

| Subsystem / Layer | God Node / Entrypoint (`repo-relative-path`) | Public Contract & Core Responsibility |
| :--- | :--- | :--- |
| **CLI Dispatcher** | `codexmorphe_builder/cli.py` | Command parser for `fetch`, `list`, `build`, `test`, `clean`. |
| **Source Registry & Fetcher** | `codexmorphe_builder/fetcher/release_client.py` | Scans `sources/*.json`, queries GitHub API / URLs, manages ETag & SHA256 caching. |
| **Cache Ledger** | `codexmorphe_builder/fetcher/cache_ledger.py` | Tracks `.cache/build-ledger.json` to prevent duplicate downloads and CI runs. |
| **MPP Archive Parser** | `codexmorphe_builder/parser/mpp_archive.py` | Inspects `.mpp` ZIP container: extracts DEX, `.mpe` extensions, resources. |
| **Compatibility Catalog** | `codexmorphe_builder/parser/compatibility.py` | Discovers target app package IDs and supported versions from DEX compatibility records. |
| **Redundancy Filter** | `codexmorphe_builder/filter/root_filter.py` | Strips root/LSPosed redundant patches (`GmsCore`, `CloneApp`, `SpoofSignature`, PairIP anti-tamper). |
| **Universal AST Transpiler** | `codexmorphe_builder/transpiler/classifier.py` | Maps Morphe bytecode mutations to the 5 Xposed/DexKit hook patterns. |
| **Bundle Assembler** | `codexmorphe_builder/assembler/apk_packager.py` | Drives D8 merge, AAPT2 resource link, and APK assembly for `<pkg>-<flavor>-bundle.apk`. |
| **Manifest Generator** | `codexmorphe_builder/assembler/manifest_gen.py` | Emits `bundle-manifest.json` indexing all providers, versions, and bundle SHA256 checksums. |

### Critical Execution Traces
* **Source Fetching:** `sources/*.json` → `ReleaseClient.resolve_latest()` → `CacheLedger.check()` → Download to `.cache/mpp/`
* **Bundle Compilation:** `.mpp` → `MppArchive.parse()` → `RootFilter.apply()` → `AstTranspiler.transpile()` → `D8.merge()` + `Aapt2.link()` → `<pkg>-bundle.apk`
* **Manifest Publishing:** Bundles generated → `ManifestGen.generate()` → `bundle-manifest.json`

## 3. Domain & Technical Specifications

* **Source Descriptor Format:** JSON files in `sources/<source-id>.json` specifying `id`, `name`, `repository`, `asset_pattern`, `priority`, `target_apps`.
* **Bundle Naming Standard:**
  * Provider Flavor: `<packageName>-<source_id>-bundle.apk` (e.g. `com.instagram.android-hushgram-bundle.apk`)
  * Canonical Default: `<packageName>-bundle.apk` (symlink or copy of highest priority provider)
* **Manifest Protocol:** JSON document indexing applications, default provider ID, provider metadata, and bundle SHA256 checksums.

## 4. Architectural Invariants & Guardrails

* **Zero Custom Recipes:** Never hand-write app-specific hook recipes. All hooks must be generated automatically by the AST Transpiler from the `.mpp` patch bytecode.
* **No Redundant Shims:** Never package `GmsCore`, microG redirections, package cloning, or signature spoofing patches into bundles.
* **Modular Community PRs:** Sources must exist exclusively as separate files in `sources/*.json`. Never merge multiple source declarations into a single monolithic JSON file.
* **Deterministic Cache Ledger:** Never rebuild or re-download an unchanged release. Check `tag_name` and `sha256` before initiating compilation.

### Known Landmines & Anti-Hallucination Guardrails
* `TRAP: Blindly merging two .mpp patchsets into one bundle` → `RISK: Namespace collision and hook conflicts between competing extensions` → `FIX: Emit isolated source-flavored bundles (<pkg>-<source_id>-bundle.apk) and let CodexMorphe client select provider`
* `TRAP: Including PairIP anti-tamper bypass in stock APK hooks` → `RISK: Tampering with genuine Google Play Store VM checks triggers false app integrity alerts` → `FIX: Drop anti-tamper shims while preserving genuine feature unlock patches`
* `TRAP: Running raw ./gradlew on Termux` → `RISK: Termux environment crashes or hangs due to missing wrapper environment fixes` → `FIX: Use fast-gradlew exclusively for any local Android compilation`

## 5. End-to-End Data & State Flow Pipelines

* **Ingress & Discovery:** Scan `sources/` → Read JSON descriptors → Validate schema.
* **Cache Check:** Query remote release → Check SHA256 vs `.cache/build-ledger.json` → Skip or proceed.
* **Extraction & Filtering:** Open `.mpp` → Extract `classes.dex` + `.mpe` + XML → Filter out `MOUNT` unavailable patches.
* **Transpilation:** Parse Fingerprints → Generate DexKit matchers → Classify bytecode patterns (1-5) → Emit hook DEX.
* **Packaging:** Merge `.mpe` + hook DEX via `d8` → Compile XML via `aapt2` → Assemble `<pkg>-bundle.apk` → Emit `bundle-manifest.json`.

## 6. UI/UX Design System & Tokens
* `N/A` (Headless CLI and CI pipeline)

## 7. Build, Verification & Diagnostic Recipes

```bash
# Fetch latest .mpp releases from all configured sources
python3 -m codexmorphe_builder fetch

# Build per-app bundles from cached .mpp archives
python3 -m codexmorphe_builder build --all

# Build bundles for a specific package only
python3 -m codexmorphe_builder build --app com.google.android.youtube

# Run automated validation test suite
pytest tests/ -v
```
