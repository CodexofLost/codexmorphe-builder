---
context_version: 1.0.8
synced_commit: HEAD
synced_at: "2026-10-30T20:40:00Z"
---

# Project Context: codexmorphe-builder

## 1. Quick Specs & Project Cockpit

| Property | Details / Specification |
| :--- | :--- |
| **Identifier** | `codexmorphe-builder` |
| **Runtime / Platform** | Python 3.10+ / Linux & Android Termux (`aarch64`) |
| **Toolchain & Prerequisites** | `d8` (Android SDK 30+), `aapt2`, `java` (OpenJDK 17/21), `git`, `gh` CLI |
| **Environment & Config** | `codexmorphe_builder/config.py` (resolves toolchain paths and defaults) |
| **Core Stack** | Standard Library (`zipfile`, `json`, `urllib`, `subprocess`), Python `argparse` |
| **Security & Auth** | `GITHUB_TOKEN` for CI release fetching; Ed25519 / Android V2 APK signing |
| **Primary Commands** | `Fetch: python3 -m codexmorphe_builder fetch` \| `Build: python3 -m codexmorphe_builder build` \| `Test: python3 -m unittest discover tests` |

## 2. Component Ownership & Architecture Map

| Subsystem / Layer | God Node / Entrypoint (`repo-relative-path`) | Public Contract & Core Responsibility |
| :--- | :--- | :--- |
| **CLI Dispatcher** | `codexmorphe_builder/cli.py` | Command parser for `fetch`, `list`, `build`, `test`, `clean`. |
| **Source Registry & Fetcher** | `codexmorphe_builder/fetcher/release_client.py` | Scans `sources/*.json`, queries GitHub API / URLs, manages ETag & SHA256 caching. |
| **Cache Ledger** | `codexmorphe_builder/fetcher/cache_ledger.py` | Tracks `.cache/build-ledger.json` to prevent duplicate downloads and CI runs. |
| **MPP Archive Parser** | `codexmorphe_builder/parser/mpp_archive.py` | Inspects `.mpp` ZIP container: extracts DEX, `.mpe` extensions, resources. |
| **Compatibility Catalog** | `codexmorphe_builder/parser/compatibility.py` | Discovers target app package IDs and supported versions from DEX compatibility records. |
| **Redundancy Filter** | `codexmorphe_builder/filter/root_filter.py` | Strips root/LSPosed redundant patches (`GmsCore`, `CloneApp`, `SpoofSignature`, PairIP anti-tamper). |
| **Universal AST Transpiler** | `codexmorphe_builder/transpiler/recipe_builder.py` | Maps Morphe bytecode mutations to Xposed/DexKit hook patterns, enforces lifecycle safety, framework class filtering, companion scanning, and hook deduplication. |
| **Bundle Assembler** | `codexmorphe_builder/assembler/apk_packager.py` | Packages MultiDex `.mpe` files, AAPT2 resources, and dual `hooks.json` / `assets/hooks.json`. |
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
* **Universal Transpilation Safety:**
  * `Discriminator Validation & Wildcard Guard`: Reject any fingerprint or hook lacking `method_name`, `strings`, or `literal` to prevent DexKit from matching every method declared in the class.
  * `Bytecode String Sanitization (is_valid_dex_string)`: Reject multi-word English sentences, patch descriptions ("Show hidden like counts", "Back leaves Home"), and compiler diagnostics from DexKit candidate strings so bytecode searches match only genuine DEX string constants.
  * `Patcher Metadata & Access Flag Filtering`: Filter out patcher framework access flags (`PUBLIC`, `FINAL`, `CONSTRUCTOR`, `STATIC`, `Opcode.*`) from DexKit string candidate pools so Dalvik bytecode searches do not fail on synthetic reflection tokens.
  * `Inner Class & Delimiter Support ($)`: Support Java/Kotlin inner classes and protobuf message identifiers (e.g. `ClientAbrStateOuterClass$ClientAbrState`, `Activity$1`) during class name and fingerprint validation.
  * `Parent Query Recursion`: Embed `parent_query` criteria into child fingerprints when a parent fingerprint lacks a static declaring class, enabling runtime resolution of parent classes (e.g. `ShortsQualityMenu`) before binding child constructors or methods.
  * `Resource Literal Queries`: Emit `resource_name` and `resource_type` in hook recipes when `resourceLiteral` calls are identified, enabling runtime Android resource ID lookup.
  * `Lifecycle Disambiguation & Data Model Decoupling`: Anchor unanchored Activity lifecycle methods (`onBackPressed`, `onCreate`, `onResume`, `onDestroy`) to `android.app.Activity` instead of data models or framework base classes, and decouple data model parameters (e.g. `ReelItem`) from UI callbacks (`onClick`, `getView`).
  * `Constructor Discrimination`: Detect constructor fingerprints (ending in `Constructor`) and assign `method_name: "<init>"` and `return_type: "void"`.
  * `Dynamic Entrypoints & Resource Fallbacks`: Auto-discover lifecycle entrypoints (`SettingsEntry#onApplicationCreate`, `AddOnApi#initialize`, `Utils#setContext`) and `ResourceUtils` classes for any author package, emitting them under `entrypoints` and `resource_fallbacks` in `hooks.json`.
  * `is_framework_class`: Framework types (`java.*`, `javax.*`, `kotlin.*`, `j$.*`, `android.os.*`, `android.util.*`, `android.content.res.*`, `android.graphics.*`) must never be mapped as `declaring_class`.
  * `Positional Fingerprint Parsing`: In Morphe Patcher, `definingClass` is strictly constructor argument 2 (`p1`). Argument 5 is `returnType`, Argument 6 is `parameters`.
  * `Intelligent Companion Mapping`: Companion classes without explicit fingerprints are dynamically mapped by target class (`InstagramAppShell`, `InstagramMainActivity`) and lifecycle methods (`onCreate`, `onNewIntent`), while purging compiler exception strings.
  * `Return Type Preservation`: Methods returning primitives must not have object-returning extensions mapped as `RETURN_TRANSFORM`.
* **No Redundant Shims:** Never package `GmsCore`, microG redirections, package cloning, or signature spoofing patches into bundles.
* **Modular Community PRs:** Sources must exist exclusively as separate files in `sources/*.json`. Never merge multiple source declarations into a single monolithic JSON file.
* **Deterministic Cache Ledger:** Never rebuild or re-download an unchanged release. Check `tag_name` and `sha256` before initiating compilation.

### Known Landmines & Anti-Hallucination Guardrails
* `TRAP: Blindly merging two .mpp patchsets into one bundle` → `RISK: Namespace collision and hook conflicts between competing extensions` → `FIX: Emit isolated source-flavored bundles (<pkg>-<source_id>-bundle.apk) and let CodexMorphe client select provider`
* `TRAP: Hooking BaseActivityHook to MainActivity.onCreate` → `RISK: Normal app launches have null intent data, causing "BaseActivityHook: Unknown intent: null" and ART crash` → `FIX: Hook BaseActivityHook exclusively to GoogleApiActivity.onCreate`
* `TRAP: Inadvertently classifying ARG_REWRITE as RETURN_TRANSFORM` → `RISK: Extension returns Object/Uri to a method expecting Boolean/int, crashing ART with ClassCastException` → `FIX: Compare target return type and smali instruction pattern (move-result-object p)`
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
python3 -m unittest discover tests -v
```
