# Requirements & Goals Tracker: Deep .mpp Archive Inspection, Recipe Pinpointing & Engine Stabilization

## 1. Executive Summary & Mission Objective
Resolve remaining runtime failures (YouTube `akrh.e()` NPE) and inert feature states (Instagram/YouTube stock behavior with missing Morphe menus) across the two-project framework:
- **`codexmorphe-builder`**:
  - Transpiles upstream Morphe Patch Packs (`.mpp`) into standalone per-app `.apk` module bundles containing MultiDex extensions, AAPT2 resources, and generated `hooks.json` recipes.
  - Dynamically extracts all qualified Android resource directories (`drawable-*`, `mipmap-*`, `layout`, `values-*`, `font`, `xml`, `raw`), formats (`.xml`, `.png`, `.webp`, `.jpg`, `.jpeg`, `.json`, `.ttf`, `.otf`, `.lua`), and raw assets (`assets/`) across all custom features (SponsorBlock, Return YouTube Dislike, SwipeControls, PlayerIcons, Downloads, Custom Branding, Piko Twitter/Instagram features).
  - Dynamically discovers all 240+ target applications from `classes.dex` without hardcoding app names or feature lists.
  - Fixes AAPT2 link missing symbols (including dotted styles like `TextAppearance.AppCompat.Medium` and style attributes like `ytStaticBrandWhite`) and sets `minSdkVersion=28` for `<adaptive-icon>` support.
  - Fixes over-broad hooks, pinpoints method/fingerprint matches causing YouTube's `akrh.e()` NPE crash, and ensures extension entrypoints and resource mappings are accurately emitted so features are active.
  - Pushes built bundles to GitHub rolling releases via CI/CD (`build-bundles.yml`).
- **`CodexMorphe` Client Engine**:
  - Universal, lightweight LSPosed client engine (API 102).
  - Dynamically fetches, verifies, and hot-loads per-app bundles via LibXposed `openRemoteFile()`, injecting MultiDex extensions, merging bundle resources via `ResourcesLoader` and `ActivityLifecycleCallbacks`, and resolving DexKit hooks at runtime.
  - Hardens `DexKitHookDispatcher` (guarded `parseExtensionCall`, prevents `RETURN_TRANSFORM` null-returns on critical host types, validates `ARG_REWRITE`), verifies `BundleBridge` extension lifecycle invocation and Kotlin singleton resolution (`INSTANCE`), and ensures persistent DexKit signature caching.

---

## 2. Active Architectural Constraints & Invariants
1. **Strict Bundle-Engine Separation**: Bundles MUST remain completely decoupled from the Client Engine APK. The client engine must never contain app-specific patch bytecode, hardcoded package hooks, or static assets for 240+ apps.
2. **Zero Hardcoded App Lists**: The builder must discover applications, extensions, features, and assets dynamically from `.mpp` archive structure and bytecode.
3. **OTA Rolling Release Gate**: Client engine testing must NEVER occur against stale or mismatched bundles. CI/CD must build and publish bundles, followed by user confirmation tapping **"Fetch / Update Bundles"** in CodexMorphe before live testing.
4. **Phase Backpropagation Protocol**: If any later phase (Phase 3 or 4) reveals builder-level fingerprint, recipe, or entrypoint errors, immediately update requirements, step back to Phase 1/2, commit, push, wait for CI/CD, prompt user update, and resume.
5. **Ponytail 7-Rung Hierarchy**: Strictly adhere to simplicity hierarchy: `YAGNI` → `Internal Reuse` → `Standard Library` → `Native Platform` → `Existing Dependencies` → `One Line` → `Minimal Viable Code`.
6. **Two-Phase Approval**: Obtain user confirmation before executing any multi-file refactors or architectural changes.
7. **Pre-Modification Rationale**: Every code snippet or file modification must be preceded by an explanation of file purpose, reason for change, and pros/cons.
8. **Termux Local Build Invariant**: Local builds must use `fast-gradlew` exclusively. Always prompt the user between on-device build and GitHub cloud CI/CD.

---

## 3. Discovered Root Causes & Ground Truth Insights

### User Personal Note Reconciliation (Shared Data & Dynamic Discovery)
- **Finding:** Upstream `.mpp` archives package shared bytecode extensions (`extensions/all/*.mpe`, `extensions/shared*.mpe`), shared resources (`addresources/values-*/shared*/`), and shared patches (`patches/shared/`, `patches/all/`).
- **Dynamic Feature Association:** Instead of maintaining hardcoded app lists, all 240+ apps are discovered directly from `classes.dex` package tags (`.../patches/<app_tag>/...`). Feature resources (e.g. `sponsorblock`, `twitter-bring-back`, `swipecontrols`, `playericons`) and extensions (e.g. `shared-youtube`) are matched by testing for bytecode token references in the app's patch classes while filtering out foreign applications.
- **Resource Suffix & Density Preservation:** Added `RES_DIR_PATTERN` to capture qualified directories (`drawable-hdpi`, `drawable-xxhdpi`, `mipmap-anydpi`, `font`, `xml`) across all supported image and font formats.
- **AAPT2 MinSdk & Dotted Style Linking:** Added `minSdkVersion=28` to dummy manifest and updated symbol parser regex to catch dotted styles (`TextAppearance.AppCompat.Medium`) and style attributes (`ytStaticBrandWhite`).

### YouTube Fatal Launch Crash (`akrh.e()` NPE) & 880 Bogus Hooks
- **Finding:** 880 out of 920 hooks in `com.google.android.youtube-official-bundle.apk` had bogus extension calls pointing to patcher build-time classes (`app/morphe/patches/...->`, `app/morphe/util/BytecodeUtilsKt->`).
- **Primary Cause 1 (NameAndType Parsing Bug):** In `recipe_builder.py`, `nat = c_ast.cp.get(ref[1][1])` returns `('NameAndType', (name_idx, desc_idx))`. The code accessed `nat[0]` as `name_idx`, but `nat[0]` is the tag string `'NameAndType'`, causing `isinstance(m_n, int)` to fail. The method name was always empty `""`, generating malformed calls ending in `->`.
- **Primary Cause 2 (Over-broad Extension Package Matching):** `is_extension_package` returned `True` for any class starting with `app.` or containing `patches`, falsely classifying internal compiler tools and patcher classes as runtime extensions.
- **Primary Cause 3 (LDC Bytecode Smali Omission):** Many patches (such as `HideAdsPatchKt`) load Smali instructions via `ldc` / `ldc_w` (`0x12` / `0x13`) instead of `invokedynamic` (`0xba`). Because `ClassfileAst` only scanned `0xba`, it missed these direct bindings and fell back to `available_ext_calls[0]`.
- **Primary Cause 4 (Constructor RETURN_TRANSFORM Classification):** Methods ending with `->` had no parsed return type, causing `classify_action_from_signature` to classify constructor `<init>` hooks as `RETURN_TRANSFORM`. At runtime, hooking constructors or methods returning objects with null-producing suppressors corrupted host dependency injection.

---

## 4. Phased Deliverables & Milestone Status

### Phase 0: Requirements Tracker Artifact
- [x] Create and maintain `.agents/requirements-and-goals.md` across both repositories.

### Phase 1: Deep `.mpp` Archive Inspection & Generalized Transpiler Stabilization
- [x] Stabilize `codexmorphe_builder/parser/mpp_archive.py`:
  - [x] Universal shared extensions (`extensions/all/*.mpe`, `shared*.mpe`).
  - [x] Dynamically route extensions (e.g. `shared-youtube.mpe`) based on app bytecode tokens without hardcoding.
  - [x] Dynamic app discovery (`get_archive_apps()`) spanning all 240+ apps.
  - [x] Generalized qualified resource directory extraction (`RES_DIR_PATTERN`).
  - [x] Raw assets packaging (`assets/`).
- [x] Stabilize `codexmorphe_builder/parser/compatibility.py`:
  - [x] Associate shared patches across applicable apps dynamically without hardcoding.
- [x] Stabilize `codexmorphe_builder/assembler/aapt_compiler.py`:
  - [x] Support dotted styles (`TextAppearance.AppCompat.Medium`) and style attributes (`ytStaticBrandWhite`).
  - [x] Set `minSdkVersion=28` for `<adaptive-icon>` support.
- [x] Stabilize `codexmorphe_builder/transpiler/recipe_builder.py`:
  - [x] Narrow `is_extension_package` to `.extension.` packages.
  - [x] Fix NameAndType tuple index unpacking (`nat[1][0]`, `nat[1][1]`).
  - [x] Add `0x12` / `0x13` (`ldc` / `ldc_w`) Smali instruction scanning in `ClassfileAst`.
  - [x] Transition regex-based parsing to structured AST across XML DOM, Dalvik DEX class defs, JVM Constant Pool AST (Class, Utf8, String), and identifier AST rules (`part.isidentifier()`).
  - [x] Reject hooks with empty method names or non-extension targets.
  - [x] Enforce that constructor `<init>` hooks are strictly `AFTER`.
  - [x] Dynamically discover all app tags in archive without hardcoding.
- [x] Run test suite (`python3 -m unittest discover tests -v`) -> 16/16 passed cleanly.

### Phase 2: Commit, Push, and Rolling Release Gate
- [x] Commit all builder fixes with clean semantic commit messages.
- [x] Push to `origin/main` in `codexmorphe-builder`.
- [x] Monitor GitHub Actions workflow (`build-bundles.yml`) until completion.
- [x] Download rolling bundles from GitHub release (`com.google.android.youtube-official-bundle.apk`, `com.instagram.android-hushgram-bundle.apk`).

### Phase 3: Harden `CodexMorphe` Client Engine
- [x] Extension Lifecycle & Initialization:
  - [x] Support Kotlin singleton `object` (`INSTANCE` field) and `ResourceUtilsKt` facades in `BundleBridge.kt`.
  - [x] Pass proper host context and set `fallbackPackageName` across static methods, fields, and singleton instances.
  - [x] Canonical MultiDex container sorting (`classes.dex` through `classesN.dex`) in `BundleClassLoader.kt`.
  - [x] Dual `ResourcesLoader` + `AssetManager.addAssetPath` injection in `BundleResourceInjector.kt` to guarantee both compiled resources and raw assets are accessible.
- [x] Hook Execution Safety in `DexKitHookDispatcher.kt`:
  - [x] Guard `parseExtensionCall`: ensure `method.isNotEmpty()` and `cls.isNotEmpty()`.
  - [x] Defensive literal isolation: ignore `fp.literal` when `fp.strings` is populated.
  - [x] Concrete parameter type matching when `"L"` wildcards are present.
  - [x] Fallback single-match resolution for obfuscated methods.
- [x] Compile and install updated client engine APK (`CodexMorphe-d1483c2.apk`) via GitHub Actions CI and `adb install -r`.

### Phase 4: Live Verification & Diagnostics
- [x] Install updated `CodexMorphe` APK via `adb install -r`.
- [x] Verify rolling release bundles updated on device.
- [x] Stream and inspect live device logs:
  - `com.google.android.youtube`: 184 hooks in fast path, 50+ dynamic interceptors bound via DexKit background worker (PoToken provider, Sanitize sharing links, Spoof video streams, Hide ads, CaptionTracksManager, etc.).
  - `com.instagram.android`: 28 hooks in synchronous fast path, 25 dynamic interceptors bound via DexKit background worker (Ghost mode, Hide ads, Notification poster, etc.).
- [x] Verify YouTube launches without `akrh.e()` NPE.
- [x] Verify Instagram loads custom Morphe settings and ghost mode interceptors cleanly.
