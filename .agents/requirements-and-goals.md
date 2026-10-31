# Requirements & Goals Tracker: Deep .mpp Archive Inspection, Recipe Pinpointing & Engine Stabilization

## 1. Executive Summary & Mission Objective
Resolve remaining runtime failures (YouTube `akrh.e()` NPE) and inert feature states (Instagram/YouTube stock behavior with missing Morphe menus) across the two-project framework:
- **`codexmorphe-builder`**:
  - Transpiles upstream Morphe Patch Packs (`.mpp`) into standalone per-app `.apk` module bundles containing MultiDex extensions, AAPT2 resources, and generated `hooks.json` recipes.
  - Fix over-broad hooks, pinpoint method/fingerprint matches causing YouTube's `akrh.e()` NPE crash, and ensure extension entrypoints and resource mappings are accurately emitted so features are active.
  - Incorporate shared patch pack data: universal shared extensions (`extensions/all/`, `shared-youtube.mpe` for YouTube Music), shared AAPT2 resources (`shared`, `all`, `sponsorblock`), and shared hook recipes (`SettingsPatch`, `LithoFilterPatch`, `TreeNodeElementHookPatch`).
  - Publish updated bundles via GitHub rolling release (`build-bundles.yml`).
- **`CodexMorphe` Client Engine**:
  - Universal, lightweight LSPosed client engine (API 102).
  - Dynamically fetches, verifies, and hot-loads per-app bundles via LibXposed `openRemoteFile()`, injecting MultiDex extensions, merging bundle resources via `ResourcesLoader` and `ActivityLifecycleCallbacks`, and resolving DexKit hooks at runtime.
  - Harden `DexKitHookDispatcher` (prevent `RETURN_TRANSFORM` null-returns on critical host types, validate `ARG_REWRITE`), verify `BundleBridge` extension lifecycle invocation and Kotlin singleton resolution, and ensure persistent DexKit signature caching.

---

## 2. Active Architectural Constraints & Invariants
1. **Strict Bundle-Engine Separation**: Bundles MUST remain completely decoupled from the Client Engine APK. The client engine must never contain app-specific patch bytecode, hardcoded package hooks, or static assets for 240+ apps.
2. **OTA Rolling Release Gate**: Client engine testing must NEVER occur against stale or mismatched bundles. CI/CD must build and publish bundles, followed by user confirmation tapping **"Fetch / Update Bundles"** in CodexMorphe before live testing.
3. **Phase Backpropagation Protocol**: If any later phase (Phase 3 or 4) reveals builder-level fingerprint, recipe, or entrypoint errors, immediately update requirements, step back to Phase 1/2, commit, push, wait for CI/CD, prompt user update, and resume.
4. **Ponytail 7-Rung Hierarchy**: Strictly adhere to simplicity hierarchy: `YAGNI` → `Internal Reuse` → `Standard Library` → `Native Platform` → `Existing Dependencies` → `One Line` → `Minimal Viable Code`.
5. **Two-Phase Approval**: Obtain user confirmation before executing any multi-file refactors or architectural changes.
6. **Pre-Modification Rationale**: Every code snippet or file modification must be preceded by an explanation of file purpose, reason for change, and pros/cons.
7. **Termux Local Build Invariant**: Local builds must use `fast-gradlew` exclusively. Always prompt the user between on-device build and GitHub cloud CI/CD.

---

## 3. Discovered Root Causes & Ground Truth Insights

### User Personal Note Reconciliation (Shared Data Invariant)
- **Finding:** Upstream `.mpp` archives package shared bytecode extensions (`extensions/all/*.mpe`, `extensions/shared*.mpe`), shared resources (`addresources/values-*/shared*/`), and shared patches (`patches/shared/`, `patches/all/`).
- **Previous Failure:** `compatibility.py` unconditionally discarded `all` and `shared` patches (`if app_tag in ("all", "shared", "util"): continue`). Consequently, 64 shared patch classes—including `SettingsPatchKt`, `LithoFilterPatchKt`, and `TreeNodeElementHookPatchKt`—were stripped from app bundles. Without these, no Morphe settings menus could inflate and no Litho UI suppression could occur (Problem B).
- **Extension Extraction Discrepancy:** `extract_extensions_for_app` omitted `extensions/all/` files (e.g. `change-version-code.mpe`) and failed to bundle `shared-youtube.mpe` with YouTube Music, while false-positive matching `amznmusic.mpe` for `music` (`"music" in "amznmusic"`).

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

### Phase 1: Deep `.mpp` Archive Inspection & Builder Recipe Pinpointing
- [ ] Stabilize `codexmorphe_builder/parser/mpp_archive.py`:
  - [ ] Extract universal shared extensions (`extensions/all/*.mpe`, `shared*.mpe`).
  - [ ] Accurately route `shared-youtube.mpe` to both YouTube (`com.google.android.youtube`) and YouTube Music (`com.google.android.apps.youtube.music`).
  - [ ] Fix strict package token matching (prevent `amznmusic` matching `music`).
  - [ ] Include shared resources (`shared`, `all`, `sponsorblock`, `shared-youtube`) in AAPT2 extraction.
- [ ] Stabilize `codexmorphe_builder/parser/compatibility.py`:
  - [ ] Associate shared patches (`patches/all/`, `patches/shared/`) across applicable apps instead of dropping them.
- [ ] Stabilize `codexmorphe_builder/transpiler/recipe_builder.py`:
  - [ ] Narrow `is_extension_package` to `.extension.` packages, strictly excluding `.patches.`, `.util.`, and `.patcher.`.
  - [ ] Fix NameAndType tuple index unpacking (`nat[1][0]`, `nat[1][1]`).
  - [ ] Add `0x12` / `0x13` (`ldc` / `ldc_w`) Smali instruction scanning in `ClassfileAst` methods.
  - [ ] Reject any hook whose `extension_call` has an empty method, ends with `->`, or points to non-extension classes.
  - [ ] Enforce that constructor `<init>` hooks are NEVER classified as `RETURN_TRANSFORM` (must be `AFTER`).
- [ ] Run test suite (`python3 -m unittest discover tests -v`) and verify 0 bogus hooks.

### Phase 2: Commit, Push, and Rolling Release Gate
- [ ] Commit all builder fixes with clean semantic commit messages.
- [ ] Push to `origin/main` in `codexmorphe-builder`.
- [ ] Monitor GitHub Actions workflow (`build-bundles.yml`) until completion.
- [ ] 🛑 **MANDATORY USER GATE**: Prompt user to open CodexMorphe app and tap **"Fetch / Update Bundles"** to download new bundles locally.

### Phase 3: Harden `CodexMorphe` Client Engine
- [ ] Extension Lifecycle & Initialization:
  - [ ] Ensure extension entrypoint methods (`initialize(Context)`) and Kotlin singleton objects (`INSTANCE`) are resolved dynamically in `BundleBridge.kt`.
  - [ ] Pass proper host context and set `fallbackPackageName` across static methods, fields, and singleton instances.
- [ ] Hook Execution Safety in `DexKitHookDispatcher.kt`:
  - [ ] Guard `parseExtensionCall`: ensure `method.isNotEmpty()`.
  - [ ] In `RETURN_TRANSFORM`, verify that if the hook return value is null or type-mismatched, it preserves `originalResult`.
  - [ ] In `BEFORE`, never return null for methods returning objects unless explicitly intended as suppressors.
- [ ] Verify `SharedPrefDexKitCache` / `DexKitCacheBridge` keys signatures by package name and `versionCode`.
- [ ] Prompt user between local on-device build (`fast-gradlew assembleDebug`) and GitHub cloud CI/CD.

### Phase 4: Live Verification & Diagnostics
- [ ] Install updated `CodexMorphe` APK via `adb install -r`.
- [ ] Deploy fresh AST-generated bundles to device storage.
- [ ] Stream and inspect live device logs via `pidcat`:
  - `pidcat com.google.android.youtube`
  - `pidcat com.instagram.android`
- [ ] Verify YouTube launches without `akrh.e()` NPE and Morphe menus are visible.
