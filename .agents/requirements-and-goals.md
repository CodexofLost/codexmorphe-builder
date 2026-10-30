# Requirements & Goals Tracker: Deep .mpp Archive Inspection, Recipe Pinpointing & Engine Stabilization

## 1. Executive Summary & Mission Objective
Resolve remaining runtime failures and inert feature states across the two-project framework:
- **`codexmorphe-builder`**:
  - Transpiles upstream Morphe Patch Packs (`.mpp`) into standalone per-app `.apk` module bundles containing MultiDex extensions, AAPT2 resources, and generated `hooks.json` recipes.
  - Fix over-broad hooks, pinpoint method/fingerprint matches causing YouTube's `akrh.e()` NPE crash, and ensure extension entrypoints and resource mappings are accurately emitted so features are active.
  - Publish updated bundles via GitHub rolling release (`build-bundles.yml`).
- **`CodexMorphe` Client Engine**:
  - Universal, lightweight LSPosed client engine (API 102).
  - Dynamically fetches, verifies, and hot-loads per-app bundles via LibXposed `openRemoteFile()`, injecting MultiDex extensions, merging bundle resources via `ResourcesLoader` and `ActivityLifecycleCallbacks`, and resolving DexKit hooks at runtime.
  - Harden `DexKitHookDispatcher` (prevent `RETURN_TRANSFORM` null-returns on critical host types, validate `ARG_REWRITE`), verify `BundleBridge` extension lifecycle invocation, and ensure persistent DexKit signature caching.

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

## 3. Phased Deliverables & Milestone Status

### Phase 0: Requirements Tracker Artifact
- [x] Create and maintain `.agents/requirements-and-goals.md` across both repositories.

### Phase 1: Deep `.mpp` Archive Inspection & Builder Recipe Pinpointing
- [x] Inspect sample `.mpp` archives (`official.mpp`, `hushgram.mpp`, `piko.mpp`, `okish.mpp`, `devanced.mpp`, `rushiranpise.mpp` in `.cache/mpp/`):
  - [x] Inspected `classes.dex` and JVM classfiles across all 6 sources (~2,400 fingerprints).
  - [x] Discovered `Fingerprint.<init>` constructor overloads and `BootstrapMethods` Smali templates.
  - [x] Uncovered the exact root cause of the YouTube `akrh.e()` NPE: 94 unconstrained `RETURN_TRANSFORM` hooks matching `'this'` and unconstrained wildcards due to regex guessing and `available_ext_calls[0]`.
- [x] Implement AST / Bytecode Structural Transpiler in `codexmorphe-builder`:
  - [x] Replaced regex heuristics in `recipe_builder.py` with `ClassfileAst` and symbolic JVM bytecode stack evaluator.
  - [x] Extracted exact Smali templates from `BootstrapMethods` and bound `Fingerprint.INSTANCE` directly to extension methods.
  - [x] Enforced strict type compatibility and eliminated unconstrained wildcards (0 unconstrained hooks, 0 `"this"` strings).
- [x] Add AST verification test suite in `tests/test_ast_transpiler.py` testing against all 6 `.mpp` archives (16/16 tests passing).
- [x] Verified end-to-end bundling: Built `com.google.android.youtube-official-bundle.apk` and confirmed clean `hooks.json`.

### Phase 2: Commit, Push, and Rolling Release Gate
- [ ] Commit all builder fixes with clean semantic commit messages.
- [ ] Push to `origin/main` in `codexmorphe-builder`.
- [ ] Monitor GitHub Actions workflow (`build-bundles.yml`) until completion.
- [ ] 🛑 **MANDATORY USER GATE**: Prompt user to open CodexMorphe app and tap **"Fetch / Update Bundles"** to download new bundles locally.

### Phase 3: Harden `CodexMorphe` Client Engine
- [ ] Extension Lifecycle & Initialization:
  - [ ] Ensure extension entrypoint methods (`initialize(Context)`) are invoked on `Application.onCreate` with proper host context and `ResourceUtils.fallbackPackageName`.
- [ ] Hook Execution Safety in `DexKitHookDispatcher.kt`:
  - [ ] In `RETURN_TRANSFORM`, verify that if the hook return value is null or type-mismatched, it preserves `param.result` rather than corrupting host dependency injection.
  - [ ] In `ARG_REWRITE`, ensure argument array lengths and types match expected parameters.
- [ ] Verify `SharedPrefDexKitCache` / `DexKitCacheBridge` keys signatures by package name and `versionCode`.
- [ ] Prompt user between local on-device build (`fast-gradlew assembleDebug`) and GitHub cloud CI/CD.

### Phase 4: Live Verification & Diagnostics
- [ ] Install updated `CodexMorphe` APK via `adb install -r`.
- [ ] Stream color-coded logs via `pidcat`:
  - `pidcat com.google.android.youtube`
  - `pidcat com.instagram.android`
- [ ] Verify:
  - YouTube launches cleanly without NPE in `akrh.e()`.
  - Instagram and YouTube have active Morphe features and settings menus.
