# Requirements & Goals Tracker: CodexMorphe & Builder Fix Session

## 1. Executive Summary & Objective
Resolve the critical integration failure across the two-project framework:
- **`codexmorphe-builder`**: Fix hook recipe generation to eliminate unconstrained wildcard queries, properly type constructors, extract strict parameter/return types, and publish verified bundles via CI/CD.
- **`CodexMorphe` Client Engine**: Harden the LSPosed client engine with Activity-level resource injection, runtime DexKit query guards, persistent signature caching (`DexKitCacheBridge`), and `ResourceUtils.fallbackPackageName` initialization.

---

## 2. Active Architectural Constraints & Invariants
1. **Engine-Bundle Separation**: Zero app-specific patch bytecode, hardcoded package hooks, or static assets in the client engine APK. All patch logic lives in standalone bundle APKs.
2. **Deterministic & Strict DexKit Matching**: No query may execute without at least a `method_name`, non-empty `strings`, or `param_types`. Wildcard queries on classes are strictly prohibited.
3. **Constructor Explicit Typing**: Fingerprints targeting constructors must use `method_name: "<init>"` and `return_type: "void"`.
4. **Activity Resource Integrity**: Injected bundle drawables, layouts, and strings must be attached to Activity instances via `ActivityLifecycleCallbacks` (`onActivityCreated` and `onActivityResumed`) in addition to `Application`.
5. **OTA Rolling Release Gate**: Client engine testing must never occur against stale bundles. CI/CD must build and publish bundles, followed by user bundle fetch in CodexMorphe before verification.
6. **Termux Build Invariant**: All local builds must use `fast-gradlew`. Always prompt user between local build and GitHub CI/CD before initiating compilation.

---

## 3. Phased Deliverables & Milestone Status

### Phase 0: Requirements Tracker Artifact
- [x] Create `.agents/requirements-and-goals.md` and track execution state.

### Phase 1: Fix `codexmorphe-builder`
- [x] Inspect existing `recipe_builder.py` and unit test harness.
- [x] Implement query guard in `recipe_builder.py` (reject hooks lacking `method_name`, `strings`, or `literal`).
- [x] Assign `method_name: "<init>"` and `return_type: "void"` for constructor fingerprints (`*Constructor.class`).
- [x] Enhance parameter and return type extraction from Morphe bytecode/AST annotations.
- [x] Validate generated `hooks.json` schema (`param_types`, `return_type`, `action`, `extension_class`).
- [x] Run automated unit tests (`python3 -m unittest discover tests -v`) and verify YouTube / Instagram recipes.

### Phase 2: Commit, Push, and Rolling Release Gate
- [x] Commit builder changes with clean semantic commit message (`789a8f1`).
- [x] Push to `origin/main` in `codexmorphe-builder`.
- [x] Monitor GitHub Actions workflow (`build-bundles.yml`, run `41110320818`) to completion (Success in 7m33s).
- [ ] 🛑 **USER GATE**: Prompt user to open CodexMorphe app and tap **"Fetch / Update Bundles"**.

### Phase 3: Harden `CodexMorphe` Client Engine
- [x] Implement Activity-level resource injection in `BundleResourceInjector.kt` via `ActivityLifecycleCallbacks`.
- [x] Add runtime DexKit query guard in `DexKitHookDispatcher.kt`.
- [x] Implement `DexKitCacheBridge` with `SharedPreferences` keyed by package name and `versionCode`.
- [x] Set `ResourceUtils.fallbackPackageName` and target package context before invoking extension initializers.
- [ ] Build client APK (prompting user: local `fast-gradlew` vs GitHub Actions).

### Phase 4: Verification & Live Diagnostics
- [ ] Install updated `CodexMorphe` APK via `adb install -r` or Shizuku (`rish`).
- [ ] Run live diagnostics via `pidcat com.google.android.youtube` and `pidcat com.instagram.android`.
- [ ] Verify clean launch without NPEs, type mismatch errors, or resource inflation exceptions.

### Dead Code Cleanup (`codexmorphe-builder`)
- [ ] Present audit findings and detailed plan (pros/cons, removal rationale) to user.
- [ ] Remove unused `d8_merger.py` and uncalled `MppArchive.extract_file()`.
- [ ] Remove dead static Kotlin generator prototype (`classifier.py`, `fingerprint.py`, `generator.py`, `test_ast_transpiler.py`).
- [ ] Remove dead imports across 8 files and orphaned `PatchCatalogItem`.
- [ ] Re-run unit tests and commit cleanup.
