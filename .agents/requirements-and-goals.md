# Requirements Tracker: CodexMorphe & Builder Fix Session

## 1. Executive Mission & Target End-State
Resolve critical integration failures across the two-project framework:
1. **`codexmorphe-builder`**:
   - Transpile upstream Morphe Patch Packs (`.mpp`) into clean, pinpointed, per-app module bundles (`.apk`).
   - Fix recipe generation in `recipe_builder.py` so no unconstrained/wildcard DexKit queries or misnamed constructor hooks are emitted.
   - Publish updated bundles via GitHub Actions rolling releases (`build-bundles.yml`).
2. **`CodexMorphe`**:
   - Universal, lightweight LSPosed API 102 client engine.
   - Injects bundle resources into both `Application` and `Activity` contexts (`onActivityCreated`, `onActivityResumed`) via `ActivityLifecycleCallbacks`.
   - Protects Dalvik execution with DexKit query guards rejecting unconstrained queries.
   - Implements persistent DexKit caching via `DexKitCacheBridge` / SharedPreferences keyed by target app `versionCode` to prevent main-thread freeze.
   - Dynamically initializes `ResourceUtils.fallbackPackageName` and target package context before invoking extension initializers.

---

## 2. Architectural Invariants & Constraints
- **Strict Engine-Bundle Decoupling**: Zero patch bytecode, app hooks, or static assets baked into `CodexMorphe.apk`. All live in per-app bundle APKs.
- **Fast OTA Updates**: Upstream patches trigger bundle recompilation & upload to GitHub release. The user updates by tapping "Fetch / Update Bundles" in CodexMorphe—client engine is not updated for patch revisions.
- **Termux Environment**: Always compile local Android builds with `fast-gradlew`. Never run `./gradlew`.
- **Pre-Build User Prompt**: Always ask user to choose between local (`fast-gradlew`) and cloud CI/CD (`gh workflow run`) before starting a build.
- **Two-Phase Approval**: Explain target files, reasons for changes, pros and cons before modifying files.

---

## 3. Discovered Root Causes & Target Fixes

| ID | Component | Defect / Failure Mode | Root Cause | Target Fix | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RC-1** | `codexmorphe-builder` | YouTube crash (NPE in `aiat.e()`), Instagram flooded with `Type mismatch in RETURN_TRANSFORM` | Path B emitted hooks with `declaring_class` but null `method_name` & empty `strings`. DexKit matched all methods in class. | Reject/constrain rules lacking `method_name`, unique `strings`, or `param_types`. | ✅ RESOLVED |
| **RC-2** | `codexmorphe-builder` | Constructor hooks fail to match DexKit query | Fingerprints ending in `Constructor` left `method_name` as null instead of `"<init>"`. | Explicitly assign `method_name: "<init>"` for constructor fingerprints. | ✅ RESOLVED |
| **RC-3** | `CodexMorphe` | Activities throw `ResourceNotFoundException` or show stock UI | `BundleResourceInjector` only injected into `Application.resources`. Activity contexts hold separate `Resources`. | Hook `registerActivityLifecycleCallbacks` on `app` to call `addModuleAssets` on `onActivityCreated` & `onActivityResumed`. | ⏳ PENDING |
| **RC-4** | `CodexMorphe` | 10–20s launch freeze / ANR risk on app boot | Main-thread DexKit re-scanning hundreds of methods during `Application.onCreate`. | Implement `DexKitCacheBridge` backed by SharedPreferences keyed by package & `versionCode`. | ⏳ PENDING |
| **RC-5** | `CodexMorphe` | Morphe settings/layouts cannot look up host resource IDs | `ResourceUtils.fallbackPackageName` uninitialized. | Dynamically set `fallbackPackageName = app.packageName` via reflection on bundle attach. | ⏳ PENDING |

---

## 4. Phase Breakdown & Execution Milestones

- [x] **Phase 0: Requirements Tracker Artifact**
  - [x] Create `.agents/requirements-and-goals.md`
- [x] **Phase 1: Fix `codexmorphe-builder`**
  - [x] Inspect upstream `.mpp` files directly
  - [x] Harden `recipe_builder.py` against wildcard hooks
  - [x] Ensure constructor fingerprints assign `"<init>"`
  - [x] Extract exact parameters and return types
  - [x] Run unit tests (`test_recipe_builder.py`, `test_ast_transpiler.py` - 14/14 passed)
- [x] **Phase 2: Commit, Push, and Rolling Release Gate**
  - [x] Commit builder changes & push to `origin/main` (commits `13a8f5c`, `583787d`, `088af56`)
  - [x] Trigger GitHub Actions `build-bundles.yml` (Run #41082257038 succeeded in 8m30s)
  - [ ] 🛑 **CRITICAL USER GATE**: User taps "Fetch / Update Bundles" in CodexMorphe to download new bundles locally
- [x] **Phase 3: Harden `CodexMorphe` Client Engine & Absolute Decoupling**
  - [x] Remove all hardcoded author package names (`app.hushgram`, `app.piko`, etc.) across `BundleBridge.kt`, `DexKitHookDispatcher.kt`, and `ExtensionClassLoading.kt`
  - [x] Dynamic entrypoint and resource fallback resolution via `manifest.entrypoints` and `manifest.resourceFallbacks`
  - [x] Activity-level resource injection via `ActivityLifecycleCallbacks` (`onActivityCreated`, `onActivityResumed`)
  - [x] DexKit query guard & discriminator safety (reject unconstrained class matching)
  - [x] DexKit signature caching (`DexKitCacheBridge` / SharedPreferences keyed by package & `versionCode`)
  - [x] On-Device compilation (`fast-gradlew assembleDebug` succeeded) and APK installed via ADB
- [ ] **Phase 4: Verification & Live Diagnostics**
  - [ ] 🛑 **CRITICAL USER GATE**: User taps "Fetch / Update Bundles" in CodexMorphe app
  - [ ] Launch YouTube and Instagram
  - [ ] Stream logs via `pidcat com.google.android.youtube` and `pidcat com.instagram.android`
  - [ ] Confirm crash-free launch and Morphe modded UI inflation
  - [ ] Install updated `CodexMorphe` APK via `adb` or `rish`
  - [ ] Stream logs via `pidcat com.google.android.youtube` and `pidcat com.instagram.android`
  - [ ] Confirm crash-free launch and Morphe modded UI inflation
