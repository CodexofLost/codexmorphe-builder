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
| **RC-3** | `CodexMorphe` | Activities throw `ResourceNotFoundException` or show stock UI | `BundleResourceInjector` only injected into `Application.resources`. Activity contexts hold separate `Resources`. | Hook `registerActivityLifecycleCallbacks` on `app` to call `addModuleAssets` on `onActivityCreated` & `onActivityResumed`. | ✅ RESOLVED |
| **RC-4** | `CodexMorphe` | 10–35s launch freeze / ANR on app boot (splash stuck) | Main-thread DexKit re-scanning 1,125 methods during `Application.onCreate` blocks UI looper, triggering AMS 5s input and 10s broadcast ANR watchdogs. | Asynchronous background DexKit worker + Direct reflection fast path + Batched SharedPreferences cache. | 🔄 IN PROGRESS |
| **RC-5** | `CodexMorphe` | Morphe settings/layouts cannot look up host resource IDs | `ResourceUtils.fallbackPackageName` uninitialized. | Dynamically set `fallbackPackageName = app.packageName` via reflection on bundle attach. | ✅ RESOLVED |

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
  - [x] Commit builder changes & push to `origin/main` (commits `13a8f5c`, `583787d`, `088af56`, `b680836`, `852cb3c`)
  - [x] Trigger GitHub Actions `build-bundles.yml` (Runs #41090022395 and #41082257038 succeeded)
  - [x] User tapped "Fetch / Update Bundles" in CodexMorphe to download new bundles locally
- [x] **Phase 3: Harden `CodexMorphe` Client Engine & Absolute Decoupling**
  - [x] Remove all hardcoded author package names (`app.hushgram`, `app.piko`, etc.) across `BundleBridge.kt`, `DexKitHookDispatcher.kt`, and `ExtensionClassLoading.kt`
  - [x] Dynamic entrypoint and resource fallback resolution via `manifest.entrypoints` and `manifest.resourceFallbacks`
  - [x] Activity-level resource injection via `ActivityLifecycleCallbacks` (`onActivityCreated`, `onActivityResumed`)
  - [x] DexKit query guard & discriminator safety (reject unconstrained class matching)
  - [x] On-Device compilation (`fast-gradlew assembleDebug` succeeded) and APK installed via ADB
- [ ] **Phase 4: Resolve Main-Thread Freeze & ANR (Cold Boot Optimization)**
  - [x] Reproduce and record logcat on-device for YouTube and Instagram during freeze/ANR
  - [x] Capture exact AMS stack trace: `Broadcast of Intent ... timed out at org.luckypray.dexkit.DexKitBridge.nativeFindMethod`
  - [ ] Implement Direct Reflection Fast Path in `DexKitHookDispatcher` for known classes (e.g. `MainActivity.onCreate`)
  - [ ] Implement Asynchronous Background Worker Thread for uncached DexKit bytecode analysis
  - [ ] Eliminate expensive multi-string fallback loops across full APK in `queryMethods`
  - [ ] Batch SharedPreferences writes to avoid disk sync stalls
  - [ ] Verify instant, freeze-free startup on both Instagram and YouTube via live diagnostics

---

## 5. Live ANR Diagnostic Evidence

### YouTube ANR Trace (`com.google.android.youtube`):
```text
AnrInfo{reason='Broadcast Timeout', message='Broadcast of Intent { act=android.intent.action.BOOT_COMPLETED flg=0x9000030 pkg=com.google.android.youtube cmp=com.google.android.youtube/androidx.work.impl.background.systemalarm.RescheduleReceiver }',
stackTrace='
  at org.luckypray.dexkit.DexKitBridge.nativeFindMethod(Native method)
  at org.luckypray.dexkit.DexKitBridge.access$nativeFindMethod(DexKitBridge.kt:56)
  at org.luckypray.dexkit.DexKitBridge$Companion.nativeFindMethod(unavailable:0)
  at org.luckypray.dexkit.DexKitBridge.findMethod(DexKitBridge.kt:437)
  at io.github.codexoflost.codexmorphe.hook.DexKitHookDispatcher.queryMethods(DexKitHookDispatcher.kt:292)
  at io.github.codexoflost.codexmorphe.hook.DexKitHookDispatcher.bindDynamicHooksWithCache(DexKitHookDispatcher.kt:180)
  at io.github.codexoflost.codexmorphe.hook.DexKitHookDispatcher.dispatch(DexKitHookDispatcher.kt:79)
  at io.github.codexoflost.codexmorphe.hook.MainHook.onPackageReady$lambda$14(MainHook.kt:116)'}
```

### Instagram ANR Capture (`com.instagram.android`):
```text
mCurrentFocus=Window{76e7af5 u0 Application Not Responding: com.instagram.android}
```
**Mechanism:** 116 DexKit queries run synchronously inside `Application.onCreate` on the UI thread, blocking Android's main looper past the 5-second AMS input dispatch threshold.
