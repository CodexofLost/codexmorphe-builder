# MASTER PROMPT: Deep `.mpp` Archive Inspection, CodexMorphe Dynamic Hooking Engine & Builder Stabilization

```markdown
# MISSION: End-to-End `.mpp` Inspection, Builder Recipe Pinpointing & CodexMorphe Engine Stabilization

## 1. Executive Context & System Architecture
You are tasked with resolving remaining runtime failures and inert feature states across a two-project Android hooking framework built on modern **LSPosed API 102** (`io.github.libxposed`) and **DexKit 2.3.0** (`org.luckypray:dexkit`):

1. **`codexmorphe-builder/`** (`https://github.com/CodexofLost/codexmorphe-builder.git`):
   - Transpiles upstream Morphe Patch Packs (`.mpp`) into standalone per-app `.apk` module bundles.
   - Each bundle contains MultiDex bytecode extensions (`classes.dex`, `classes2.dex`, etc.), AAPT2-compiled resources (`res/`, `AndroidManifest.xml`), and a generated `hooks.json` recipe.
   - Pushes built bundles to GitHub rolling releases via CI/CD (`build-bundles.yml`).

2. **`CodexMorphe/`** (`https://github.com/CodexofLost/CodexMorphe.git`):
   - A universal, lightweight LSPosed client engine (the module APK).
   - Dynamically fetches, verifies, and hot-loads per-app bundles via LibXposed `openRemoteFile()`, injecting MultiDex extensions, merging bundle resources via `ResourcesLoader` and `ActivityLifecycleCallbacks`, and resolving DexKit hooks at runtime.
   - Scope targets 240+ Android apps (e.g., YouTube `com.google.android.youtube`, Instagram `com.instagram.android`).

### ⚠️ NON-NEGOTIABLE ARCHITECTURAL INVARIANT: Bundle-Engine Separation
- **Bundles MUST remain completely decoupled from the Client Engine APK.**
- The client engine MUST NEVER be bloated with app-specific patch bytecode, hardcoded package hooks, or static assets for 240+ apps.
- All patch definitions, runtime extensions, AAPT2 resources, and hook recipes live exclusively inside the bundle APKs.
- When Morphe upstream updates patches, the user clicks **"Fetch / Update Bundles"** in CodexMorphe to receive OTA updates—the client engine APK itself is NOT recompiled for patch revisions.

---

## 2. Current Symptoms & Target Problems

### Problem A: YouTube Fatal Launch Crash (`akrh.e()` NPE)
YouTube (`com.google.android.youtube`) crashes during `MainActivity.onCreate` / `onStart` lifecycle dispatch with a fatal `NullPointerException`:

```text
AndroidRuntime: FATAL EXCEPTION: main
AndroidRuntime: Process: com.google.android.youtube, PID: 5515
AndroidRuntime: java.lang.RuntimeException: Unable to start activity ComponentInfo{com.google.android.youtube/com.google.android.apps.youtube.app.watchwhile.MainActivity}: java.lang.NullPointerException: Attempt to read from field 'int bfco.aN' on a null object reference in method 'baci akrh.e()'
AndroidRuntime: 	at android.app.ActivityThread.performLaunchActivity(ActivityThread.java:4654)
AndroidRuntime: 	at android.app.ActivityThread.handleLaunchActivity(ActivityThread.java:4851)
AndroidRuntime: 	at android.app.servertransaction.LaunchActivityItem.execute(LaunchActivityItem.java:242)
AndroidRuntime: 	at android.app.servertransaction.TransactionExecutor.executeNonLifecycleItem(TransactionExecutor.java:138)
AndroidRuntime: 	at android.app.servertransaction.TransactionExecutor.executeTransactionItems(TransactionExecutor.java:108)
AndroidRuntime: 	at android.app.servertransaction.TransactionExecutor.execute(TransactionExecutor.java:85)
AndroidRuntime: 	at android.app.ActivityThread$H.handleMessage(ActivityThread.java:3131)
AndroidRuntime: 	at android.os.Handler.dispatchMessage(Handler.java:115)
AndroidRuntime: 	at android.os.Looper.loopOnce(Looper.java:302)
AndroidRuntime: 	at android.os.Looper.loop(Looper.java:412)
AndroidRuntime: 	at android.app.ActivityThread.main(ActivityThread.java:9998)
AndroidRuntime: 	at java.lang.reflect.Method.invoke(Native Method)
AndroidRuntime: 	at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:613)
AndroidRuntime: 	at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1074)
AndroidRuntime: Caused by: java.lang.NullPointerException: Attempt to read from field 'int bfco.aN' on a null object reference in method 'baci akrh.e()'
AndroidRuntime: 	at akrh.e(PG:44)
AndroidRuntime: 	at akrh.a(PG:1)
AndroidRuntime: 	at arqz.s(PG:12)
AndroidRuntime: 	at jgg.x(PG:314)
AndroidRuntime: 	at jgg.nu(PG:74)
AndroidRuntime: 	at brjy.d(PG:10)
AndroidRuntime: 	at brjy.nu(PG:7)
AndroidRuntime: 	at asvv.a(PG:48)
AndroidRuntime: 	at aopg.nu(PG:818)
AndroidRuntime: 	at axnb.nu(PG:14)
AndroidRuntime: 	at asvv.c(PG:3)
AndroidRuntime: 	at abxa.nu(PG:68)
AndroidRuntime: 	at axnb.nu(PG:14)
AndroidRuntime: 	at akgr.c(PG:3)
AndroidRuntime: 	at kqt.p(PG:31)
AndroidRuntime: 	at jdk.n(PG:32)
AndroidRuntime: 	at jdk.nu(PG:102)
AndroidRuntime: 	at brjy.d(PG:10)
AndroidRuntime: 	at brjy.nu(PG:7)
AndroidRuntime: 	at jdl.fs(PG:3)
AndroidRuntime: 	at jdk.e(PG:1259)
AndroidRuntime: 	at jdk.nu(PG:62)
AndroidRuntime: 	at brkg.nu(PG:14)
AndroidRuntime: 	at jdk.c(PG:2320)
AndroidRuntime: 	at jdk.nu(PG:112)
AndroidRuntime: 	at brkg.nu(PG:14)
AndroidRuntime: 	at brjx.nu(PG:5)
AndroidRuntime: 	at jdl.dN(PG:61)
AndroidRuntime: 	at jdl.fd(PG:1)
AndroidRuntime: 	at jdk.c(PG:2381)
AndroidRuntime: 	at jdk.nu(PG:112)
AndroidRuntime: 	at brkg.nu(PG:14)
AndroidRuntime: 	at jdl.dL(PG:21)
AndroidRuntime: 	at jdk.c(PG:2452)
AndroidRuntime: 	at jdk.nu(PG:112)
AndroidRuntime: 	at brkg.nu(PG:14)
AndroidRuntime: 	at brjx.nu(PG:5)
AndroidRuntime: 	at jdk.c(PG:2605)
AndroidRuntime: 	at jdk.nu(PG:112)
AndroidRuntime: 	at brjx.nu(PG:5)
AndroidRuntime: 	at jdk.n(PG:33)
AndroidRuntime: 	at jdk.nu(PG:102)
AndroidRuntime: 	at qer.<init>(PG:26)
AndroidRuntime: 	at qer.<init>(PG:118)
AndroidRuntime: 	at jdk.n(PG:43)
AndroidRuntime: 	at jdk.nu(PG:102)
AndroidRuntime: 	at brjy.d(PG:10)
AndroidRuntime: 	at brjy.nu(PG:7)
AndroidRuntime: 	at npb.s(PG:17)
AndroidRuntime: 	at jdk.n(PG:43)
AndroidRuntime: 	at jdk.nu(PG:102)
AndroidRuntime: 	at brjy.d(PG:10)
AndroidRuntime: 	at brjy.nu(PG:7)
AndroidRuntime: 	at brjx.nu(PG:5)
AndroidRuntime: 	at brjy.d(PG:10)
AndroidRuntime: 	at brjy.nu(PG:7)
AndroidRuntime: 	at ret.run(PG:213)
AndroidRuntime: 	at afmp.run(PG:40)
AndroidRuntime: 	at afmr.i(PG:91)
AndroidRuntime: 	at com.google.android.apps.youtube.app.watchwhile.MainActivity.onCreate(PG:148)
```

**Root Cause Hypothesis:** An over-broad hook in `hooks.json` (such as `RETURN_TRANSFORM`, `REPLACE`, or `ARG_REWRITE` targeting an obfuscated method or constructor invoked during dependency injection) returns `null` or replaces a critical host object, causing `baci akrh.e()` to attempt reading `bfco.aN` from a `null` reference.

### Problem B: Inert Features in Apps Running Stock
Apps that launch without crashing (e.g. Instagram `com.instagram.android`) load without their patched features active:
- No Morphe settings menu appears.
- Custom UI modifications or suppressions do not take effect.
- The app operates as if unmodified (stock behavior).

**Root Cause Hypothesis:** Either:
1. Extension initializers (`initialize()`, `main()`, or package-level init methods) are not invoked with the proper Android `Context` / `ClassLoader`.
2. Fingerprints are failing to resolve in DexKit, causing critical patches to be skipped.
3. Injected bundle resources (strings, drawables, layout IDs) are not accessible to the app's components due to missing ID mappings or package namespace mismatch (`ResourceUtils.fallbackPackageName`).

---

## 3. Upstream Ground Truth: How Morphe Patcher & Manager Work

To resolve these issues, you must understand how upstream **Morphe Patcher** (`https://github.com/MorpheApp/morphe-patcher`) and **Morphe Manager** (`https://github.com/MorpheApp/morphe-manager`) use `.mpp` files:

1. **Static AST & Bytecode Splicing (`dexlib2`):**
   - Morphe Manager does NOT use Xposed or DexKit. It decompiles the target APK offline into Dalvik bytecode (`smali`), parses `.mpp` fingerprints against all classes in the APK using AST pattern matching, and physically edits instructions (e.g. inserting `invoke-static` calls to extension methods directly into the host APK).
   - Because it patches bytecode directly, it replaces exact instruction blocks at precise offsets.
2. **Extensions (`.mpe`):**
   - Extensions are standalone DEX files containing the patch logic (e.g. `app.morphe.extension.*`). In offline patching, Morphe Manager merges these classes into the APK's `classes.dex` or adds a new `classesN.dex`.
3. **Fingerprint Resolution:**
   - In `.mpp` files, fingerprints (`*Fingerprint.class`) describe the target method using:
     - Specific string constants accessed by the method (`strings`).
     - Numeric literals (`numbers`).
     - Opcode instruction sequences (`opcodes`).
     - Parameter types and return types.
4. **Our Dynamic LSPosed/DexKit Approach:**
   - We do NOT modify target APKs on disk. We load `.mpe` DEX files via `DexClassLoader` into the running process and use DexKit to find the exact same methods at runtime, then hook them using LibXposed (`hookBefore`, `hookAfter`, `hookReplace`).
   - If our translation from `.mpp` fingerprints to DexKit queries is too loose, we hook the wrong methods and crash the app. If it is too strict or lacks proper parameter matching, it finds nothing and features stay inert.

---

## 4. Phase-by-Phase Execution Plan

### Phase 0: Requirements Tracker Artifact
- **Action:** Maintain `.agents/requirements-and-goals.md` before taking action. Record all active goals, constraints, and verifiable deliverables. Update this artifact as each milestone is achieved.

### Phase 1: Deep `.mpp` Archive Inspection & Builder Recipe Pinpointing
1. **Exhaustive Inspection of `.mpp` Files:**
   - Extract sample `.mpp` files (`official.mpp`, `hushgram.mpp`, `piko.mpp` in `.cache/mpp/`).
   - Decompile and inspect:
     - `classes.dex`: Inspect every `*Fingerprint.class`, `*Patch.class`, and annotation metadata.
     - `extensions/*.mpe`: Decompile extension classes (`jadx`) to understand how extension methods interact with host methods.
     - `res/`, `values/strings.xml`, `AndroidManifest.xml`: Verify all injected resources.
     - `manifest.json`: Map declared patch options and dependencies.
2. **Trace the YouTube Crash (`akrh.e()`):**
   - Search the generated `hooks.json` for YouTube (`dist/` or `.cache/tmp/`) for every hook matching methods involved in the crash stack (`MainActivity.onCreate`, `afmr`, `ret`, `jdk`, `qer`, `jdl`, `brjy`, `akrh`).
   - Identify which hook replaced, suppressed, or returned null in these classes, and fix its fingerprint or method matching.
3. **Trace Inert Features (Instagram & Others):**
   - Inspect extension entrypoints: Look for `@ExtensionEntrypoint`, `initialize()`, or methods annotated with `@Patch`.
   - Ensure `recipe_builder.py` emits:
     - Explicit initializers to be invoked on app start.
     - Correct parameter types (`param_types`) and return types (`return_type`).
     - Pinpointed method names and string discriminators.
4. **Run Builder Unit Tests:**
   - Run `python3 -m unittest discover tests -v` in `codexmorphe-builder`.
   - Verify generated `hooks.json` files have zero unconstrained queries and zero invalid class hooks.

### Phase 2: Commit, Push, and Rolling Release Gate
1. Commit all builder fixes to `codexmorphe-builder` and push to `origin/main`.
2. Monitor GitHub Actions (`gh run watch` or `gh run list`) until `build-bundles.yml` completes successfully and publishes updated bundle APKs.
3. 🛑 **MANDATORY USER GATE:** Once the workflow finishes, **STOP and ask the user to open the CodexMorphe app on their device and tap "Fetch / Update Bundles"** to download the new bundles locally before running the app. Never test against stale bundles!

### Phase 3: Harden `CodexMorphe` Client Engine
1. **Extension Lifecycle & Initialization:**
   - In `BundleBridge.kt`, ensure extension entrypoint methods (e.g. `initialize(Context)`) are invoked on host `Application.onCreate` with proper host context and `ResourceUtils.fallbackPackageName` set.
2. **Hook Execution Safety:**
   - In `DexKitHookDispatcher.kt`:
     - In `RETURN_TRANSFORM`, verify that if the hook return value is null or type-mismatched, it preserves `param.result` rather than corrupting host dependency injection.
     - In `ARG_REWRITE`, ensure argument array lengths and types match expected parameters.
3. **DexKit Cache Verification:**
   - Ensure `SharedPrefDexKitCache` correctly keys signatures by app package name and `versionCode`.
4. **Build Prompt:**
   - Prompt the user between local on-device build (`fast-gradlew assembleDebug`) and GitHub cloud CI/CD (`gh workflow run`).

### Phase 4: Live Verification & Diagnostics
1. Install updated `CodexMorphe` APK via `adb install -r`.
2. Stream color-coded logs using `pidcat`:
   - `pidcat com.google.android.youtube`
   - `pidcat com.instagram.android`
3. Verify:
   - YouTube launches without any `NullPointerException` in `akrh.e()` or `aiat.e()`.
   - Instagram and YouTube display active Morphe features/menus.

---

## 5. ⚠️ STRICT INVARIANT: Phase Backpropagation Protocol
If at any point during later phases (e.g., Phase 3 engine work or Phase 4 live testing) you discover that:
- A fingerprint pattern in `recipe_builder.py` is wrong.
- A hook recipe needs an additional field or different action type.
- An extension entrypoint was missed during bundle compilation.

**You MUST follow this backpropagation protocol:**
1. **Update Tracker Artifact:** Add the newly discovered requirement to `.agents/requirements-and-goals.md`.
2. **Step Back to Previous Phase:** Modify the builder code in `codexmorphe-builder/`.
3. **Execute Full Pipeline:**
   - Run unit tests in `codexmorphe-builder`.
   - Commit and push to GitHub `origin/main`.
   - Wait for GitHub Actions `build-bundles.yml` to successfully build and publish.
   - **Enforce User Gate:** Prompt the user to tap **"Fetch / Update Bundles"** in CodexMorphe.
4. **Resume Later Phases:** Only resume testing the client engine once the updated bundles are fetched locally. Never test changes against mismatched or stale bundle artifacts!

---

## 6. Operating Rules & Termux Environment Constraints
- **Host Environment:** Termux on Android (`linux-aarch64`).
- **Compilation:** Always use `fast-gradlew` for local compilation. Never run `./gradlew` or `sh gradlew`.
- **Pre-Modification Rationale:** Before presenting any code snippet or editing a file, always explain what the target file is for, the specific reason for the change, and provide a clear breakdown of pros and cons.
- **Simplicity Hierarchy (Ponytail):** Adhere to `YAGNI` → `Internal Reuse` → `Standard Library` → `Native Platform` → `Existing Dependencies`.
```
