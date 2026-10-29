# codexmorphe-builder

An automated build tool and CI engine that ingests Morphe Patch Packages (`.mpp`), strips non-root redundant shims, transpiles bytecode mutations into native DexKit/LibXposed hooks, and compiles isolated, per-app runtime bundles (`<packageName>-<provider>-bundle.apk`) for the **CodexMorphe** LSPosed engine.

---

## Key Features

* **Zero-Recipe Universal AST Transpiler:** Automatically translates Morphe bytecode transformations into native DexKit queries and LibXposed hooks with 0 manual intervention across 5 deterministic hook patterns.
* **Isolated Per-App Bundles:** Generates lightweight, app-specific APK payloads instead of one giant monolithic bundle.
* **Decoupled Source Registry:** Modular repository descriptors in `sources/*.json`. Anyone can submit a Pull Request to add their patch repository with zero merge conflicts!
* **Multi-Provider Flavoring:** When multiple repositories support the same application (e.g., [HushGram](https://github.com/SysAdminDoc/HushGram) and [Piko](https://github.com/crimera/piko) both targeting Instagram), independent flavored bundles are emitted, and users can select their preferred provider in the CodexMorphe client.
* **Root Redundancy Filtering:** Automatically drops `GmsCore`, microG redirections, package cloning, and APK signature spoofing patches that are redundant on genuine Google Play Store apps under LSPosed.
* **Bandwidth & CI Efficient:** Tracks releases via `.cache/build-ledger.json` using GitHub API ETags and SHA256 checksums to avoid redundant rebuilds.

---

## Adding Your Repository (Community Pull Requests)

To add your patch repository to `codexmorphe-builder`, you only need to create a single JSON file under `sources/` and open a PR:

1. Fork this repository.
2. Create `sources/<your-repo-name>.json` with the following format:

```json
{
  "id": "myrepo",
  "name": "My Custom Patches",
  "type": "github_release",
  "repository": "myusername/my-morphe-patches",
  "asset_pattern": ".*\\.mpp$",
  "include_prerelease": false,
  "priority": 80,
  "enabled": true,
  "description": "Custom patches for popular apps."
}
```

3. Submit your Pull Request. Our CI automatically validates the JSON schema, fetches your `.mpp` package, runs the AST validator, and catalogs your supported applications!

---

## Quickstart & CLI Commands

### Prerequisites
* Python 3.10+
* Android SDK `d8` (in `PATH` or configured via `ANDROID_HOME` / `config.py`)
* `aapt2` (in `PATH` or SDK build-tools)
* OpenJDK 17 or 21

### Commands

```bash
# 1. Fetch latest .mpp releases from all configured sources
python3 -m codexmorphe_builder fetch

# 2. List all configured sources and their cached status
python3 -m codexmorphe_builder list

# 3. Build bundles for all discovered applications across all sources
python3 -m codexmorphe_builder build --all

# 4. Build bundle for a specific package only
python3 -m codexmorphe_builder build --app com.google.android.youtube

# 5. Build bundle for a specific provider only
python3 -m codexmorphe_builder build --source hushgram

# 6. Run the automated AST transpiler test suite
pytest tests/ -v
```

---

## License
Licensed under GPL-3.0.
