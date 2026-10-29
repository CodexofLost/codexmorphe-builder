import subprocess
from pathlib import Path
from typing import Optional
from ..config import AAPT2_BIN


DUMMY_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">
    <application android:hasCode="true" />
</manifest>
"""


def compile_resources(
    res_dir: Path,
    package_name: str,
    output_dir: Path,
    android_jar: Optional[Path] = None
) -> Optional[Path]:
    """
    Compile and link Android XML resources into an APK container containing resources.arsc.
    """
    if not AAPT2_BIN:
        print("[WARN] aapt2 binary not found. Skipping binary resource linking.")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "AndroidManifest.xml"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(DUMMY_MANIFEST.format(package_name=package_name))

    compiled_zip = output_dir / "compiled_res.zip"
    out_apk = output_dir / "resources.apk"

    if res_dir.exists() and any(res_dir.iterdir()):
        # Step 1: aapt2 compile
        compile_cmd = [
            str(AAPT2_BIN), "compile",
            "--dir", str(res_dir),
            "-o", str(compiled_zip)
        ]
        res = subprocess.run(compile_cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[WARN] aapt2 compile error: {res.stderr}")
            return None

        # Step 2: aapt2 link
        link_cmd = [
            str(AAPT2_BIN), "link",
            "-o", str(out_apk),
            "--manifest", str(manifest_path),
            str(compiled_zip)
        ]
        if android_jar and android_jar.exists():
            link_cmd.extend(["-I", str(android_jar)])

        res_link = subprocess.run(link_cmd, capture_output=True, text=True)
        if res_link.returncode == 0 and out_apk.exists():
            return out_apk

    return None
