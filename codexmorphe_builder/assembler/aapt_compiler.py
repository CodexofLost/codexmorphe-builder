import re
import subprocess
from pathlib import Path
from typing import Dict, Optional, Set, Tuple
from ..config import AAPT2_BIN, ANDROID_JAR


DUMMY_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">
    <application android:hasCode="false" />
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
    Uses an iterative placeholder resolver to synthesize host application symbols
    (e.g. yt_white1, robotoFont) that are referenced in Morphe layouts/drawables.
    """
    if not AAPT2_BIN:
        print("[WARN] aapt2 binary not found. Skipping binary resource linking.")
        return None

    jar = android_jar or ANDROID_JAR
    if not jar or not jar.exists():
        print("[WARN] android.jar not found. Skipping binary resource linking.")
        return None

    if not res_dir.exists() or not any(res_dir.iterdir()):
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "AndroidManifest.xml"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(DUMMY_MANIFEST.format(package_name=package_name))

    compiled_zip = output_dir / "compiled_res.zip"
    out_apk = output_dir / "resources.apk"

    # Ensure values directory exists for placeholder declarations
    values_dir = res_dir / "values"
    values_dir.mkdir(parents=True, exist_ok=True)
    dummy_file = values_dir / "dummy_host_placeholders.xml"

    known_placeholders: Set[Tuple[str, str]] = set()

    for iteration in range(6):
        # 1. Write current placeholders if any
        if known_placeholders:
            lines = ['<resources>']
            for res_type, res_name in sorted(known_placeholders):
                if res_type == "attr":
                    lines.append(f'    <attr name="{res_name}" format="string|reference|color|dimension|boolean|integer" />')
                elif res_type == "color":
                    lines.append(f'    <color name="{res_name}">#000000</color>')
                elif res_type == "dimen":
                    lines.append(f'    <dimen name="{res_name}">0dp</dimen>')
                elif res_type == "string":
                    lines.append(f'    <string name="{res_name}">dummy</string>')
                elif res_type == "drawable":
                    lines.append(f'    <drawable name="{res_name}">#000000</drawable>')
                elif res_type == "style":
                    lines.append(f'    <style name="{res_name}" />')
                elif res_type == "id":
                    lines.append(f'    <item type="id" name="{res_name}" />')
                else:
                    lines.append(f'    <item type="{res_type}" name="{res_name}" />')
            lines.append('</resources>')
            dummy_file.write_text('\n'.join(lines), encoding="utf-8")

        # 2. aapt2 compile
        compile_cmd = [
            str(AAPT2_BIN), "compile",
            "--legacy",
            "--dir", str(res_dir),
            "-o", str(compiled_zip)
        ]
        res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)
        if res_compile.returncode != 0:
            print(f"[WARN] aapt2 compile error on iteration {iteration}: {res_compile.stderr[:300]}")
            return None

        # 3. aapt2 link
        link_cmd = [
            str(AAPT2_BIN), "link",
            "--auto-add-overlay",
            "-o", str(out_apk),
            "--manifest", str(manifest_path),
            "-I", str(jar),
            str(compiled_zip)
        ]
        res_link = subprocess.run(link_cmd, capture_output=True, text=True)
        if res_link.returncode == 0 and out_apk.exists():
            return out_apk

        # 4. Parse missing host symbols from link error output
        missing_res = re.findall(r'resource (\w+)/(\w+) \(aka [^)]+\) not found', res_link.stderr)
        missing_attrs = re.findall(r'attribute (\w+) \(aka [^)]+\) not found', res_link.stderr)

        new_symbols = 0
        for r_type, r_name in missing_res:
            pair = (r_type, r_name)
            if pair not in known_placeholders:
                known_placeholders.add(pair)
                new_symbols += 1

        for a_name in missing_attrs:
            pair = ("attr", a_name)
            if pair not in known_placeholders:
                known_placeholders.add(pair)
                new_symbols += 1

        if new_symbols == 0:
            # Cannot resolve remaining errors
            print(f"[WARN] aapt2 link unresolvable errors: {res_link.stderr[:400]}")
            return None

    return None
