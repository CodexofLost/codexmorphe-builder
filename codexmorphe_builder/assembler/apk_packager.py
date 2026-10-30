import hashlib
import zipfile
from pathlib import Path
from typing import List, Optional


def assemble_bundle_apk(
    dex_files: List[Path],
    resources_apk: Optional[Path],
    output_apk: Path,
    hooks_data: Optional[str] = None,
    hooks_file: Optional[Path] = None
) -> Path:
    """
    Assemble the final <packageName>-<source>-bundle.apk package using standard Android MultiDex.
    Packages extracted .mpe DEX files as classes.dex, classes2.dex, classes3.dex...
    Embeds hooks.json if provided so the client engine can execute patch recipes dynamically.
    """
    output_apk.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output_apk, "w", compression=zipfile.ZIP_DEFLATED) as apk:
        # 1. Add all DEX files in MultiDex order
        for i, dex_path in enumerate(dex_files):
            if dex_path.exists():
                arcname = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                apk.write(dex_path, arcname=arcname)

        # 2. Add resources from resources_apk if present
        if resources_apk and resources_apk.exists():
            with zipfile.ZipFile(resources_apk, "r") as res_zip:
                for item in res_zip.infolist():
                    if not item.filename.startswith("classes") or not item.filename.endswith(".dex"):
                        data = res_zip.read(item.filename)
                        apk.writestr(item.filename, data)

        # 3. Add dynamic hook recipes container (hooks.json)
        if hooks_data:
            apk.writestr("hooks.json", hooks_data)
        elif hooks_file and hooks_file.exists():
            apk.write(hooks_file, arcname="hooks.json")

    return output_apk


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()
