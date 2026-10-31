import hashlib
import struct
import zipfile
import zlib
from pathlib import Path
from typing import List, Optional


def make_empty_dex() -> bytes:
    """Generate a minimal valid 112-byte Android DEX header with 0 classes."""
    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, 112)        # file_size
    struct.pack_into("<I", header, 36, 112)        # header_size
    struct.pack_into("<I", header, 40, 0x12345678) # endian_tag
    struct.pack_into("<I", header, 52, 0)          # map_off
    sha1 = hashlib.sha1(header[32:]).digest()
    header[12:32] = sha1
    checksum = zlib.adler32(header[12:]) & 0xffffffff
    struct.pack_into("<I", header, 8, checksum)
    return bytes(header)


def assemble_bundle_apk(
    dex_files: List[Path],
    resources_apk: Optional[Path],
    output_apk: Path,
    hooks_data: Optional[str] = None,
    hooks_file: Optional[Path] = None,
    assets_dir: Optional[Path] = None
) -> Path:
    """
    Assemble the final <packageName>-<source>-bundle.apk package using standard Android MultiDex.
    Packages extracted .mpe DEX files as classes.dex, classes2.dex, classes3.dex...
    Embeds hooks.json if provided so the client engine can execute patch recipes dynamically.
    Packages raw assets into assets/ if provided.
    """
    output_apk.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output_apk, "w", compression=zipfile.ZIP_DEFLATED) as apk:
        # 1. Add all DEX files in MultiDex order
        written_classes_dex = False
        if dex_files:
            for i, dex_path in enumerate(dex_files):
                if dex_path.exists():
                    arcname = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                    apk.write(dex_path, arcname=arcname)
                    if arcname == "classes.dex":
                        written_classes_dex = True

        if not written_classes_dex:
            apk.writestr("classes.dex", make_empty_dex())

        # 2. Add resources from resources_apk if present
        if resources_apk and resources_apk.exists():
            with zipfile.ZipFile(resources_apk, "r") as res_zip:
                for item in res_zip.infolist():
                    if not item.filename.startswith("classes") or not item.filename.endswith(".dex"):
                        data = res_zip.read(item.filename)
                        apk.writestr(item.filename, data)

        # 3. Add dynamic hook recipes container (hooks.json) at both root and assets/
        if hooks_data:
            apk.writestr("hooks.json", hooks_data)
            apk.writestr("assets/hooks.json", hooks_data)
        elif hooks_file and hooks_file.exists():
            apk.write(hooks_file, arcname="hooks.json")
            apk.write(hooks_file, arcname="assets/hooks.json")

        # 4. Add raw assets from assets_dir into assets/
        if assets_dir and assets_dir.exists():
            for asset_file in assets_dir.rglob("*"):
                if asset_file.is_file():
                    rel_path = asset_file.relative_to(assets_dir)
                    arcname = f"assets/{rel_path}".replace("\\", "/")
                    # Avoid duplicate hooks.json
                    if arcname != "assets/hooks.json":
                        apk.write(asset_file, arcname=arcname)

    return output_apk


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()
