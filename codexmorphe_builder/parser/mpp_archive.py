import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


RES_DIR_PATTERN = re.compile(
    r"^((?:drawable|layout|values|raw|anim|color|font|xml|mipmap|interpolator|transition)(?:-[a-zA-Z0-9+_-]+)?)$"
)
VALID_RESOURCE_EXTS = {".xml", ".png", ".webp", ".jpg", ".jpeg", ".json", ".svg", ".ttf", ".otf", ".lua", ".txt"}
UNIVERSAL_SHARED_EXTS = {"shared", "shared-extension", "shared-gmscore", "extension"}
GENERIC_SEGMENTS = {"com", "org", "net", "android", "app", "apps", "google", "io", "in"}


@dataclass
class MppArchive:
    path: Path
    all_files: List[str] = field(default_factory=list)
    dex_classes: List[str] = field(default_factory=list)
    extension_files: List[str] = field(default_factory=list)
    resource_files: List[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path) -> "MppArchive":
        with zipfile.ZipFile(path, "r") as z:
            all_files = z.namelist()
            extensions = [
                f for f in all_files
                if (f.endswith(".mpe") or (f.endswith(".dex") and "extension" in f and f != "classes.dex"))
            ]
            resources = [f for f in all_files if f.startswith("addresources/") or f.startswith("res/")]

            dex_classes = []
            if "classes.dex" in all_files:
                dex_bytes = z.read("classes.dex")
                dex_classes = cls._extract_dex_classes(dex_bytes)

        return cls(
            path=path,
            all_files=all_files,
            dex_classes=dex_classes,
            extension_files=extensions,
            resource_files=resources
        )

    def get_archive_apps(self) -> Set[str]:
        """
        Dynamically discover target application tags present in this archive.
        """
        apps = set()
        for c in self.dex_classes:
            if "patches/" in c:
                parts = c.strip("L;").replace("\\", "/").split("/")
                try:
                    p_idx = parts.index("patches")
                    if p_idx + 1 < len(parts):
                        tag = parts[p_idx + 1]
                        if tag not in ("all", "shared", "util"):
                            apps.add(tag)
                    if p_idx > 0:
                        prev = parts[p_idx - 1]
                        if prev not in ("app", "morphe", "template", "crimera"):
                            apps.add(prev)
                except ValueError:
                    pass
        return apps

    def extract_extensions_for_app(
        self,
        app_tag: str,
        dest_dir: Path,
        app_pkg: Optional[str] = None,
        patch_classes: Optional[List[str]] = None
    ) -> List[Path]:
        """
        Extract extensions dynamically matching this application:
        1. Universal Shared Containers: 'shared.mpe', 'extension.mpe', 'shared-gmscore.mpe',
           or anything in 'extensions/all/'.
        2. Shared Family Extensions: 'shared-<family>.mpe' (e.g. 'shared-youtube.mpe') when
           referenced by the app or belonging to the app family.
        3. Exact and Slug Matches: <app_tag>.mpe, <slug>.mpe.
        4. Bytecode References: Any extension referenced in the bytecode of the app's patch closure.
        5. Single-Extension Repositories: If only 1 non-shared extension exists, it serves all apps.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        extracted = []

        archive_apps = self.get_archive_apps()
        other_apps = archive_apps - {app_tag}

        meaningful_segments: Set[str] = set()
        if app_pkg:
            meaningful_segments.update(
                s.lower() for s in app_pkg.split(".") if s.lower() not in GENERIC_SEGMENTS
            )
        meaningful_segments.add(app_tag.lower())

        non_shared_exts = [
            f for f in self.extension_files
            if Path(f).stem not in UNIVERSAL_SHARED_EXTS and not f.startswith("extensions/all/")
        ]

        with zipfile.ZipFile(self.path, "r") as z:
            # Collect patch class bytecode for this app to detect referenced extensions
            if patch_classes:
                app_bytes = b"".join(
                    z.read(f"{c}.class") for c in patch_classes if f"{c}.class" in self.all_files
                )
            else:
                app_bytes = b"".join(
                    z.read(n) for n in z.namelist()
                    if (f"/patches/{app_tag}/" in n or any(f"/{s}/" in n for s in meaningful_segments))
                    and n.endswith(".class")
                )

            for ext in self.extension_files:
                ext_name = Path(ext).stem
                ext_lower = ext_name.lower()

                is_all_ext = ext.startswith("extensions/all/") or "/all/" in ext
                is_shared_base = ext_lower in UNIVERSAL_SHARED_EXTS
                is_sole_app_ext = (len(non_shared_exts) <= 1)

                is_shared_family = ext_lower.startswith("shared-")

                # Check if exact app match or family match
                is_app_match = (
                    ext_lower == app_tag.lower()
                    or (is_shared_family and any(s in ext_lower for s in meaningful_segments))
                )

                # An extension is foreign if its name strictly equals another app tag in this archive
                is_foreign_app = (ext_lower in other_apps and ext_lower != app_tag.lower())

                # Check if referenced dynamically in bytecode
                is_referenced = (not is_foreign_app and ext_name.encode() in app_bytes)

                if is_all_ext or is_shared_base or is_sole_app_ext or (is_app_match and not is_foreign_app) or is_referenced:
                    out_path = dest_dir / f"{ext_name}.dex"
                    with open(out_path, "wb") as out:
                        out.write(z.read(ext))
                    extracted.append(out_path)

        return extracted

    def extract_resources_for_app(
        self,
        app_tag: str,
        dest_res_dir: Path,
        dest_assets_dir: Optional[Path] = None,
        app_pkg: Optional[str] = None,
        patch_classes: Optional[List[str]] = None
    ) -> Path:
        """
        Extract XML layouts, vector/raster drawables, localized strings, typography fonts,
        and raw assets matching this application's inheritance chain into a standard Android res/ directory.
        Derives feature associations dynamically without hardcoding app names.
        """
        dest_res_dir.mkdir(parents=True, exist_ok=True)
        if dest_assets_dir:
            dest_assets_dir.mkdir(parents=True, exist_ok=True)

        archive_apps = self.get_archive_apps()
        other_apps = archive_apps - {app_tag}

        meaningful_segments: Set[str] = set()
        if app_pkg:
            meaningful_segments.update(
                s.lower() for s in app_pkg.split(".") if s.lower() not in GENERIC_SEGMENTS
            )
        meaningful_segments.add(app_tag.lower())

        with zipfile.ZipFile(self.path, "r") as z:
            if patch_classes:
                app_bytes = b"".join(
                    z.read(f"{c}.class") for c in patch_classes if f"{c}.class" in self.all_files
                )
            else:
                app_bytes = b"".join(
                    z.read(n) for n in z.namelist()
                    if (f"/patches/{app_tag}/" in n or any(f"/{s}/" in n for s in meaningful_segments))
                    and n.endswith(".class")
                )

            other_bytes = {
                o: b"".join(z.read(n) for n in z.namelist() if f"/patches/{o}/" in n and n.endswith(".class"))
                for o in other_apps
            }

            host_ids: Set[str] = set()

            for name in z.namelist():
                # Skip non-resource files, directory entries, extensions, and patches
                if (
                    name.endswith("/")
                    or name.startswith("META-INF/")
                    or name.startswith("patches/")
                    or name.endswith(".mpe")
                ):
                    continue

                # Collect declared resource IDs from /host/ layout templates
                if "/host/" in name:
                    if name.endswith(".xml"):
                        try:
                            host_xml = z.read(name).decode("utf-8", errors="ignore")
                            for m in re.finditer(r'@\+id/([a-zA-Z0-9_]+)', host_xml):
                                host_ids.add(m.group(1))
                        except Exception:
                            pass
                    continue

                ext = "." + name.split(".")[-1].lower() if "." in name else ""
                if ext not in VALID_RESOURCE_EXTS:
                    continue

                parts = name.split("/")
                first = parts[0].lower()

                # Skip files rooted under a foreign application's directory
                if any(first == o or first.startswith(f"{o}-") for o in other_apps) and not (
                    first == app_tag.lower() or first.startswith(f"{app_tag.lower()}-")
                ):
                    continue

                # Dynamic feature membership check
                first_clean = first.replace("-", "").replace("_", "")
                first_in_this = (first.encode() in app_bytes or first_clean.encode() in app_bytes)
                first_in_other = any(first.encode() in ob or first_clean.encode() in ob for ob in other_bytes.values())

                is_universal_root = first in ("shared", "all", "res", "settings")
                is_app_root = first in meaningful_segments or any(first.startswith(f"{s}-") for s in meaningful_segments)

                if is_universal_root or is_app_root:
                    allowed = True
                elif first_in_this:
                    allowed = True
                elif first_in_other:
                    allowed = False
                else:
                    allowed = True

                if not allowed:
                    continue

                # -------------------------------------------------------------
                # Handle localized value tables (addresources/values-<lang>/<target>/*.xml)
                # -------------------------------------------------------------
                if name.startswith("addresources/"):
                    if len(parts) >= 4 and parts[3].endswith(".xml"):
                        val_qualifier = parts[1]
                        target = parts[2].lower()
                        target_clean = target.replace("-", "").replace("_", "")
                        target_in_this = (target.encode() in app_bytes or target_clean.encode() in app_bytes)
                        target_in_other = any(target.encode() in ob or target_clean.encode() in ob for ob in other_bytes.values())

                        target_allowed = False
                        is_foreign_target = any(
                            target == o or target.startswith(f"{o}-") for o in other_apps
                        ) and not (
                            target == app_tag.lower() or target.startswith(f"{app_tag.lower()}-")
                        )

                        if is_foreign_target:
                            target_allowed = False
                        elif target in ("shared", "all"):
                            target_allowed = True
                        elif target == app_tag.lower():
                            target_allowed = True
                        elif target.startswith("shared-") and any(s in target for s in meaningful_segments):
                            target_allowed = True
                        elif target in meaningful_segments or any(target.startswith(f"{s}-") for s in meaningful_segments):
                            target_allowed = True
                        elif target_in_this:
                            target_allowed = True
                        elif target_in_other:
                            target_allowed = False
                        else:
                            target_allowed = True

                        if target_allowed:
                            val_dir = dest_res_dir / val_qualifier
                            val_dir.mkdir(parents=True, exist_ok=True)
                            raw_xml = z.read(name).decode("utf-8", errors="ignore")
                            fixed_xml = raw_xml
                            try:
                                fixed_xml = re.sub(r'%(?![0-9]+\$[a-zA-Z%]|s|d|f|c|b|o|x|e|g|a|h)', '&#37;', raw_xml)
                            except Exception:
                                pass

                            target_xml = val_dir / f"{target}_{parts[3]}"
                            target_xml.write_text(fixed_xml, encoding="utf-8")
                    continue

                # -------------------------------------------------------------
                # Handle root feature directories (e.g. settings/, swipecontrols/, waze/assets/)
                # -------------------------------------------------------------
                if len(parts) >= 2:
                    # Check if entry is routed to assets
                    if "assets/" in name and dest_assets_dir:
                        assets_sub = name[name.index("assets/") + len("assets/"):]
                        out_asset_path = dest_assets_dir / assets_sub
                        out_asset_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_asset_path, "wb") as f_out:
                            f_out.write(z.read(name))
                        continue

                    # Otherwise, check if second segment is a standard Android resource qualifier
                    res_segment = parts[1]
                    if RES_DIR_PATTERN.match(res_segment):
                        rel_path = Path(*parts[1:])
                        out_file = dest_res_dir / rel_path
                        out_file.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_file, "wb") as f_out:
                            f_out.write(z.read(name))
                    elif RES_DIR_PATTERN.match(first):
                        out_file = dest_res_dir / name
                        out_file.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_file, "wb") as f_out:
                            f_out.write(z.read(name))

        # Synthesize declared host layout IDs into a public id declaration if needed
        if host_ids:
            values_dir = dest_res_dir / "values"
            values_dir.mkdir(parents=True, exist_ok=True)
            ids_xml_path = values_dir / "morphe_host_injected_ids.xml"
            items = "\n".join(f'    <item type="id" name="{i}" />' for i in sorted(host_ids))
            ids_xml = f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{items}\n</resources>'
            ids_xml_path.write_text(ids_xml, encoding="utf-8")

        return dest_res_dir

    @staticmethod
    def _extract_dex_classes(dex_bytes: bytes) -> List[str]:
        """
        Pure Python DEX header & class_defs parser.
        Extracts all class descriptors defined in classes.dex.
        """
        if len(dex_bytes) < 112:
            return []

        magic = dex_bytes[:4]
        if magic != b"dex\n":
            return []

        (
            string_ids_size, string_ids_off,
            type_ids_size, type_ids_off,
            proto_ids_size, proto_ids_off,
            field_ids_size, field_ids_off,
            method_ids_size, method_ids_off,
            class_defs_size, class_defs_off,
        ) = struct.unpack_from("<12I", dex_bytes, 56)

        def get_string(idx: int) -> str:
            if idx >= string_ids_size:
                return ""
            str_off, = struct.unpack_from("<I", dex_bytes, string_ids_off + idx * 4)
            pos = str_off
            ulen = 0
            shift = 0
            while pos < len(dex_bytes):
                b = dex_bytes[pos]
                pos += 1
                ulen |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7

            end = dex_bytes.find(b"\x00", pos)
            if end == -1:
                end = len(dex_bytes)
            return dex_bytes[pos:end].decode("utf-8", errors="ignore")

        def get_type(idx: int) -> str:
            if idx >= type_ids_size:
                return ""
            desc_idx, = struct.unpack_from("<I", dex_bytes, type_ids_off + idx * 4)
            return get_string(desc_idx)

        classes = []
        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            class_idx, = struct.unpack_from("<I", dex_bytes, off)
            desc = get_type(class_idx)
            if desc:
                classes.append(desc)

        return classes
