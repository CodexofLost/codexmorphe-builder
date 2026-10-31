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
        Dynamically discover all target applications present in this archive from classes.dex.
        Works across all 240+ apps without hardcoding any app names.
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
                except ValueError:
                    pass
        return apps

    def extract_extensions_for_app(self, app_tag: str, dest_dir: Path) -> List[Path]:
        """
        Extract extensions dynamically matching this application:
        1. Universal Shared Containers: 'extensions/all/*.mpe', 'shared.mpe', 'extension.mpe',
           'shared-extension.mpe', 'shared-gmscore.mpe'.
        2. Single-Extension Repositories: If an archive contains only 1 non-shared extension,
           it serves all apps in the bundle.
        3. Exact and Family Matches: Matches <app_tag>.mpe, shared-<app_tag>.mpe, or extensions
           referenced in bytecode by this app's patch classes.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        extracted = []

        archive_apps = self.get_archive_apps()
        other_apps = archive_apps - {app_tag}

        non_shared_exts = [
            f for f in self.extension_files
            if Path(f).stem not in UNIVERSAL_SHARED_EXTS and not f.startswith("extensions/all/")
        ]

        with zipfile.ZipFile(self.path, "r") as z:
            # Collect patch class bytecode for this app to detect referenced extensions
            app_bytes = b"".join(
                z.read(n) for n in z.namelist()
                if f"/patches/{app_tag}/" in n and n.endswith(".class")
            )

            for ext in self.extension_files:
                ext_name = Path(ext).stem

                is_all_ext = ext.startswith("extensions/all/") or "/all/" in ext
                is_shared_base = ext_name in UNIVERSAL_SHARED_EXTS
                is_sole_app_ext = (len(non_shared_exts) <= 1)
                is_app_match = (
                    ext_name == app_tag
                    or ext_name == f"shared-{app_tag}"
                    or ext_name.endswith(f"-{app_tag}")
                )
                # If extension belongs explicitly to another app in this archive, do not bundle it
                is_foreign_app = (ext_name in other_apps or any(ext_name.endswith(f"-{o}") for o in other_apps))
                # Check if referenced dynamically in bytecode (e.g. shared-youtube referenced by music)
                is_referenced = (not is_foreign_app and ext_name.encode() in app_bytes)

                if is_all_ext or is_shared_base or is_sole_app_ext or is_app_match or is_referenced:
                    out_path = dest_dir / f"{ext_name}.dex"
                    with open(out_path, "wb") as out:
                        out.write(z.read(ext))
                    extracted.append(out_path)

        return extracted

    def extract_resources_for_app(
        self,
        app_tag: str,
        dest_res_dir: Path,
        dest_assets_dir: Optional[Path] = None
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

        with zipfile.ZipFile(self.path, "r") as z:
            app_bytes = b"".join(
                z.read(n) for n in z.namelist()
                if f"/patches/{app_tag}/" in n and n.endswith(".class")
            )
            other_bytes = {
                o: b"".join(z.read(n) for n in z.namelist() if f"/patches/{o}/" in n and n.endswith(".class"))
                for o in other_apps
            }

            host_ids: Set[str] = set()

            for name in z.namelist():
                # 1. Skip non-resource files, directory entries, and patches
                if name.endswith("/") or name.startswith("META-INF/") or name.startswith("patches/"):
                    continue

                # Collect declared resource IDs from /host/ layout templates (e.g. morphe_external_download_button)
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

                # 2. Skip files rooted under a foreign application's directory
                if first in other_apps:
                    continue

                # 3. Dynamic feature membership check
                first_clean = first.replace("-", "").replace("_", "")
                first_in_this = (first.encode() in app_bytes or first_clean.encode() in app_bytes)
                first_in_other = any(first.encode() in ob or first_clean.encode() in ob for ob in other_bytes.values())

                if first in ("shared", "all", "res", "settings") or first == app_tag or first.startswith(f"{app_tag}-"):
                    allowed = True
                elif first_in_this:
                    allowed = True
                elif first_in_other:
                    allowed = False
                else:
                    allowed = True

                if not allowed:
                    continue

                # 4. Handle localized value tables (addresources/values-<lang>/<target>/*.xml: strings, arrays)
                if name.startswith("addresources/"):
                    if len(parts) >= 4 and parts[3].endswith(".xml"):
                        val_qualifier = parts[1]
                        target = parts[2].lower()
                        target_clean = target.replace("-", "").replace("_", "")
                        target_in_this = (target.encode() in app_bytes or target_clean.encode() in app_bytes)
                        target_in_other = any(target.encode() in ob or target_clean.encode() in ob for ob in other_bytes.values())

                        target_allowed = False
                        if target in other_apps:
                            target_allowed = False
                        elif target in ("shared", "all") or target == app_tag or target.startswith(f"{app_tag}-"):
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
                            # Sanitize unescaped % tokens via XML DOM AST for strict AAPT2 compliance
                            fixed_xml = raw_xml
                            try:
                                root = ET.fromstring(raw_xml)
                                modified = False
                                for elem in root.iter():
                                    if elem.tag in ("string", "item") and elem.text and "%" in elem.text:
                                        if "formatted" not in elem.attrib:
                                            elem.set("formatted", "false")
                                            modified = True
                                if modified:
                                    fixed_xml = ET.tostring(root, encoding="utf-8").decode("utf-8")
                            except ET.ParseError:
                                # Fallback regex for non-standard XML fragments
                                fixed_xml = re.sub(
                                    r'<string\s+([^>]*?)>([^<]*?%[^<]*?)</string>',
                                    lambda m: f'<string {m.group(1)} formatted="false">{m.group(2)}</string>' if 'formatted=' not in m.group(1) else m.group(0),
                                    raw_xml
                                )
                                fixed_xml = re.sub(
                                    r'<item\s*([^>]*?)>([^<]*?%[^<]*?)</item>',
                                    lambda m: f'<item {m.group(1)} formatted="false">{m.group(2)}</item>' if 'formatted=' not in m.group(1) else m.group(0),
                                    fixed_xml
                                )
                            xml_stem = parts[3].replace(".xml", "")
                            out_file = val_dir / f"{xml_stem}_{target}.xml"
                            out_file.write_text(fixed_xml, encoding="utf-8")
                    continue

                # 5. Handle raw assets (e.g. actionbar/assets/animated_like_icon_dark_v4.json, waze skins)
                if "assets" in parts and dest_assets_dir is not None:
                    asset_idx = parts.index("assets")
                    rel_asset_path = Path(*parts[asset_idx + 1:])
                    out_asset = dest_assets_dir / rel_asset_path
                    out_asset.parent.mkdir(parents=True, exist_ok=True)
                    with open(out_asset, "wb") as out:
                        out.write(z.read(name))
                    continue

                # 6. Handle standard & qualified Android resource directories (drawables, layouts, fonts, mipmaps, raw, anim, color, xml)
                res_dir_idx = -1
                for i, p in enumerate(parts[:-1]):
                    if RES_DIR_PATTERN.match(p):
                        res_dir_idx = i
                        break

                if res_dir_idx != -1:
                    res_type_dir = parts[res_dir_idx]
                    target_type_dir = dest_res_dir / res_type_dir
                    target_type_dir.mkdir(parents=True, exist_ok=True)
                    out_target_file = target_type_dir / Path(name).name
                    with open(out_target_file, "wb") as out:
                        out.write(z.read(name))

            if host_ids:
                val_dir = dest_res_dir / "values"
                val_dir.mkdir(parents=True, exist_ok=True)
                items = "\n".join(f'    <item type="id" name="{i}" />' for i in sorted(host_ids))
                (val_dir / "host_ids.xml").write_text(
                    f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{items}\n</resources>\n',
                    encoding="utf-8"
                )

        return dest_res_dir

    @staticmethod
    def _extract_dex_classes(dex_bytes: bytes) -> List[str]:
        if len(dex_bytes) < 0x70 or not dex_bytes[:4].startswith(b"dex\n"):
            return []

        string_ids_size, string_ids_off = struct.unpack_from("<II", dex_bytes, 0x38)
        type_ids_size, type_ids_off = struct.unpack_from("<II", dex_bytes, 0x40)
        class_defs_size, class_defs_off = struct.unpack_from("<II", dex_bytes, 0x60)

        string_offsets = [struct.unpack_from("<I", dex_bytes, string_ids_off + i * 4)[0] for i in range(string_ids_size)]

        def get_string(idx: int) -> str:
            if idx >= len(string_offsets):
                return ""
            off = string_offsets[idx]
            while dex_bytes[off] & 0x80:
                off += 1
            off += 1
            end = dex_bytes.find(b"\x00", off)
            return dex_bytes[off:end].decode("utf-8", errors="ignore")

        type_strings = [get_string(struct.unpack_from("<I", dex_bytes, type_ids_off + i * 4)[0]) for i in range(type_ids_size)]
        classes = []
        for i in range(class_defs_size):
            type_idx = struct.unpack_from("<I", dex_bytes, class_defs_off + i * 32)[0]
            if type_idx < len(type_strings):
                classes.append(type_strings[type_idx])

        return classes
