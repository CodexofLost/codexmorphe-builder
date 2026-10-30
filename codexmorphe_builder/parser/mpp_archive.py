import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


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
            extensions = [f for f in all_files if f.startswith("extensions/") and f.endswith(".mpe")]
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

    def extract_extensions_for_app(self, app_tag: str, dest_dir: Path) -> List[Path]:
        """
        Extract extensions following official Morphe specifications:
        1. Universal Shared Containers: 'shared.mpe', 'extension.mpe', 'shared-extension.mpe', 'shared-gmscore.mpe'.
        2. Single-Extension Repositories: If an archive contains only 1 extension, it serves all apps in the bundle.
        3. Multi-App Domain Matching: Matches <app_tag>.mpe, shared-<app_tag>.mpe, or domain tags.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        extracted = []

        shared_stems = {"shared", "shared-extension", "shared-gmscore", "extension"}
        non_shared_exts = [f for f in self.extension_files if Path(f).stem not in shared_stems]

        with zipfile.ZipFile(self.path, "r") as z:
            for ext in self.extension_files:
                ext_name = Path(ext).stem

                is_shared_base = ext_name in shared_stems
                is_sole_app_ext = len(non_shared_exts) == 1 and len(self.extension_files) == 1
                is_app_match = (
                    ext_name == app_tag
                    or ext_name == f"shared-{app_tag}"
                    or ext_name.endswith(f"-{app_tag}")
                    or (app_tag in ext_name and len(app_tag) > 3)
                )

                if is_shared_base or is_sole_app_ext or is_app_match:
                    out_path = dest_dir / f"{ext_name}.dex"
                    with open(out_path, "wb") as out:
                        out.write(z.read(ext))
                    extracted.append(out_path)

        return extracted

    def extract_resources_for_app(self, app_tag: str, dest_res_dir: Path) -> Path:
        """
        Extract XML layouts, vector/raster drawables, localized strings, and raw assets
        matching this application's inheritance chain into a standard Android res/ directory.
        """
        import re

        dest_res_dir.mkdir(parents=True, exist_ok=True)
        allowed_targets = {"shared", app_tag, f"shared-{app_tag}"}
        if app_tag in ("youtube", "music"):
            allowed_targets.add("sponsorblock")
            allowed_targets.add("shared-youtube")

        valid_exts = {".xml", ".png", ".webp", ".jpg", ".jpeg", ".json", ".svg"}
        known_apps = {"youtube", "music", "reddit", "instagram", "twitter", "waze", "twitch"}

        with zipfile.ZipFile(self.path, "r") as z:
            for name in z.namelist():
                # 1. Skip non-resource files and excluded branding
                if name.endswith("/") or name.startswith("META-INF/") or name.startswith("patches/"):
                    continue
                if name.startswith("custom-branding/") or "branding" in name.lower() and ("icon" in name.lower() or "logo" in name.lower()):
                    continue
                if Path(name).suffix.lower() not in valid_exts:
                    continue

                # 2. Check if file is isolated under a foreign app root (e.g. twitter/ when app_tag is instagram)
                first_part = name.split("/")[0].lower()
                if first_part in known_apps and first_part != app_tag:
                    continue

                # 3. Handle localized string tables (addresources/values-<lang>/<target>/strings.xml)
                if name.startswith("addresources/"):
                    parts = name.split("/")
                    if len(parts) >= 4 and parts[3] == "strings.xml":
                        val_qualifier = parts[1]
                        target = parts[2].lower()
                        if target in allowed_targets:
                            val_dir = dest_res_dir / val_qualifier
                            val_dir.mkdir(parents=True, exist_ok=True)
                            raw_xml = z.read(name).decode("utf-8", errors="ignore")
                            # Sanitize unescaped % tokens for AAPT2 format validation
                            fixed_xml = re.sub(
                                r'<string\s+([^>]*?)>([^<]*?%[^<]*?)</string>',
                                lambda m: f'<string {m.group(1)} formatted="false">{m.group(2)}</string>' if 'formatted=' not in m.group(1) else m.group(0),
                                raw_xml
                            )
                            out_file = val_dir / f"strings_{target}.xml"
                            out_file.write_text(fixed_xml, encoding="utf-8")
                    continue

                # 4. Handle standard Android resource types (drawables, layouts, raw, anim, color)
                for res_type in ("drawable", "layout", "raw", "anim", "color"):
                    marker = f"/{res_type}/"
                    idx = name.find(marker)
                    if idx != -1:
                        filename = name[idx + len(marker):]
                        if filename and not filename.endswith("/"):
                            target_type_dir = dest_res_dir / res_type
                            target_type_dir.mkdir(parents=True, exist_ok=True)
                            out_target_file = target_type_dir / Path(filename).name
                            with open(out_target_file, "wb") as out:
                                out.write(z.read(name))
                        break

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
