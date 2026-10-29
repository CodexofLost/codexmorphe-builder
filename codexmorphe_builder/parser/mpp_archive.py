import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


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

    def extract_file(self, internal_path: str, dest_path: Path) -> Path:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(self.path, "r") as z:
            with open(dest_path, "wb") as out:
                out.write(z.read(internal_path))
        return dest_path

    def extract_extensions_for_app(self, app_tag: str, dest_dir: Path) -> List[Path]:
        """
        Extract extensions matching the inheritance chain for an app.
        e.g. For 'youtube': 'shared.mpe', 'shared-youtube.mpe', 'youtube.mpe'.
        For 'reddit': 'shared.mpe', 'reddit.mpe'.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        extracted = []
        with zipfile.ZipFile(self.path, "r") as z:
            for ext in self.extension_files:
                ext_name = Path(ext).stem
                # Check inheritance matching
                if ext_name == "shared" or ext_name == app_tag or ext_name == f"shared-{app_tag}":
                    out_path = dest_dir / f"{ext_name}.dex"
                    with open(out_path, "wb") as out:
                        out.write(z.read(ext))
                    extracted.append(out_path)
        return extracted

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
