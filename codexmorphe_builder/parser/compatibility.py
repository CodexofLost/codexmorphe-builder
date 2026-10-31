import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .classfile_ast import ClassfileAst
from .mpp_archive import MppArchive

PKG_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
GENERIC_PACKAGE_SEGMENTS = {"com", "org", "net", "android", "app", "apps", "google", "io", "in"}


@dataclass
class PatchInfo:
    id: str
    name: str
    description: str
    default: bool
    key: str
    patch_class: str


def clean_patch_name(cls_name: str) -> str:
    base = cls_name.split("/")[-1].replace("PatchKt", "").replace("Patch", "")
    name = re.sub(r"([A-Z])", r" \1", base).strip()
    return name or "Custom Patch"


def make_patch_key(name: str) -> str:
    return "morphe_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


@dataclass
class DiscoveredApp:
    package_name: str
    app_name: str
    app_tag: str
    patch_classes: List[str] = field(default_factory=list)
    patches: List[PatchInfo] = field(default_factory=list)


def _resolve_cp_str(ast: ClassfileAst, idx: int) -> Optional[str]:
    """Resolve String or Utf8 constant from constant pool."""
    item = ast.cp.get(idx)
    if not item:
        return None
    if item[0] == "String":
        u = ast.cp.get(item[1])
        return u[1] if u and u[0] == "Utf8" else None
    if item[0] == "Utf8":
        return item[1]
    return None


def _derive_app_slug(package_name: str, patch_classes: Optional[Set[str]] = None) -> str:
    """Derive primary application slug matching patch repository layout and package identity."""
    if patch_classes:
        tag_candidates: Set[str] = set()
        for c in patch_classes:
            parts = c.split("/")
            if "patches" in parts:
                idx = parts.index("patches")
                if idx + 1 < len(parts) and parts[idx + 1] not in ("all", "shared", "util"):
                    tag_candidates.add(parts[idx + 1])
                if idx > 0 and parts[idx - 1] not in ("app", "morphe", "template", "crimera"):
                    tag_candidates.add(parts[idx - 1])

        pkg_lower = package_name.lower()
        for cand in sorted(tag_candidates):
            if cand in pkg_lower or any(cand in s for s in pkg_lower.split(".")):
                return cand
        if tag_candidates:
            return sorted(tag_candidates)[0]

    parts = package_name.split(".")
    meaningful = [p for p in parts if p not in GENERIC_PACKAGE_SEGMENTS]
    return meaningful[-1].lower() if meaningful else parts[-1].lower()


def discover_compatible_apps(archive: MppArchive) -> Dict[str, DiscoveredApp]:
    """
    Dynamically discover all genuine applications and their standalone patch closures
    directly from .mpp bytecode, strictly conforming to the official Morphe specification.

    1. Scans Compatibility constructor invocations to discover genuine package names and display names.
    2. Builds getter/field mappings from <clinit> putstatic references to Compatibility instances.
    3. Discards standalone universal packaging patches (e.g. /patches/all/ like CloneApp, SpoofSignature).
    4. Maps targeted patches to applications and traverses dependsOn references into /patches/shared/
       to compute the autonomous standalone patch closure per application.
    """
    discovered: Dict[str, DiscoveredApp] = {}
    compat_map: Dict[Tuple[str, str], str] = {}  # (class_name, field_or_getter) -> package_name
    app_meta: Dict[str, str] = {}  # package_name -> display_name

    with zipfile.ZipFile(archive.path, "r") as z:
        # -------------------------------------------------------------
        # Step 1: Scan Compatibility declarations across all .class files
        # -------------------------------------------------------------
        for name in z.namelist():
            if not name.endswith(".class") or name.startswith("META-INF/"):
                continue

            data = z.read(name)
            ast = ClassfileAst(data)

            compat_classes = {
                idx for idx, item in ast.cp.items()
                if item[0] == "Class"
                and ast.cp.get(item[1])
                and ast.cp.get(item[1])[1] in (
                    "app/morphe/patcher/patch/Compatibility",
                    "app/revanced/patcher/patch/Compatibility"
                )
            }
            if not compat_classes:
                continue

            for (mname, mdesc), code in ast.methods.items():
                i = 0
                while i < len(code):
                    op = code[i]
                    if op == 0xbb and i + 2 < len(code):  # new Compatibility
                        cidx, = struct.unpack_from(">H", code, i + 1)
                        if cidx in compat_classes:
                            j = i + 3
                            ldc_strings: List[str] = []
                            putstatic_ref: Optional[Tuple[str, str]] = None

                            while j < min(len(code), i + 80):
                                sub_op = code[j]
                                if sub_op == 0x12:  # ldc
                                    if j + 1 >= len(code):
                                        break
                                    s = _resolve_cp_str(ast, code[j + 1])
                                    if s is not None:
                                        ldc_strings.append(s)
                                    j += 2
                                elif sub_op == 0x13:  # ldc_w
                                    if j + 2 >= len(code):
                                        break
                                    sidx, = struct.unpack_from(">H", code, j + 1)
                                    s = _resolve_cp_str(ast, sidx)
                                    if s is not None:
                                        ldc_strings.append(s)
                                    j += 3
                                elif sub_op in (0xb7, 0xb8):  # invokespecial / invokestatic
                                    j += 3
                                elif sub_op == 0xb3:  # putstatic
                                    if j + 2 >= len(code):
                                        break
                                    fidx, = struct.unpack_from(">H", code, j + 1)
                                    item = ast.cp.get(fidx)
                                    if item and item[0] == "Ref2":
                                        f_cls = ast.cp.get(ast.cp.get(item[1][0])[1])[1]
                                        f_nat = ast.cp.get(item[1][1])
                                        f_name = ast.cp.get(f_nat[1][0])[1]
                                        putstatic_ref = (f_cls, f_name)
                                    j += 3
                                    break
                                else:
                                    j += 1

                            # First string matching PKG_REGEX is package_name; second is display_name
                            pkg: Optional[str] = None
                            disp: Optional[str] = None
                            for s_idx, s in enumerate(ldc_strings):
                                if (
                                    PKG_REGEX.match(s)
                                    and not s.startswith((
                                        "java.", "android.", "kotlin.",
                                        "app.morphe.", "app.revanced.", "app.crimera."
                                    ))
                                ):
                                    pkg = s
                                    if s_idx + 1 < len(ldc_strings):
                                        disp = ldc_strings[s_idx + 1]
                                    break

                            if pkg:
                                app_name = disp or pkg.split(".")[-1].title()
                                app_meta[pkg] = app_name
                                if putstatic_ref:
                                    f_cls, f_name = putstatic_ref
                                    compat_map[(f_cls, f_name)] = pkg
                                    getter_name = f_name if f_name.startswith("get") else f"get{f_name}"
                                    compat_map[(f_cls, getter_name)] = pkg
                    i += 1

        # -------------------------------------------------------------
        # Step 2: Index all patch classes (excluding universal /all/)
        # -------------------------------------------------------------
        patch_ast: Dict[str, ClassfileAst] = {}
        for name in z.namelist():
            if not (name.endswith("PatchKt.class") or (name.endswith("Patch.class") and "$" not in name)):
                continue
            if name.startswith("META-INF/"):
                continue
            # Discard universal repackager patches in /patches/all/ or /all/
            if "/patches/all/" in name or "/all/" in name:
                continue

            clean_cls = name[:-6]  # strip '.class'
            data = z.read(name)
            patch_ast[clean_cls] = ClassfileAst(data)

        # -------------------------------------------------------------
        # Step 3: Map targeted patches to discovered applications
        # -------------------------------------------------------------
        targeted_patches: Dict[str, Set[str]] = {pkg: set() for pkg in app_meta}

        for clean_cls, ast in patch_ast.items():
            matched_pkg: Optional[str] = None

            # Check if patch bytecode references any Compatibility field or getter
            for idx, item in ast.cp.items():
                if item[0] == "Ref2":
                    cls_item = ast.cp.get(item[1][0])
                    nat_item = ast.cp.get(item[1][1])
                    if cls_item and nat_item:
                        c_name = ast.cp.get(cls_item[1])[1]
                        m_name = ast.cp.get(nat_item[1][0])[1]
                        if (c_name, m_name) in compat_map:
                            matched_pkg = compat_map[(c_name, m_name)]
                            break

            # If not directly matched via getter/field, check path against app package segments
            if not matched_pkg:
                for pkg in app_meta:
                    meaningful = [s for s in pkg.split(".") if s not in GENERIC_PACKAGE_SEGMENTS]
                    if any(f"/{s}/" in clean_cls for s in meaningful):
                        matched_pkg = pkg
                        break

            if matched_pkg and matched_pkg in targeted_patches:
                targeted_patches[matched_pkg].add(clean_cls)

        # -------------------------------------------------------------
        # Step 4: Standalone Patch Closure (Recursive dependsOn Tracing)
        # -------------------------------------------------------------
        for pkg, target_set in targeted_patches.items():
            closure: Set[str] = set(target_set)
            queue: List[str] = list(target_set)

            while queue:
                curr = queue.pop(0)
                curr_ast = patch_ast.get(curr)
                if not curr_ast:
                    continue

                for idx, item in curr_ast.cp.items():
                    if item[0] == "Ref2":
                        cls_item = curr_ast.cp.get(item[1][0])
                        if cls_item:
                            ref_cls = curr_ast.cp.get(cls_item[1])[1]
                            if ref_cls in patch_ast and ref_cls not in closure:
                                # Include if it is in /patches/shared/, or matches app domain
                                is_shared = "/patches/shared/" in ref_cls or "/shared/" in ref_cls
                                meaningful = [s for s in pkg.split(".") if s not in GENERIC_PACKAGE_SEGMENTS]
                                is_app_domain = any(s in ref_cls for s in meaningful)

                                if is_shared or is_app_domain:
                                    closure.add(ref_cls)
                                    queue.append(ref_cls)

            app_tag = _derive_app_slug(pkg, closure)
            app_display_name = app_meta[pkg]

            # Build PatchInfo metadata for all patches in closure
            patch_infos: List[PatchInfo] = []
            for p_cls in sorted(closure):
                p_name = clean_patch_name(p_cls)
                p_key = make_patch_key(p_name)
                p_id = re.sub(r"[^a-z0-9]+", "_", p_name.lower()).strip("_")
                desc = f"Enables enhancements and customization for {p_name.lower()}."

                patch_infos.append(PatchInfo(
                    id=p_id,
                    name=p_name,
                    description=desc,
                    default=True,
                    key=p_key,
                    patch_class=p_cls
                ))

            discovered[pkg] = DiscoveredApp(
                package_name=pkg,
                app_name=app_display_name,
                app_tag=app_tag,
                patch_classes=sorted(closure),
                patches=patch_infos
            )

    return discovered
