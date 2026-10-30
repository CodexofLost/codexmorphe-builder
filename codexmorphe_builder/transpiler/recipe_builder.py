import json
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from ..parser.compatibility import DiscoveredApp
from ..parser.mpp_archive import MppArchive


def clean_type(t: str) -> str:
    """Normalize Smali and JVM type descriptors into DexKit-compatible Java types."""
    if not t:
        return "void"
    t = t.strip()
    if t == "V":
        return "void"
    if t == "Z":
        return "boolean"
    if t == "I":
        return "int"
    if t == "J":
        return "long"
    if t == "F":
        return "float"
    if t == "D":
        return "double"
    if t == "S":
        return "short"
    if t == "B":
        return "byte"
    if t == "C":
        return "char"
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    if t.startswith("["):
        return clean_type(t[1:]) + "[]"
    return t.replace("/", ".")


def parse_jvm_class(data: bytes) -> Tuple[List[str], List[str], List[int]]:
    """
    Parse a compiled JVM .class file binary to extract string constants,
    Utf8 symbols, and integer literals from the constant pool.
    """
    if len(data) < 10:
        return [], [], []

    magic, minor, major, cp_count = struct.unpack_from('>IHHH', data, 0)
    if magic != 0xCAFEBABE:
        return [], [], []

    pos = 10
    cp: Dict[int, Tuple[str, Any]] = {}
    i = 1
    while i < cp_count:
        if pos >= len(data):
            break
        tag = data[pos]
        pos += 1
        if tag == 1:  # Utf8
            if pos + 2 > len(data):
                break
            length, = struct.unpack_from('>H', data, pos)
            pos += 2
            val = data[pos:pos+length].decode('utf-8', errors='ignore')
            cp[i] = ('Utf8', val)
            pos += length
        elif tag in (3, 4):  # Integer, Float
            val, = struct.unpack_from('>I', data, pos)
            pos += 4
            cp[i] = ('Int' if tag == 3 else 'Float', val)
        elif tag in (5, 6):  # Long, Double
            val, = struct.unpack_from('>Q', data, pos)
            pos += 8
            cp[i] = ('Long' if tag == 5 else 'Double', val)
            i += 1  # 8-byte constants take two constant pool entries
        elif tag in (7, 8):  # Class, String
            idx, = struct.unpack_from('>H', data, pos)
            pos += 2
            cp[i] = ('Class' if tag == 7 else 'String', idx)
        elif tag in (9, 10, 11, 12, 17, 18):  # Fieldref, Methodref, InterfaceMethodref, NameAndType, Dynamic, InvokeDynamic
            a, b = struct.unpack_from('>HH', data, pos)
            pos += 4
            cp[i] = ('Ref', (a, b))
        elif tag in (15, 16, 19, 20):  # MethodHandle, MethodType, Module, Package
            pos += 3 if tag == 15 else 2
        i += 1

    strings = [cp[v[1]][1] for k, v in cp.items() if v[0] == 'String' and v[1] in cp and cp[v[1]][0] == 'Utf8']
    utf8s = [v[1] for k, v in cp.items() if v[0] == 'Utf8']
    ints = [v[1] for k, v in cp.items() if v[0] == 'Int']

    return strings, utf8s, ints


def discover_extension_entrypoints(extracted_mpe: Optional[List[Path]]) -> List[str]:
    """
    Auto-discover extension lifecycle initializers from extracted extension .mpe/.dex files.
    """
    if not extracted_mpe:
        return []

    entrypoints: List[str] = []
    seen = set()

    for dex_path in extracted_mpe:
        if not dex_path.exists():
            continue
        try:
            data = dex_path.read_bytes()
            # Fast scan for common extension entrypoint classes
            if b'SettingsEntry' in data:
                # Find exact class descriptor
                matches = re.findall(rb'L(app/[a-zA-Z0-9_/]+/SettingsEntry);', data)
                for m in set(matches):
                    cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                    ep = f"{cls_name}#onApplicationCreate"
                    if ep not in seen:
                        seen.add(ep)
                        entrypoints.append(ep)

            if b'AddOnApi' in data:
                matches = re.findall(rb'L(app/[a-zA-Z0-9_/]+/AddOnApi);', data)
                for m in set(matches):
                    cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                    ep = f"{cls_name}#initialize"
                    if ep not in seen:
                        seen.add(ep)
                        entrypoints.append(ep)

            if b'Utils' in data:
                matches = re.findall(rb'L(app/[a-zA-Z0-9_/]+/Utils);', data)
                for m in set(matches):
                    cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                    ep = f"{cls_name}#setContext"
                    if ep not in seen:
                        seen.add(ep)
                        entrypoints.append(ep)
        except Exception:
            pass

    return entrypoints


def extract_fingerprint_def(class_name: str, class_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract DexKit 2.3.0 MethodMatcher criteria from a compiled *Fingerprint.class file.
    """
    strings, utf8s, ints = parse_jvm_class(class_bytes)
    if not strings and not utf8s:
        return None

    fp: Dict[str, Any] = {}
    candidate_strings: List[str] = []

    # 1. Parse string constants
    for s in strings:
        s_clean = s.strip()
        if not s_clean:
            continue

        # Declaring class descriptor: e.g. Lcom/google/android/gms/...; or /MusicHomeActivity;
        if s_clean.startswith("L") and s_clean.endswith(";"):
            fp["declaring_class"] = clean_type(s_clean)
        elif s_clean.startswith("/") and s_clean.endswith(";"):
            fp["declaring_class_ends_with"] = s_clean.strip("/;").replace("/", ".")
        # Return type: single character smali primitive
        elif s_clean in ("V", "Z", "I", "J", "F", "D", "S", "B", "C"):
            fp["return_type"] = clean_type(s_clean)
        # Parameter wildcard "L" (object without type)
        elif s_clean == "L":
            fp["param_count"] = fp.get("param_count", 0) + 1
        # Method name: clean alphanumeric identifier
        elif re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$", s_clean) and s_clean not in (
            "V", "Z", "I", "J", "F", "D", "S", "B", "C", "L", "<this>", "patch", "injected", "method"
        ):
            if "method_name" not in fp:
                fp["method_name"] = s_clean
        # Search strings used inside the method (features, preferences, flags)
        elif any(c in s_clean for c in (".", "_", " ", "/", "-", ":", "@")):
            if not s_clean.startswith("(") and len(s_clean) > 2:
                candidate_strings.append(s_clean)

    if candidate_strings:
        fp["strings"] = candidate_strings[:5]

    # Numeric literals (e.g. integer IDs)
    valid_ints = [i for i in ints if 1000 < i < 2000000000]
    if valid_ints and "literal" not in fp:
        fp["literal"] = valid_ints[0]

    return fp if (fp.get("declaring_class") or fp.get("declaring_class_ends_with") or fp.get("strings") or fp.get("method_name")) else None


INVOKE_STATIC_RE = re.compile(
    r"invoke-static(?:\s*/range)?\s*\{[^}]*\},?\s*([a-zA-Z0-9_/$]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)"
)


def classify_action_from_patch(patch_bytes: bytes) -> Tuple[str, Optional[Any], Optional[str]]:
    """
    Classify smali bytecode instructions in a *PatchKt.class file into a LibXposed API 102 action.
    Uses non-backtracking scanning for sub-second execution across large archives.
    """
    strings, utf8s, _ = parse_jvm_class(patch_bytes)
    all_text = " ".join(strings + utf8s)

    has_super = "invoke-super" in all_text
    has_create = "onCreate" in all_text or "attachBaseContext" in all_text
    has_branch = "if-eqz" in all_text or "if-nez" in all_text

    m_inv = INVOKE_STATIC_RE.search(all_text)
    ext_call = m_inv.group(1).lstrip("L").rstrip(";") if m_inv else None

    # 1. Lifecycle hook: onCreate / attachBaseContext -> METHOD_AFTER
    if has_super and has_create:
        return "METHOD_AFTER", None, ext_call

    # 2. Early return suppressor
    if has_branch and ext_call:
        return "EARLY_RETURN_SUPPRESSOR", None, ext_call

    # 3. Direct method replacement / custom hook initializer
    if ext_call and any(k in all_text for k in ("initialize", "hook", "Extension", "watch")):
        return "METHOD_REPLACE", None, ext_call

    # 4. Constant replace
    if "return-void" in all_text:
        return "CONSTANT_REPLACE", "void", None
    if "const/4" in all_text and "0x0" in all_text:
        return "CONSTANT_REPLACE", False, None
    if "const/4" in all_text and "0x1" in all_text:
        return "CONSTANT_REPLACE", True, None

    # Default to CONSTANT_REPLACE false (safe suppression) or METHOD_REPLACE
    return "CONSTANT_REPLACE", False, None


def generate_hook_recipe_json(
    pkg: str,
    app_info: DiscoveredApp,
    archive: Optional[MppArchive] = None,
    extracted_mpe: Optional[List[Path]] = None
) -> str:
    """
    Generate dynamic hooks.json manifest for any application by scanning
    its compiled .mpp archive. Zero hardcoded per-app branches.
    """
    hooks: List[Dict[str, Any]] = []
    seen_hook_ids = set()

    # 1. Discover extension entrypoints
    entrypoints = discover_extension_entrypoints(extracted_mpe)

    # 2. Extract hook recipes from .mpp archive if provided
    if archive and archive.path.exists():
        app_tag = app_info.app_tag
        with zipfile.ZipFile(archive.path, "r") as z:
            names = z.namelist()

            # Find matching patch directories
            prefix = f"app/morphe/patches/{app_tag}/"
            alt_prefix = f"app/crimera/patches/{app_tag}/"
            app_files = [n for n in names if (n.startswith(prefix) or n.startswith(alt_prefix)) and n.endswith(".class") and "$" not in n]

            # Also include shared patches (like GoogleApiActivityOnCreateFingerprint)
            shared_files = [n for n in names if ("patches/shared/" in n or "patches/all/" in n) and n.endswith(".class") and "$" not in n]

            # Group by patch directory
            patch_dirs: Dict[str, List[str]] = {}
            for f in app_files + shared_files:
                d = str(Path(f).parent)
                patch_dirs.setdefault(d, []).append(f)

            for d, files in patch_dirs.items():
                patch_file = next((f for f in files if f.endswith("PatchKt.class")), None)
                fp_files = [f for f in files if f.endswith("Fingerprint.class")]

                action_type = "CONSTANT_REPLACE"
                constant_val: Any = False
                ext_call: Optional[str] = None
                patch_name = ""

                if patch_file:
                    try:
                        p_data = z.read(patch_file)
                        action_type, constant_val, ext_call = classify_action_from_patch(p_data)
                        p_strings, _, _ = parse_jvm_class(p_data)
                        # Extract patch display name
                        patch_name = next((s for s in p_strings if 3 < len(s) < 40 and not s.startswith("L") and not s.startswith("$") and " " in s), "")
                    except Exception:
                        pass

                for fp_file in fp_files:
                    fp_name = Path(fp_file).stem.replace("Fingerprint", "")
                    hook_id = re.sub(r"[^a-z0-9]+", "_", fp_name.lower()).strip("_")
                    if hook_id in seen_hook_ids:
                        continue

                    try:
                        fp_data = z.read(fp_file)
                        fp_def = extract_fingerprint_def(fp_file, fp_data)
                        if not fp_def:
                            continue

                        # Special case: GoogleApiActivity is a lifecycle hook -> METHOD_AFTER
                        if "GoogleApiActivity" in fp_def.get("declaring_class", ""):
                            action_type = "METHOD_AFTER"
                            if not ext_call:
                                ext_call = f"app.morphe.extension.{app_tag}.settings.YouTubeActivityHook->initialize(Landroid/app/Activity;)V"

                        hook_recipe: Dict[str, Any] = {
                            "id": hook_id,
                            "name": patch_name or fp_name,
                            "action": action_type,
                            "fingerprint": fp_def
                        }
                        if constant_val is not None:
                            hook_recipe["constant_val"] = constant_val
                        if ext_call:
                            hook_recipe["extension_call"] = ext_call

                        hooks.append(hook_recipe)
                        seen_hook_ids.add(hook_id)
                    except Exception:
                        pass

    manifest = {
        "version": 1,
        "package_name": pkg,
        "entrypoints": entrypoints,
        "hooks": hooks
    }

    return json.dumps(manifest, indent=2)
