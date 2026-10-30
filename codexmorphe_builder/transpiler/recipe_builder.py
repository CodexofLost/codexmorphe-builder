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
    Extract DexKit 2.3.0 MethodMatcher criteria from a compiled *Fingerprint.class file
    by safely inspecting the <init> constructor bytecode instructions.
    """
    if len(class_bytes) < 10:
        return None
    magic, minor, major, cp_count = struct.unpack_from('>IHHH', class_bytes, 0)
    if magic != 0xCAFEBABE:
        return None

    pos = 10
    cp: Dict[int, Tuple[str, Any]] = {}
    i = 1
    while i < cp_count:
        if pos >= len(class_bytes):
            break
        tag = class_bytes[pos]
        pos += 1
        if tag == 1:  # Utf8
            if pos + 2 > len(class_bytes):
                break
            length, = struct.unpack_from('>H', class_bytes, pos)
            pos += 2
            val = class_bytes[pos:pos+length].decode('utf-8', errors='ignore')
            cp[i] = ('Utf8', val)
            pos += length
        elif tag in (3, 4):  # Integer, Float
            val, = struct.unpack_from('>I', class_bytes, pos)
            pos += 4
            cp[i] = ('Int' if tag == 3 else 'Float', val)
        elif tag in (5, 6):  # Long, Double
            val, = struct.unpack_from('>Q', class_bytes, pos)
            pos += 8
            cp[i] = ('Long' if tag == 5 else 'Double', val)
            i += 1
        elif tag in (7, 8):  # Class, String
            idx, = struct.unpack_from('>H', class_bytes, pos)
            pos += 2
            cp[i] = ('Ref', idx)
        elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
            ref = struct.unpack_from('>HH', class_bytes, pos)
            pos += 4
            cp[i] = ('Ref2', ref)
        elif tag == 12:  # NameAndType
            nat = struct.unpack_from('>HH', class_bytes, pos)
            pos += 4
            cp[i] = ('NameAndType', nat)
        elif tag in (15, 16, 17, 18, 19, 20):
            pos += 3 if tag == 15 else 4 if tag in (17, 18) else 2
        i += 1

    if pos + 8 > len(class_bytes):
        return None
    access, this_c, super_c, if_cnt = struct.unpack_from('>HHHH', class_bytes, pos)
    pos += 8 + if_cnt * 2

    if pos + 2 > len(class_bytes):
        return None
    f_cnt, = struct.unpack_from('>H', class_bytes, pos)
    pos += 2
    for _ in range(f_cnt):
        if pos + 8 > len(class_bytes):
            return None
        _, _, _, a_cnt = struct.unpack_from('>HHHH', class_bytes, pos)
        pos += 8
        for _ in range(a_cnt):
            if pos + 6 > len(class_bytes):
                return None
            _, a_len = struct.unpack_from('>HI', class_bytes, pos)
            pos += 6 + a_len

    if pos + 2 > len(class_bytes):
        return None
    m_cnt, = struct.unpack_from('>H', class_bytes, pos)
    pos += 2
    init_code = b''
    for _ in range(m_cnt):
        if pos + 8 > len(class_bytes):
            return None
        _, m_name_idx, _, a_cnt = struct.unpack_from('>HHHH', class_bytes, pos)
        pos += 8
        m_name = cp.get(m_name_idx, ('', ''))[1]
        for _ in range(a_cnt):
            if pos + 6 > len(class_bytes):
                return None
            a_name_idx, a_len = struct.unpack_from('>HI', class_bytes, pos)
            pos += 6
            a_name = cp.get(a_name_idx, ('', ''))[1]
            if a_name == 'Code' and m_name == '<init>':
                if pos + 8 <= len(class_bytes):
                    max_s, max_l, c_len = struct.unpack_from('>HHI', class_bytes, pos)
                    init_code = class_bytes[pos+8:pos+8+c_len]
            pos += a_len

    # Parse instructions inside <init>
    idx = 0
    instructions: List[Tuple[str, Any]] = []
    while idx < len(init_code):
        op = init_code[idx]
        if op == 0x12 and idx + 1 < len(init_code):
            c_idx = init_code[idx+1]
            idx += 2
            val = cp.get(c_idx)
            val_resolved = cp.get(val[1])[1] if val and val[0] == 'Ref' else (val[1] if val else None)
            instructions.append(('ldc', val_resolved))
        elif op == 0x13 and idx + 2 < len(init_code):
            c_idx, = struct.unpack_from('>H', init_code, idx+1)
            idx += 3
            val = cp.get(c_idx)
            val_resolved = cp.get(val[1])[1] if val and val[0] == 'Ref' else (val[1] if val else None)
            instructions.append(('ldc', val_resolved))
        elif op in (0xb8, 0xb7) and idx + 2 < len(init_code):
            m_idx, = struct.unpack_from('>H', init_code, idx+1)
            idx += 3
            ref = cp.get(m_idx)
            if ref and ref[0] == 'Ref2':
                c_n = cp.get(cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                nat = cp.get(ref[1][1])
                m_n = cp.get(nat[1][0], (None, ''))[1] if nat else ''
                m_d = cp.get(nat[1][1], (None, ''))[1] if nat else ''
                instructions.append(('invoke', f'{c_n}->{m_n}{m_d}'))
        elif op == 0xbd and idx + 2 < len(init_code):
            a_idx, = struct.unpack_from('>H', init_code, idx+1)
            idx += 3
            c_n = cp.get(cp.get(a_idx, (None, None))[1], (None, ''))[1]
            instructions.append(('anewarray', c_n))
        elif op == 0x53:
            instructions.append(('aastore', None))
            idx += 1
        else:
            idx += 1

    fp: Dict[str, Any] = {}
    pending_list: List[Any] = []
    in_array = False
    param_types: List[str] = []
    candidate_strings: List[str] = []

    i = 0
    while i < len(instructions):
        itype, ival = instructions[i]
        if itype == 'anewarray':
            in_array = True
            pending_list = []
        elif itype == 'ldc':
            if in_array:
                pending_list.append(ival)
            else:
                # Check if this single ldc is passed directly to listOf
                if i + 1 < len(instructions) and instructions[i+1][0] == 'invoke' and 'listOf' in instructions[i+1][1]:
                    if isinstance(ival, str):
                        if ival.startswith('L') or ival in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C'):
                            param_types.append(clean_type(ival))
                        elif len(ival) > 2:
                            candidate_strings.append(ival)
                    i += 2
                    continue

                # Check if followed by stringFilter
                if i + 1 < len(instructions) and instructions[i+1][0] == 'invoke' and 'string' in instructions[i+1][1].lower():
                    if isinstance(ival, str) and len(ival) > 1:
                        candidate_strings.append(ival)
                    i += 2
                    continue

                # Direct scalar ldc argument to Fingerprint.<init>
                if isinstance(ival, str):
                    s_clean = ival.strip()
                    if s_clean.startswith('L') and s_clean.endswith(';'):
                        if 'declaring_class' not in fp:
                            fp['declaring_class'] = clean_type(s_clean)
                    elif s_clean.startswith('/') and s_clean.endswith(';'):
                        fp['declaring_class_ends_with'] = s_clean.strip('/;').replace('/', '.')
                    elif s_clean in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C'):
                        if 'return_type' not in fp:
                            fp['return_type'] = clean_type(s_clean)
                    elif re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', s_clean) and s_clean not in (
                        'V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C', 'L', '<this>', 'this', 'patch', 'injected', 'method'
                    ):
                        if 'method_name' not in fp:
                            fp['method_name'] = s_clean
                    elif any(c in s_clean for c in ('.', '_', ' ', '/', '-', ':', '@')) and not s_clean.startswith('('):
                        if len(s_clean) > 2:
                            candidate_strings.append(s_clean)
                elif isinstance(ival, int) and 1000 < ival < 2000000000:
                    if 'literal' not in fp:
                        fp['literal'] = ival
        elif itype == 'invoke':
            if in_array and 'listOf' in ival:
                in_array = False
                is_type_list = all(isinstance(x, str) and (x.startswith('L') or x in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C', 'L')) for x in pending_list)
                if is_type_list and pending_list:
                    param_types.extend([clean_type(x) for x in pending_list])
                else:
                    for x in pending_list:
                        if isinstance(x, str) and len(x) > 2:
                            candidate_strings.append(x)
                pending_list = []
        i += 1

    if param_types:
        fp['param_types'] = param_types
    if candidate_strings:
        fp['strings'] = candidate_strings[:5]

    # Enforce discriminator requirement: never emit an ambiguous query
    has_discriminator = bool(
        fp.get('method_name') or
        fp.get('strings') or
        fp.get('param_types') or
        fp.get('literal') or
        fp.get('param_count', 0) > 0
    )
    if not has_discriminator:
        return None

    return fp


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

    m_inv = re.search(
        r"(?:Lapp/[a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)|(?:invoke-static[^\n]*\s*([a-zA-Z0-9_/$]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*))",
        all_text
    )
    ext_call = m_inv.group(1) if (m_inv and m_inv.group(1)) else (m_inv.group(0) if m_inv else None)
    if ext_call:
        ext_call = ext_call.lstrip("L").rstrip(";")

    # 1. Lifecycle hook: onCreate / attachBaseContext -> METHOD_AFTER
    if has_super and has_create:
        return "METHOD_AFTER", None, ext_call

    # 2. Early return suppressor
    if has_branch and ext_call:
        return "EARLY_RETURN_SUPPRESSOR", None, ext_call

    # 3. Direct method replacement / custom hook initializer
    if ext_call and any(k in all_text for k in ("initialize", "hook", "Extension", "watch")):
        return "METHOD_REPLACE", None, ext_call

    # 4. Strict constant replace ONLY if explicit return constant is present
    if "return-void" in all_text and not ext_call:
        return "CONSTANT_REPLACE", "void", None
    if "const/4" in all_text and "0x0" in all_text and not ext_call:
        return "CONSTANT_REPLACE", False, None
    if "const/4" in all_text and "0x1" in all_text and not ext_call:
        return "CONSTANT_REPLACE", True, None

    # Never default to CONSTANT_REPLACE false! Return None to indicate no actionable hook
    return "UNKNOWN", None, ext_call


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

            patch_classes = [
                n for n in names
                if n.endswith(".class") and "$" not in n and ("PatchKt" in n or n.endswith("Patch.class"))
                and (f"/{app_tag}/" in n or "/shared/" in n or "/all/" in n or app_tag in n)
            ]
            fp_file_map = {n.split("/")[-1]: n for n in names if n.endswith("Fingerprint.class") and "$" not in n}

            for pf in patch_classes:
                try:
                    p_data = z.read(pf)
                    p_strings, _, _ = parse_jvm_class(p_data)
                    patch_name = next((s for s in p_strings if 3 < len(s) < 40 and not s.startswith("L") and not s.startswith("$") and " " in s), "")

                    fp_refs = set(re.findall(rb'[a-zA-Z0-9_/]+/[a-zA-Z0-9_]+Fingerprint', p_data))
                    ext_calls_raw = set(re.findall(rb'(?:Lapp/[a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', p_data))
                    ext_calls = [e.decode("utf-8", errors="ignore").lstrip("L").rstrip(";") for e in ext_calls_raw]

                    for fp_raw in fp_refs:
                        fp_cls = fp_raw.decode("utf-8", errors="ignore")
                        fp_name = fp_cls.split("/")[-1].replace("Fingerprint", "")
                        hook_id = re.sub(r"[^a-z0-9]+", "_", fp_name.lower()).strip("_")
                        if hook_id in seen_hook_ids:
                            continue

                        fp_file = fp_file_map.get(fp_cls.split("/")[-1] + ".class")
                        if not fp_file:
                            continue

                        fp_data = z.read(fp_file)
                        fp_def = extract_fingerprint_def(fp_file, fp_data)
                        if not fp_def:
                            continue

                        # Require discriminator: never emit overbroad queries that match random methods
                        if not fp_def.get("method_name") and not fp_def.get("declaring_class") and not fp_def.get("declaring_class_ends_with"):
                            continue

                        # Match to best extension call by token overlap
                        best_ext = None
                        if ext_calls:
                            words = [w for w in re.split(r'[^a-z0-9]', re.sub(r'([a-z])([A-Z])', r'\1 \2', fp_name).lower()) if len(w) > 3]
                            for ext in ext_calls:
                                mtd = ext.split("->")[1].split("(")[0].lower()
                                if any(w in mtd for w in words) or mtd in fp_name.lower() or fp_name.lower() in mtd:
                                    best_ext = ext
                                    break
                            if not best_ext and len(ext_calls) <= 2:
                                best_ext = ext_calls[0]

                        # Only emit if an extension call was resolved or if GoogleApiActivity lifecycle hook
                        if "GoogleApiActivity" in fp_def.get("declaring_class", ""):
                            best_ext = f"app.morphe.extension.{app_tag}.settings.YouTubeActivityHook->initialize(Landroid/app/Activity;)V"

                        if not best_ext:
                            continue

                        action = "METHOD_AFTER"
                        if best_ext.endswith(")Z"):
                            action = "EARLY_RETURN_SUPPRESSOR"
                        elif best_ext.endswith(")V"):
                            action = "METHOD_AFTER"
                        else:
                            action = "RETURN_TRANSFORM"

                        hook_recipe: Dict[str, Any] = {
                            "id": hook_id,
                            "name": patch_name or fp_name,
                            "action": action,
                            "fingerprint": fp_def,
                            "extension_call": best_ext
                        }

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
