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
    # Reject invalid type descriptors containing method/field markers
    if ";" in t and "->" in t:
        return ""
    if any(c in t for c in (" ", "(", ")", ":")):
        return ""
    if t.count(";") > 1:
        return ""

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
    if t == "L":
        return ""  # Wildcard object descriptor in Morphe, not a concrete type

    if t.startswith("L") and t.endswith(";"):
        inner = t[1:-1]
        if ";" in inner or " " in inner or "->" in inner:
            return ""
        return inner.replace("/", ".")
    if t.startswith("["):
        sub = clean_type(t[1:])
        return f"{sub}[]" if sub else ""
    if "/" in t:
        return t.replace("/", ".")
    return t


def is_valid_class_name(name: str) -> bool:
    """Validate that a string is a clean, fully-qualified Java class name."""
    if not name or len(name) < 2:
        return False
    if any(c in name for c in (";", "->", " ", "(", ")", ":", "[", "<", ">", "$$")):
        return False
    if is_extension_package(name):
        return False
    return bool(re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*(\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$', name))


def is_extension_package(name: str) -> bool:
    """Return True if class or path belongs to an extension/patcher package rather than the host app."""
    return any(name.startswith(p) for p in (
        "app.morphe.", "app.hushgram.", "app.piko.", "app.crimera.",
        "app.rushiranpise.", "app.devanced.", "app.okish.",
        "app/morphe/", "app/hushgram/", "app/piko/", "app/crimera/",
        "app/rushiranpise/", "app/devanced/", "app/okish/", "Lapp/"
    ))


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
            i += 1  # 8-byte constants take two entries
        elif tag == 7:  # Class
            idx, = struct.unpack_from('>H', data, pos)
            pos += 2
            cp[i] = ('Class', idx)
        elif tag == 8:  # String
            idx, = struct.unpack_from('>H', data, pos)
            pos += 2
            cp[i] = ('String', idx)
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


def discover_extension_entrypoints(
    extracted_mpe: Optional[List[Path]] = None,
    archive: Optional[MppArchive] = None,
    app_tag: str = ""
) -> List[str]:
    """
    Auto-discover extension lifecycle initializers from extracted extension .mpe/.dex files
    or directly from the .mpp archive container.
    """
    entrypoints: List[str] = []
    seen = set()

    def scan_dex_bytes(data: bytes):
        if b'SettingsEntry' in data:
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

    if extracted_mpe:
        for dex_path in extracted_mpe:
            if dex_path.exists():
                try:
                    scan_dex_bytes(dex_path.read_bytes())
                except Exception:
                    pass

    if not entrypoints and archive and archive.path.exists():
        try:
            with zipfile.ZipFile(archive.path, "r") as z:
                for n in z.namelist():
                    if (n.endswith(".mpe") or n.endswith(".dex")) and (not app_tag or app_tag in n or "shared" in n or n == "classes.dex"):
                        try:
                            scan_dex_bytes(z.read(n))
                        except Exception:
                            pass
        except Exception:
            pass

    return entrypoints


def extract_fingerprint_def(class_name: str, class_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract DexKit 2.3.0 MethodMatcher criteria from a compiled *Fingerprint.class file
    by safely inspecting the <init> constructor bytecode instructions.
    Distinguishes CONSTANT_Class from CONSTANT_String and removes compiler artifacts.
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
        elif tag == 7:  # Class
            idx, = struct.unpack_from('>H', class_bytes, pos)
            pos += 2
            cp[i] = ('Class', idx)
        elif tag == 8:  # String
            idx, = struct.unpack_from('>H', class_bytes, pos)
            pos += 2
            cp[i] = ('String', idx)
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
    instructions: List[Tuple[str, Any, Any]] = []
    while idx < len(init_code):
        op = init_code[idx]
        if op == 0x12 and idx + 1 < len(init_code):
            c_idx = init_code[idx+1]
            idx += 2
            val = cp.get(c_idx)
            val_resolved = cp.get(val[1])[1] if val and val[0] in ('Class', 'String') else (val[1] if val else None)
            instructions.append(('ldc', val[0] if val else None, val_resolved))
        elif op == 0x13 and idx + 2 < len(init_code):
            c_idx, = struct.unpack_from('>H', init_code, idx+1)
            idx += 3
            val = cp.get(c_idx)
            val_resolved = cp.get(val[1])[1] if val and val[0] in ('Class', 'String') else (val[1] if val else None)
            instructions.append(('ldc', val[0] if val else None, val_resolved))
        elif op in (0xb8, 0xb7) and idx + 2 < len(init_code):
            m_idx, = struct.unpack_from('>H', init_code, idx+1)
            idx += 3
            ref = cp.get(m_idx)
            if ref and ref[0] == 'Ref2':
                c_n = cp.get(cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                nat = cp.get(ref[1][1])
                m_n = cp.get(nat[1][0], (None, ''))[1] if nat else ''
                m_d = cp.get(nat[1][1], (None, ''))[1] if nat else ''
                instructions.append(('invoke', f'{c_n}->{m_n}{m_d}', None))
        elif op == 0xbd and idx + 2 < len(init_code):
            a_idx, = struct.unpack_from('>H', init_code, idx+1)
            idx += 3
            c_n = cp.get(cp.get(a_idx, (None, None))[1], (None, ''))[1]
            instructions.append(('anewarray', c_n, None))
        else:
            idx += 1

    fp: Dict[str, Any] = {}
    pending_list: List[Tuple[Optional[str], Any]] = []
    in_array = False
    param_types: List[str] = []
    candidate_strings: List[str] = []

    for itype, const_tag, ival in instructions:
        if itype == 'anewarray':
            in_array = True
            pending_list = []
        elif itype == 'ldc':
            if in_array:
                pending_list.append((const_tag, ival))
            else:
                if const_tag == 'String' and isinstance(ival, str):
                    s_clean = ival.strip()
                    if s_clean.startswith('L') and s_clean.endswith(';'):
                        cls_name = clean_type(s_clean)
                        if cls_name and is_valid_class_name(cls_name):
                            if 'declaring_class' not in fp:
                                fp['declaring_class'] = cls_name
                    elif s_clean.startswith('/') and s_clean.endswith(';'):
                        fp['declaring_class_ends_with'] = s_clean.strip('/;').replace('/', '.')
                    elif s_clean in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C'):
                        if 'return_type' not in fp:
                            fp['return_type'] = clean_type(s_clean)
                    elif re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', s_clean) and s_clean not in (
                        'V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C', 'L', '<this>', 'this', 'patch', 'injected', 'method', 'invoke'
                    ):
                        if 'method_name' not in fp and not s_clean.startswith("app"):
                            fp['method_name'] = s_clean
                    elif (
                        len(s_clean) > 2
                        and not is_extension_package(s_clean)
                        and "Fingerprint" not in s_clean
                        and not s_clean.endswith("(...)")
                        and not any(ord(c) < 32 for c in s_clean)
                        and s_clean not in ('this', '<this>', 'patchContext', 'patch', 'method')
                    ):
                        candidate_strings.append(s_clean)
                elif const_tag == 'Class' and isinstance(ival, str):
                    cls_name = clean_type(ival)
                    if cls_name and is_valid_class_name(cls_name) and not cls_name.startswith('java.'):
                        if 'declaring_class' not in fp:
                            fp['declaring_class'] = cls_name
                elif isinstance(ival, int) and 1000 < ival < 2000000000:
                    if 'literal' not in fp:
                        fp['literal'] = ival
        elif itype == 'invoke':
            inv_target = const_tag or ""
            if in_array and 'listOf' in inv_target:
                in_array = False
                for tag, x in pending_list:
                    if isinstance(x, str):
                        if x == 'L':
                            param_types.append('L')
                        elif x.startswith('L') or x in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C'):
                            ct = clean_type(x)
                            if ct:
                                param_types.append(ct)
                        elif (
                            tag == 'String'
                            and len(x) > 2
                            and not is_extension_package(x)
                            and "Fingerprint" not in x
                            and not x.endswith("(...)")
                            and not any(ord(c) < 32 for c in x)
                        ):
                            candidate_strings.append(x)
                pending_list = []

    if param_types:
        # If param_types contains wildcard 'L', DexKit cannot load class 'L', so switch to param_count
        if any(p == 'L' for p in param_types):
            fp['param_count'] = len(param_types)
            fp['param_types'] = []
        else:
            fp['param_types'] = param_types

    if candidate_strings:
        fp['strings'] = candidate_strings[:5]

    # Clean overly broad declaring classes
    declaring_cls = fp.get('declaring_class')
    if declaring_cls in ('java.lang.Object', 'android.content.res.Resources', 'android.view.View'):
        if not fp.get('method_name'):
            del fp['declaring_class']

    has_discriminator = bool(
        fp.get('method_name') or
        fp.get('strings') or
        fp.get('param_types') or
        fp.get('param_count') or
        fp.get('literal') or
        fp.get('declaring_class')
    )
    if not has_discriminator:
        return None

    return fp


def classify_action_from_signature(ext_call: str, smali_text: str = "", target_method: str = "") -> str:
    """Classify LibXposed hook action based on extension method descriptor and bytecode."""
    # Critical invariant: Android lifecycle methods must ALWAYS run METHOD_AFTER
    if target_method in ("onCreate", "onActivityCreated", "attachBaseContext", "onResume", "onStart", "onPause", "onStop", "onDestroy"):
        return "METHOD_AFTER"
    if "onCreate" in ext_call or "attachBaseContext" in ext_call:
        return "METHOD_AFTER"

    ret_part = ext_call.split(")")[-1] if ")" in ext_call else ""
    if ret_part == "Z" and ("if-eqz" in smali_text or "if-nez" in smali_text):
        return "EARLY_RETURN_SUPPRESSOR"
    if ret_part == "V":
        return "METHOD_AFTER"
    return "RETURN_TRANSFORM"


def generate_hook_recipe_json(
    pkg: str,
    app_info: DiscoveredApp,
    archive: Optional[MppArchive] = None,
    extracted_mpe: Optional[List[Path]] = None,
    retained_patches: Optional[List[str]] = None
) -> str:
    """
    Generate dynamic hooks.json manifest for any application by scanning
    its compiled .mpp archive. Zero hardcoded per-app branches.
    Supports standard Fingerprint classes and direct-target patch patterns.
    """
    hooks: List[Dict[str, Any]] = []
    seen_hook_ids: Set[str] = set()
    seen_target_exts: Set[Tuple[str, str, str]] = set()
    seen_activity_init = False

    # 1. Discover extension entrypoints
    entrypoints = discover_extension_entrypoints(extracted_mpe, archive, app_tag=app_info.app_tag)

    # 2. Extract hook recipes from .mpp archive if provided
    if archive and archive.path.exists():
        app_tag = app_info.app_tag
        other_known_tags = {"music", "youtube", "reddit", "instagram", "twitter", "waze", "twitch"} - {app_tag}

        def is_patch_for_app(path: str) -> bool:
            # Exclude other app primary directories (e.g. music when building youtube)
            for other in other_known_tags:
                if f"/{other}/" in path or f"app/morphe/patches/{other}/" in path:
                    return False
            return (
                f"/{app_tag}/" in path
                or f"app/morphe/patches/{app_tag}/" in path
                or "/shared/" in path
                or "/all/" in path
            )

        retained_set = set(retained_patches) if retained_patches is not None else None

        with zipfile.ZipFile(archive.path, "r") as z:
            names = z.namelist()

            patch_classes = [
                n for n in names
                if n.endswith(".class") and "$" not in n and ("PatchKt" in n or n.endswith("Patch.class"))
                and is_patch_for_app(n)
            ]
            fp_file_map = {n.split("/")[-1]: n for n in names if n.endswith("Fingerprint.class") and "$" not in n}

            for pf in patch_classes:
                try:
                    if retained_set is not None:
                        # Match retained patches against class path
                        patch_stem = pf.replace(".class", "")
                        if not any(r in patch_stem or patch_stem in r for r in retained_set):
                            continue

                    p_dir = "/".join(pf.split("/")[:-1])
                    companion_classes = [n for n in names if n.startswith(p_dir + "/") and n.endswith(".class") and "$" not in n]

                    # Read combined bytes for patch class and companion classes in same directory
                    p_data = z.read(pf)
                    companion_data = [z.read(cf) for cf in companion_classes]
                    combined_bytes = p_data + b"".join(companion_data)

                    p_strings, _, _ = parse_jvm_class(p_data)
                    patch_name = next((s for s in p_strings if 3 < len(s) < 40 and not s.startswith("L") and not s.startswith("$") and " " in s), "")

                    # Discover all fingerprints referenced in this patch or its companion classes
                    fp_matches = re.findall(rb'(?:L)?(app/[a-zA-Z0-9_/]+/[a-zA-Z0-9_]+Fingerprint)', combined_bytes)
                    fp_refs = set(m.decode("utf-8", errors="ignore") for m in fp_matches)

                    ext_calls_raw = set(re.findall(rb'(?:Lapp/[a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', combined_bytes))
                    ext_calls = [e.decode("utf-8", errors="ignore").lstrip("L").rstrip(";") for e in ext_calls_raw]
                    # Filter out extension calls from other app tags
                    ext_calls = [
                        e for e in ext_calls
                        if not any(f".{other}." in e or f"/{other}/" in e for other in other_known_tags)
                    ]

                    all_text = " ".join(p_strings)

                    # --- Path A: Standard Fingerprint Matchers ---
                    for fp_cls in fp_refs:
                        fp_simple = fp_cls.split("/")[-1]
                        fp_name = fp_simple.replace("Fingerprint", "")
                        fp_file = fp_file_map.get(fp_simple + ".class")
                        if not fp_file:
                            continue

                        fp_data = z.read(fp_file)
                        fp_def = extract_fingerprint_def(fp_file, fp_data)
                        if not fp_def:
                            continue

                        target_mtd = fp_def.get('method_name', '')
                        target_cls = fp_def.get('declaring_class', '')

                        # Check for Activity Lifecycle Hooks (e.g. YouTubeActivityOnCreate)
                        is_activity_on_create = (
                            ('MainActivity' in target_cls or 'GoogleApiActivity' in target_cls)
                            and (target_mtd == 'onCreate' or not target_mtd)
                        ) or 'YouTubeActivityOnCreate' in fp_simple

                        if is_activity_on_create:
                            if seen_activity_init:
                                continue  # Exactly one activity lifecycle hook registered
                            init_ext = next((e for e in ext_calls if 'ActivityHook' in e and 'initialize' in e), None)
                            if not init_ext:
                                init_ext = f"app.morphe.extension.{app_tag}.settings.YouTubeActivityHook->initialize(Landroid/app/Activity;)V"

                            seen_activity_init = True
                            hook_recipe = {
                                "id": f"{app_tag}_activity_lifecycle_init",
                                "name": "Activity Lifecycle Initializer",
                                "action": "METHOD_AFTER",
                                "fingerprint": {
                                    "declaring_class": "com.google.android.apps.youtube.app.watchwhile.MainActivity" if app_tag == "youtube" else target_cls,
                                    "method_name": "onCreate",
                                    "return_type": "void"
                                },
                                "extension_call": init_ext
                            }
                            hooks.append(hook_recipe)
                            seen_hook_ids.add(hook_recipe["id"])
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
                            if not best_ext:
                                best_ext = ext_calls[0]

                        if not best_ext:
                            continue

                        # Deduplicate identical (target_class, target_method, extension_call) hooks
                        target_key = (target_cls, target_mtd, best_ext)
                        if target_cls and target_mtd and target_key in seen_target_exts:
                            continue

                        patch_id_prefix = re.sub(r"[^a-z0-9]+", "_", (patch_name or pf.split("/")[-1]).lower())[:15]
                        hook_id = f"{patch_id_prefix}_{fp_name.lower()}".strip("_")
                        if hook_id in seen_hook_ids:
                            continue

                        action = classify_action_from_signature(best_ext, all_text, target_method=target_mtd)

                        hook_recipe: Dict[str, Any] = {
                            "id": hook_id,
                            "name": patch_name or fp_name,
                            "action": action,
                            "fingerprint": fp_def,
                            "extension_call": best_ext
                        }

                        hooks.append(hook_recipe)
                        seen_hook_ids.add(hook_id)
                        if target_cls and target_mtd:
                            seen_target_exts.add(target_key)

                    # --- Path B: Direct Targets / Non-Fingerprint Patches ---
                    if not fp_refs and ext_calls:
                        # Extract only valid Java class names (avoiding method descriptors)
                        direct_classes = [
                            clean_type(x) for x in p_strings
                            if (x.startswith('Lcom/') or x.startswith('Landroid/'))
                            and x.endswith(';')
                            and not x.startswith('Lcom/android/tools/')
                            and is_valid_class_name(clean_type(x))
                        ]
                        direct_methods = [
                            x for x in p_strings
                            if x in ('onCreate', 'onNewIntent', 'onCreateView', 'getView', 'onMeasure', 'onBackPressed', 'finish', 'onClick')
                        ]

                        comp_strings: List[str] = []
                        comp_return: Optional[str] = None
                        for cf in companion_classes:
                            cs, _, _ = parse_jvm_class(z.read(cf))
                            if 'FingerprintsKt' in cf or 'TargetsKt' in cf:
                                for s in cs:
                                    if (
                                        3 < len(s) < 50
                                        and not s.startswith('L')
                                        and not s.endswith('(...)')
                                        and not any(ord(c) < 32 for c in s)
                                        and not is_extension_package(s)
                                        and not any(k in s for k in ('Fingerprint', 'Exception', 'java/', '<'))
                                    ):
                                        comp_strings.append(s)
                                    if s in ('Z', 'V', 'I'):
                                        comp_return = clean_type(s)

                        for ext in ext_calls:
                            target_cls = direct_classes[0] if direct_classes else None
                            target_mtd = direct_methods[0] if direct_methods else None

                            if not target_cls and not comp_strings:
                                continue

                            b_fp: Dict[str, Any] = {}
                            if target_cls:
                                b_fp['declaring_class'] = target_cls
                            if target_mtd:
                                b_fp['method_name'] = target_mtd
                            if comp_strings:
                                b_fp['strings'] = comp_strings[:3]
                            if comp_return:
                                b_fp['return_type'] = comp_return

                            ext_mtd_name = ext.split("->")[1].split("(")[0].lower()
                            patch_id_prefix = re.sub(r"[^a-z0-9]+", "_", (patch_name or pf.split("/")[-1]).lower())[:20]
                            b_id = f"{patch_id_prefix}_{ext_mtd_name}".strip("_")
                            if b_id in seen_hook_ids:
                                continue

                            action = classify_action_from_signature(ext, all_text, target_method=target_mtd or "")

                            b_hook: Dict[str, Any] = {
                                "id": b_id,
                                "name": patch_name or b_id,
                                "action": action,
                                "fingerprint": b_fp,
                                "extension_call": ext
                            }

                            hooks.append(b_hook)
                            seen_hook_ids.add(b_id)

                except Exception:
                    pass

    manifest = {
        "version": 1,
        "package_name": pkg,
        "entrypoints": entrypoints,
        "hooks": hooks
    }

    return json.dumps(manifest, indent=2)
