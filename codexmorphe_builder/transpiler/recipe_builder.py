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
        return t.rstrip(";").replace("/", ".")
    return t.rstrip(";")


def parse_method_descriptor(desc: str) -> Tuple[List[str], str]:
    """Parse JVM method descriptor into list of clean parameter types and return type."""
    if not desc or not desc.startswith("(") or ")" not in desc:
        return [], ""
    param_str = desc[1:desc.index(")")]
    ret_str = desc[desc.index(")")+1:]

    params = []
    i = 0
    while i < len(param_str):
        c = param_str[i]
        if c in 'ZBCSIJFDV':
            params.append(clean_type(c))
            i += 1
        elif c == 'L':
            end = param_str.find(';', i)
            if end != -1:
                params.append(clean_type(param_str[i:end+1]))
                i = end + 1
            else:
                break
        elif c == '[':
            dim = 0
            while i < len(param_str) and param_str[i] == '[':
                dim += 1
                i += 1
            if i < len(param_str):
                if param_str[i] in 'ZBCSIJFD':
                    base = clean_type(param_str[i])
                    params.append(f"{base}{'[]' * dim}")
                    i += 1
                elif param_str[i] == 'L':
                    end = param_str.find(';', i)
                    if end != -1:
                        base = clean_type(param_str[i:end+1])
                        params.append(f"{base}{'[]' * dim}")
                        i = end + 1
                    else:
                        break
        else:
            i += 1
    return [p for p in params if p], clean_type(ret_str)


def is_framework_class(cls_name: str) -> bool:
    """Return True if class belongs to standard Java/Kotlin/Android framework/runtime."""
    if not cls_name:
        return False
    # Host activities and core application shells are genuine target classes
    if cls_name.endswith("Activity") or cls_name.endswith("Application") or cls_name.endswith("AppShell"):
        if not cls_name.startswith("android.app.Activity") and cls_name != "android.app.Application":
            return False
    return any(cls_name.startswith(p) for p in (
        "java.", "javax.", "kotlin.", "kotlinx.", "j$.", "com.google.protobuf.",
        "android.os.", "android.util.", "android.content.res.", "android.graphics.",
        "android.view.", "android.widget."
    ))


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
    clean = name.lstrip("L").replace("/", ".")
    return (
        clean.startswith("app.") or
        ".extension." in clean or
        clean.startswith("morphe.") or
        "patches" in clean
    )


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
) -> Tuple[List[str], List[str]]:
    """
    Auto-discover extension lifecycle initializers and ResourceUtils classes from extracted
    extension .mpe/.dex files or directly from the .mpp archive container.
    """
    entrypoints: List[str] = []
    resource_fallbacks: List[str] = []
    seen = set()
    seen_rf = set()

    def scan_dex_bytes(data: bytes):
        if b'SettingsEntry' in data:
            matches = re.findall(rb'L([a-zA-Z0-9_$/]+/SettingsEntry);', data)
            for m in set(matches):
                cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                ep = f"{cls_name}#onApplicationCreate"
                if ep not in seen:
                    seen.add(ep)
                    entrypoints.append(ep)

        if b'AddOnApi' in data:
            matches = re.findall(rb'L([a-zA-Z0-9_$/]+/AddOnApi);', data)
            for m in set(matches):
                cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                ep = f"{cls_name}#initialize"
                if ep not in seen:
                    seen.add(ep)
                    entrypoints.append(ep)

        if b'Utils' in data:
            matches = re.findall(rb'L([a-zA-Z0-9_$/]+/Utils);', data)
            for m in set(matches):
                cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                if not is_extension_package(cls_name):
                    continue
                ep = f"{cls_name}#setContext"
                if ep not in seen:
                    seen.add(ep)
                    entrypoints.append(ep)

        if b'ResourceUtils' in data:
            matches = re.findall(rb'L([a-zA-Z0-9_$/]+/ResourceUtils);', data)
            for m in set(matches):
                cls_name = m.decode('utf-8', errors='ignore').replace('/', '.')
                if cls_name not in seen_rf:
                    seen_rf.add(cls_name)
                    resource_fallbacks.append(cls_name)

    if extracted_mpe:
        for dex_path in extracted_mpe:
            if dex_path.exists():
                try:
                    scan_dex_bytes(dex_path.read_bytes())
                except Exception:
                    pass

    if (not entrypoints or not resource_fallbacks) and archive and Path(archive.path).exists():
        try:
            with zipfile.ZipFile(Path(archive.path), "r") as z:
                for n in z.namelist():
                    if (n.endswith(".mpe") or n.endswith(".dex")) and (not app_tag or app_tag in n or "shared" in n or n == "classes.dex"):
                        try:
                            scan_dex_bytes(z.read(n))
                        except Exception:
                            pass
        except Exception:
            pass

    return entrypoints, resource_fallbacks


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

    file_name = class_name.split("/")[-1].replace(".class", "")
    is_constructor = "Constructor" in file_name or file_name.endswith("ConstructorFingerprint")

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
                    if s_clean == "<init>":
                        fp['method_name'] = "<init>"
                        if 'return_type' not in fp:
                            fp['return_type'] = "void"
                    elif s_clean.startswith("(") and ")" in s_clean:
                        p_types, r_type = parse_method_descriptor(s_clean)
                        if p_types and not param_types:
                            param_types.extend(p_types)
                        if r_type and 'return_type' not in fp:
                            fp['return_type'] = r_type
                    elif s_clean.startswith('L') and s_clean.endswith(';'):
                        cls_name = clean_type(s_clean)
                        if cls_name and is_valid_class_name(cls_name):
                            if is_framework_class(cls_name):
                                if 'return_type' not in fp:
                                    fp['return_type'] = cls_name
                                else:
                                    param_types.append(cls_name)
                            else:
                                if 'declaring_class' not in fp:
                                    fp['declaring_class'] = cls_name
                                else:
                                    param_types.append(cls_name)
                    elif s_clean.startswith('/') and s_clean.endswith(';'):
                        fp['declaring_class_ends_with'] = s_clean.strip('/;').replace('/', '.')
                    elif s_clean in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C'):
                        if 'return_type' not in fp:
                            fp['return_type'] = clean_type(s_clean)
                    elif "." in s_clean and not s_clean.endswith("..."):
                        parts = s_clean.split(".")
                        if len(parts) == 2 and parts[1] == fp.get('method_name'):
                            fp['declaring_class_ends_with'] = parts[0]
                        elif (
                            len(s_clean) > 2
                            and not is_extension_package(s_clean)
                            and "Fingerprint" not in s_clean
                            and not any(ord(c) < 32 for c in s_clean)
                            and s_clean not in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>')
                        ):
                            candidate_strings.append(s_clean)
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
                        and s_clean not in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>')
                    ):
                        candidate_strings.append(s_clean)
                elif const_tag == 'Class' and isinstance(ival, str):
                    cls_name = clean_type(ival)
                    if cls_name and is_valid_class_name(cls_name) and not is_framework_class(cls_name):
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
                            and x != "<init>"
                        ):
                            candidate_strings.append(x)
                pending_list = []

    if is_constructor and ('method_name' not in fp or not fp.get('method_name')):
        fp['method_name'] = "<init>"
        if 'return_type' not in fp:
            fp['return_type'] = "void"

    if param_types:
        # If param_types contains wildcard 'L', DexKit cannot load class 'L', so switch to param_count
        if any(p == 'L' for p in param_types):
            fp['param_count'] = len(param_types)
            fp['param_types'] = []
        else:
            fp['param_types'] = param_types

    if candidate_strings:
        candidate_strings = [s for s in candidate_strings if s != "<init>"]
        if candidate_strings:
            fp['strings'] = candidate_strings[:5]

    # Check constant pool for companion Class.method hints if declaring class is not yet known
    if 'declaring_class' not in fp and 'declaring_class_ends_with' not in fp and fp.get('method_name'):
        m_name = fp['method_name']
        for _, entry in cp.items():
            if entry and entry[0] == 'Utf8' and isinstance(entry[1], str) and '.' in entry[1]:
                parts = entry[1].split('.')
                if len(parts) == 2 and parts[1] == m_name and is_valid_class_name(parts[0]):
                    fp['declaring_class_ends_with'] = parts[0]
                    break

    # Clean overly broad or framework declaring classes
    declaring_cls = fp.get('declaring_class')
    if declaring_cls:
        if is_framework_class(declaring_cls):
            if 'return_type' not in fp:
                fp['return_type'] = declaring_cls
            del fp['declaring_class']
        elif declaring_cls in ('java.lang.Object', 'android.content.res.Resources', 'android.view.View'):
            if not fp.get('method_name'):
                del fp['declaring_class']

    # CRITICAL GUARD: A fingerprint MUST have at least one specific discriminator
    # (method_name, non-empty strings, or a literal number).
    # Declaring class alone is a wildcard query that matches ALL methods in that class.
    has_discriminator = bool(
        fp.get('method_name') or
        fp.get('strings') or
        fp.get('literal') is not None
    )
    if not has_discriminator:
        return None

    COMMON_METHODS = {
        "onCreate", "onActivityCreated", "attachBaseContext", "onResume", "onStart",
        "onPause", "onStop", "onDestroy", "run", "toString", "equals", "hashCode", "close",
        "getView", "onClick", "onItemClick", "onBackPressed"
    }

    # Strict guard: Common lifecycle or ubiquitous methods must NEVER be queried globally without class or strings!
    if (
        fp.get("method_name") in COMMON_METHODS
        and not fp.get("declaring_class")
        and not fp.get("declaring_class_ends_with")
        and not fp.get("strings")
        and not fp.get("literal")
    ):
        return None

    return fp


def classify_action_from_signature(ext_call: str, smali_text: str = "", target_method: str = "", target_return: str = "") -> str:
    """Classify LibXposed hook action based on extension method descriptor and bytecode."""
    # Critical invariant: Android lifecycle methods must ALWAYS run AFTER
    if target_method in ("onCreate", "onActivityCreated", "attachBaseContext", "onResume", "onStart", "onPause", "onStop", "onDestroy"):
        return "AFTER"
    if "onCreate" in ext_call or "attachBaseContext" in ext_call:
        return "AFTER"

    # Pattern 2: Argument interception
    if "move-result-object p" in smali_text or "move-result p" in smali_text:
        return "ARG_REWRITE"

    ret_part = ext_call.split(")")[-1] if ")" in ext_call else ""
    if ret_part == "Z" and ("if-eqz" in smali_text or "if-nez" in smali_text):
        return "BEFORE"
    if ret_part == "V":
        return "AFTER"

    # Check for return type mismatch with primitive targets
    ext_clean = clean_type(ret_part)
    target_clean = clean_type(target_return) if target_return else ""
    if target_clean and ext_clean != target_clean:
        if target_clean in ("boolean", "int", "void", "long", "float", "double"):
            return "AFTER"

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

    # 1. Discover extension entrypoints & resource fallbacks
    entrypoints, resource_fallbacks = discover_extension_entrypoints(extracted_mpe, archive, app_tag=app_info.app_tag)

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

                        # Constructor detection fallback
                        if ("Constructor" in fp_simple or fp_name.endswith("Constructor")) and not fp_def.get('method_name'):
                            fp_def['method_name'] = "<init>"
                            if 'return_type' not in fp_def:
                                fp_def['return_type'] = "void"

                        # Guard against wildcard queries in Path A:
                        # Must have method_name, non-empty strings, or literal
                        if not fp_def.get('method_name') and not fp_def.get('strings') and fp_def.get('literal') is None:
                            continue

                        target_mtd = fp_def.get('method_name', '')
                        target_cls = fp_def.get('declaring_class', '')

                        # Check for Settings Trampoline Activity Lifecycle Hook (GoogleApiActivity)
                        if 'GoogleApiActivity' in target_cls:
                            if seen_activity_init:
                                continue
                            init_ext = next((e for e in ext_calls if 'ActivityHook' in e and 'initialize' in e), None)
                            if not init_ext:
                                init_ext = f"app.morphe.extension.{app_tag}.settings.YouTubeActivityHook->initialize(Landroid/app/Activity;)V"

                            seen_activity_init = True
                            init_cls = clean_type(init_ext.split("->")[0]) if "->" in init_ext else None
                            init_mtd = init_ext.split("->")[1].split("(")[0].strip() if "->" in init_ext else None
                            hook_recipe = {
                                "id": f"{app_tag}_google_api_activity_init",
                                "name": "Google API Settings Activity Initializer",
                                "action": "AFTER",
                                "fingerprint": {
                                    "declaring_class": "com.google.android.gms.common.api.GoogleApiActivity",
                                    "method_name": "onCreate",
                                    "return_type": "void",
                                    "param_types": ["android.os.Bundle"]
                                },
                                "extension_call": init_ext,
                                "extension_class": init_cls,
                                "extension_method": init_mtd
                            }
                            hooks.append(hook_recipe)
                            seen_hook_ids.add(hook_recipe["id"])
                            continue

                        # When target is MainActivity, never attach YouTubeActivityHook (it crashes with Unknown intent: null)
                        available_ext_calls = [
                            e for e in ext_calls
                            if not ('ActivityHook' in e and 'initialize' in e and 'MainActivity' in target_cls)
                        ] or ext_calls

                        # Match to best extension call by token overlap
                        best_ext = None
                        if available_ext_calls:
                            words = [w for w in re.split(r'[^a-z0-9]', re.sub(r'([a-z])([A-Z])', r'\1 \2', fp_name).lower()) if len(w) > 3]
                            for ext in available_ext_calls:
                                mtd = ext.split("->")[1].split("(")[0].lower()
                                if any(w in mtd for w in words) or mtd in fp_name.lower() or fp_name.lower() in mtd:
                                    best_ext = ext
                                    break
                            if not best_ext:
                                best_ext = available_ext_calls[0]

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

                        action = classify_action_from_signature(
                            best_ext,
                            all_text,
                            target_method=target_mtd,
                            target_return=fp_def.get('return_type', '')
                        )

                        ext_class = clean_type(best_ext.split("->")[0]) if "->" in best_ext else None
                        ext_method = best_ext.split("->")[1].split("(")[0].strip() if "->" in best_ext else None

                        hook_recipe: Dict[str, Any] = {
                            "id": hook_id,
                            "name": patch_name or fp_name,
                            "action": action,
                            "fingerprint": fp_def,
                            "extension_call": best_ext,
                            "extension_class": ext_class,
                            "extension_method": ext_method
                        }

                        hooks.append(hook_recipe)
                        seen_hook_ids.add(hook_id)
                        if target_cls and target_mtd:
                            seen_target_exts.add(target_key)

                    # --- Path B: Direct Targets / Non-Fingerprint Patches ---
                    if not fp_refs and ext_calls:
                        # Extract only valid host Java class names (avoiding framework classes and method descriptors)
                        direct_classes = [
                            clean_type(x) for x in p_strings
                            if (x.startswith('Lcom/') or x.startswith('Landroid/'))
                            and x.endswith(';')
                            and not x.startswith('Lcom/android/tools/')
                            and is_valid_class_name(clean_type(x))
                            and not is_framework_class(clean_type(x))
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
                                        4 < len(s) < 50
                                        and not s.startswith('L')
                                        and not s.endswith('(...)')
                                        and not any(ord(c) < 32 for c in s)
                                        and not is_extension_package(s)
                                        and not any(k in s.lower() for k in ('fingerprint', 'exception', 'java/', '<', 'patch', 'what', 'targets', 'predicate', 'element'))
                                    ):
                                        comp_strings.append(s)
                                    if s in ('Z', 'V', 'I'):
                                        comp_return = clean_type(s)

                        for idx, ext in enumerate(ext_calls):
                            # Resolve target class & method intelligently
                            ext_lower = ext.lower()
                            if 'onapplicationcreate' in ext_lower:
                                target_cls = next((c for c in direct_classes if 'shell' in c.lower() or 'app' in c.lower()), direct_classes[0] if direct_classes else None)
                                target_mtd = 'onCreate'
                            elif 'onnewintent' in ext_lower:
                                target_cls = next((c for c in direct_classes if 'activity' in c.lower()), direct_classes[-1] if direct_classes else None)
                                target_mtd = 'onNewIntent'
                            else:
                                target_cls = direct_classes[idx] if idx < len(direct_classes) else (direct_classes[0] if direct_classes else None)
                                target_mtd = direct_methods[idx] if idx < len(direct_methods) else (direct_methods[0] if direct_methods else None)

                            # CRITICAL GUARD: Never emit a wildcard hook without method name or unique strings
                            if not target_mtd and not comp_strings:
                                continue

                            b_fp: Dict[str, Any] = {}
                            if target_cls:
                                b_fp['declaring_class'] = target_cls
                            if target_mtd:
                                b_fp['method_name'] = target_mtd
                            # Only include strings if we don't have an exact class + method target
                            if comp_strings and (not target_cls or not target_mtd):
                                b_fp['strings'] = comp_strings[:3]
                            if comp_return:
                                b_fp['return_type'] = comp_return

                            # Reject unconstrained queries (must have method_name, non-empty strings, or literal)
                            if not b_fp.get('method_name') and not b_fp.get('strings') and b_fp.get('literal') is None:
                                continue

                            ext_mtd_name = ext.split("->")[1].split("(")[0].lower()
                            patch_id_prefix = re.sub(r"[^a-z0-9]+", "_", (patch_name or pf.split("/")[-1]).lower())[:20]
                            b_id = f"{patch_id_prefix}_{ext_mtd_name}".strip("_")
                            if b_id in seen_hook_ids:
                                continue

                            action = classify_action_from_signature(
                                ext,
                                all_text,
                                target_method=target_mtd or "",
                                target_return=comp_return or ""
                            )

                            b_ext_class = clean_type(ext.split("->")[0]) if "->" in ext else None
                            b_ext_method = ext.split("->")[1].split("(")[0].strip() if "->" in ext else None

                            b_hook: Dict[str, Any] = {
                                "id": b_id,
                                "name": patch_name or b_id,
                                "action": action,
                                "fingerprint": b_fp,
                                "extension_call": ext,
                                "extension_class": b_ext_class,
                                "extension_method": b_ext_method
                            }

                            hooks.append(b_hook)
                            seen_hook_ids.add(b_id)

                except Exception:
                    pass

    manifest = {
        "version": 1,
        "package_name": pkg,
        "entrypoints": entrypoints,
        "resource_fallbacks": resource_fallbacks,
        "hooks": hooks
    }

    return json.dumps(manifest, indent=2)
