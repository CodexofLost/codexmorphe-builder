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


class ClassfileAst:
    """
    Pure Python JVM Classfile AST and constant pool parser.
    Supports ClassFile format (major 45 through 65, Java 1.1 to 21+),
    including invokedynamic / BootstrapMethods attributes and bytecode Code inspection.
    """
    def __init__(self, data: bytes):
        self.cp: Dict[int, Tuple[str, Any]] = {}
        self.methods: Dict[Tuple[str, str], bytes] = {}
        self.bootstrap_methods: List[List[Any]] = []
        self.super_class: str = ""
        self.this_class: str = ""
        self._parse(data)

    def _parse(self, data: bytes):
        if len(data) < 10:
            return
        magic, minor, major, cp_count = struct.unpack_from('>IHHH', data, 0)
        if magic != 0xCAFEBABE:
            return
        pos = 10
        i = 1
        while i < cp_count:
            if pos >= len(data):
                break
            tag = data[pos]
            pos += 1
            if tag == 1:  # Utf8
                if pos + 2 > len(data): break
                length, = struct.unpack_from('>H', data, pos); pos += 2
                self.cp[i] = ('Utf8', data[pos:pos+length].decode('utf-8', errors='ignore'))
                pos += length
            elif tag in (3, 4):  # Integer, Float
                if pos + 4 > len(data): break
                val, = struct.unpack_from('>I', data, pos); pos += 4
                self.cp[i] = ('Int' if tag == 3 else 'Float', val)
            elif tag in (5, 6):  # Long, Double
                if pos + 8 > len(data): break
                val, = struct.unpack_from('>Q', data, pos); pos += 8
                self.cp[i] = ('Long' if tag == 5 else 'Double', val)
                i += 1  # 8-byte entries take 2 constant pool slots
            elif tag == 7:  # Class
                if pos + 2 > len(data): break
                idx, = struct.unpack_from('>H', data, pos); pos += 2
                self.cp[i] = ('Class', idx)
            elif tag == 8:  # String
                if pos + 2 > len(data): break
                idx, = struct.unpack_from('>H', data, pos); pos += 2
                self.cp[i] = ('String', idx)
            elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                if pos + 4 > len(data): break
                ref = struct.unpack_from('>HH', data, pos); pos += 4
                self.cp[i] = ('Ref2', ref)
            elif tag == 12:  # NameAndType
                if pos + 4 > len(data): break
                nat = struct.unpack_from('>HH', data, pos); pos += 4
                self.cp[i] = ('NameAndType', nat)
            elif tag in (15, 16):  # MethodHandle, MethodType
                pos += 3 if tag == 15 else 2
            elif tag in (17, 18):  # Dynamic, InvokeDynamic
                if pos + 4 > len(data): break
                bsm, nat_idx = struct.unpack_from('>HH', data, pos); pos += 4
                self.cp[i] = ('InvokeDynamic', (bsm, nat_idx))
            elif tag in (19, 20):  # Module, Package
                pos += 2
            i += 1

        if pos + 8 > len(data): return
        access, this_c, super_c, if_cnt = struct.unpack_from('>HHHH', data, pos)
        pos += 8 + if_cnt * 2

        this_entry = self.cp.get(this_c)
        if this_entry and this_entry[0] == 'Class':
            self.this_class = self.cp.get(this_entry[1], ('', ''))[1]
        super_entry = self.cp.get(super_c)
        if super_entry and super_entry[0] == 'Class':
            self.super_class = self.cp.get(super_entry[1], ('', ''))[1]

        if pos + 2 > len(data): return
        f_cnt, = struct.unpack_from('>H', data, pos); pos += 2
        for _ in range(f_cnt):
            if pos + 8 > len(data): return
            _, _, _, a_cnt = struct.unpack_from('>HHHH', data, pos); pos += 8
            for _ in range(a_cnt):
                if pos + 6 > len(data): return
                _, a_len = struct.unpack_from('>HI', data, pos); pos += 6 + a_len

        if pos + 2 > len(data): return
        m_cnt, = struct.unpack_from('>H', data, pos); pos += 2
        for _ in range(m_cnt):
            if pos + 8 > len(data): return
            _, m_name_idx, m_desc_idx, a_cnt = struct.unpack_from('>HHHH', data, pos); pos += 8
            m_name = self.cp.get(m_name_idx, ('', ''))[1]
            m_desc = self.cp.get(m_desc_idx, ('', ''))[1]
            code = b''
            for _ in range(a_cnt):
                if pos + 6 > len(data): return
                a_name_idx, a_len = struct.unpack_from('>HI', data, pos); pos += 6
                a_name = self.cp.get(a_name_idx, ('', ''))[1]
                if a_name == 'Code' and pos + 8 <= len(data):
                    _, _, c_len = struct.unpack_from('>HHI', data, pos)
                    code = data[pos+8:pos+8+c_len]
                pos += a_len
            self.methods[(m_name, m_desc)] = code

        if pos + 2 > len(data): return
        a_cnt, = struct.unpack_from('>H', data, pos); pos += 2
        for _ in range(a_cnt):
            if pos + 6 > len(data): return
            a_name_idx, a_len = struct.unpack_from('>HI', data, pos); pos += 6
            a_name = self.cp.get(a_name_idx, ('', ''))[1]
            if a_name == 'BootstrapMethods' and pos + 2 <= len(data):
                num_bsm, = struct.unpack_from('>H', data, pos)
                bpos = pos + 2
                for _ in range(num_bsm):
                    if bpos + 4 > len(data): break
                    m_ref, arg_cnt = struct.unpack_from('>HH', data, bpos); bpos += 4
                    args = []
                    for _ in range(arg_cnt):
                        if bpos + 2 > len(data): break
                        arg_idx, = struct.unpack_from('>H', data, bpos); bpos += 2
                        entry = self.cp.get(arg_idx)
                        resolved = self.cp.get(entry[1])[1] if entry and entry[0] in ('String', 'Class') else (entry[1] if entry else None)
                        args.append(resolved)
                    self.bootstrap_methods.append(args)
            pos += a_len

    def get_constant_string(self, idx: int) -> Optional[str]:
        entry = self.cp.get(idx)
        if entry:
            if entry[0] == 'String':
                utf = self.cp.get(entry[1])
                return utf[1] if utf and utf[0] == 'Utf8' else None
            elif entry[0] == 'Utf8':
                return entry[1]
        return None


def extract_fingerprint_def(class_name: str, class_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract DexKit 2.3.0 MethodMatcher criteria from a compiled *Fingerprint.class file
    by safely inspecting the <init> constructor bytecode instructions via AST operand stack evaluation.
    Distinguishes CONSTANT_Class from CONSTANT_String and removes compiler artifacts.
    """
    ast = ClassfileAst(class_bytes)
    if not ast.cp:
        return None

    # Find the <init> method bytecode
    init_code = None
    for (m_name, _), code in ast.methods.items():
        if m_name == '<init>' and code:
            init_code = code
            break
    if not init_code:
        return None

    file_name = class_name.split("/")[-1].replace(".class", "")
    is_constructor = (
        "Constructor" in file_name
        or file_name.endswith("ConstructorFingerprint")
        or file_name.endswith("CtorFingerprint")
        or "Ctor" in file_name
    )

    stack: List[Any] = []
    idx = 0
    instructions: List[Tuple[str, Any, Any]] = []

    while idx < len(init_code):
        op = init_code[idx]
        if op == 0x01:  # aconst_null
            stack.append(None); idx += 1
        elif op == 0x2a:  # aload_0 (this)
            stack.append('this'); idx += 1
        elif op in (0x12, 0x13):  # ldc, ldc_w
            if op == 0x12:
                if idx + 1 >= len(init_code): break
                c_idx = init_code[idx+1]; idx += 2
            else:
                if idx + 2 >= len(init_code): break
                c_idx, = struct.unpack_from('>H', init_code, idx+1); idx += 3
            entry = ast.cp.get(c_idx)
            val = None
            if entry:
                if entry[0] in ('Class', 'String'):
                    val_utf = ast.cp.get(entry[1])
                    val = val_utf[1] if val_utf else None
                else:
                    val = entry[1]
            instructions.append(('ldc', entry[0] if entry else None, val))
            stack.append(('ldc', entry[0] if entry else None, val))
        elif op in (0x10, 0x11):  # bipush, sipush
            if op == 0x10:
                if idx + 1 >= len(init_code): break
                v = struct.unpack_from('>b', init_code, idx+1)[0]; idx += 2
            else:
                if idx + 2 >= len(init_code): break
                v = struct.unpack_from('>h', init_code, idx+1)[0]; idx += 3
            instructions.append(('const_int', None, v))
            stack.append(('const_int', None, v))
        elif 0x02 <= op <= 0x08:  # iconst_m1 .. iconst_5
            v = op - 0x03
            instructions.append(('const_int', None, v))
            stack.append(('const_int', None, v))
            idx += 1
        elif op in (0xb7, 0xb8):  # invokespecial, invokestatic
            if idx + 2 >= len(init_code): break
            m_idx, = struct.unpack_from('>H', init_code, idx+1); idx += 3
            ref = ast.cp.get(m_idx)
            if ref and ref[0] == 'Ref2':
                c_n = ast.cp.get(ast.cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                nat = ast.cp.get(ref[1][1])
                m_n = ast.cp.get(nat[1][0], (None, ''))[1] if nat else ''
                m_d = ast.cp.get(nat[1][1], (None, ''))[1] if nat else ''
                instructions.append(('invoke', f'{c_n}->{m_n}{m_d}', None))
                if 'listOf' in m_n or 'emptyList' in m_n:
                    if 'emptyList' in m_n:
                        stack.append([])
                    elif 'listOf' in m_n:
                        if stack:
                            top = stack.pop()
                            if isinstance(top, list):
                                stack.append(top)
                            else:
                                val = top[2] if isinstance(top, tuple) and len(top) > 2 else top
                                stack.append([val] if val is not None else [])
                        else:
                            stack.append([])
        elif op == 0xbd:  # anewarray
            if idx + 2 >= len(init_code): break
            a_idx, = struct.unpack_from('>H', init_code, idx+1); idx += 3
            c_n = ast.cp.get(ast.cp.get(a_idx, (None, None))[1], (None, ''))[1]
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
                            len(s_clean) >= 4
                            and not is_extension_package(s_clean)
                            and "Fingerprint" not in s_clean
                            and not any(ord(c) < 32 for c in s_clean)
                            and s_clean not in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'true', 'false')
                        ):
                            candidate_strings.append(s_clean)
                    elif (
                        not is_constructor
                        and re.match(r'^[a-z_$][a-zA-Z0-9_$]*$', s_clean)
                        and s_clean not in (
                            'this', '<this>', 'patchContext', 'patch', 'method', 'invoke', 'injected', 'true', 'false'
                        )
                    ):
                        if 'method_name' not in fp and not s_clean.startswith("app"):
                            fp['method_name'] = s_clean
                        elif len(s_clean) >= 4:
                            candidate_strings.append(s_clean)
                    elif (
                        len(s_clean) >= 4
                        and not is_extension_package(s_clean)
                        and "Fingerprint" not in s_clean
                        and not s_clean.endswith("(...)")
                        and not any(ord(c) < 32 for c in s_clean)
                        and s_clean not in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'true', 'false', 'invoke')
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
        elif itype == 'const_int':
            ival = ival
            if isinstance(ival, int) and 1000 < ival < 2000000000:
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
                            and len(x) >= 4
                            and not is_extension_package(x)
                            and "Fingerprint" not in x
                            and not x.endswith("(...)")
                            and not any(ord(c) < 32 for c in x)
                            and x not in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'true', 'false')
                        ):
                            candidate_strings.append(x)
                pending_list = []

    # Also harvest resolved lists from symbolic stack evaluation
    for item in stack:
        if isinstance(item, list):
            for elem in item:
                if isinstance(elem, str):
                    s = elem.strip()
                    if s.startswith('L') and s.endswith(';'):
                        ct = clean_type(s)
                        if ct and ct not in param_types:
                            param_types.append(ct)
                    elif s in ('V', 'Z', 'I', 'J', 'F', 'D', 'S', 'B', 'C'):
                        ct = clean_type(s)
                        if ct and ct not in param_types:
                            param_types.append(ct)
                    elif (
                        len(s) >= 4
                        and not is_extension_package(s)
                        and "Fingerprint" not in s
                        and s not in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'true', 'false')
                    ):
                        if s not in candidate_strings:
                            candidate_strings.append(s)

    if is_constructor:
        fp['method_name'] = "<init>"
        if 'return_type' not in fp:
            fp['return_type'] = "void"

    if param_types:
        if any(p == 'L' for p in param_types):
            fp['param_count'] = len(param_types)
            fp['param_types'] = []
        else:
            fp['param_types'] = param_types

    # Discard non-discriminating strings
    GENERIC_DISCRIMINATORS = {'this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'invoke', 'true', 'false', 'null'}
    cleaned_strings = [s for s in candidate_strings if s not in GENERIC_DISCRIMINATORS and len(s) >= 4]
    if cleaned_strings:
        fp['strings'] = cleaned_strings[:5]

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

                    # Read bytes for patch class and companion classes in same directory
                    p_data = z.read(pf)
                    companion_data = [z.read(cf) for cf in companion_classes]
                    combined_bytes = p_data + b"".join(companion_data)

                    # Parse patch class and companion classes via ClassfileAst
                    patch_ast = ClassfileAst(p_data)
                    comp_asts = [ClassfileAst(cd) for cd in companion_data]
                    all_asts = [patch_ast] + comp_asts

                    p_strings, _, _ = parse_jvm_class(p_data)
                    patch_name = next((s for s in p_strings if 3 < len(s) < 40 and not s.startswith("L") and not s.startswith("$") and " " in s), "")

                    # Extract all BSM templates and direct AST fingerprint bindings
                    ast_fp_bindings: Dict[str, Tuple[str, str]] = {}
                    for c_ast in all_asts:
                        bsms = c_ast.bootstrap_methods
                        for (m_name, _), code in c_ast.methods.items():
                            if not code:
                                continue
                            idx = 0
                            last_fp_name = None
                            while idx < len(code):
                                op = code[idx]
                                if op == 0xb2 and idx + 2 < len(code):  # getstatic
                                    f_idx, = struct.unpack_from('>H', code, idx+1); idx += 3
                                    ref = c_ast.cp.get(f_idx)
                                    if ref and ref[0] == 'Ref2':
                                        c_n = c_ast.cp.get(c_ast.cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                                        if 'Fingerprint' in c_n:
                                            last_fp_name = c_n.split('/')[-1].replace('Fingerprint', '')
                                elif op == 0xba and idx + 4 < len(code):  # invokedynamic
                                    id_idx, = struct.unpack_from('>H', code, idx+1); idx += 5
                                    entry = c_ast.cp.get(id_idx)
                                    if entry and entry[0] == 'InvokeDynamic':
                                        bsm_idx = entry[1][0]
                                        if bsm_idx < len(bsms):
                                            bsm_args = bsms[bsm_idx]
                                            for b_arg in bsm_args:
                                                if isinstance(b_arg, str) and 'invoke-static' in b_arg:
                                                    ext_match = re.search(r'([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', b_arg)
                                                    if ext_match and last_fp_name:
                                                        ext_str = ext_match.group(1).lstrip('L').rstrip(';')
                                                        ast_fp_bindings[last_fp_name] = (ext_str, b_arg)
                                elif op in (0xb7, 0xb8) and idx + 2 < len(code):  # invokespecial, invokestatic
                                    m_idx, = struct.unpack_from('>H', code, idx+1); idx += 3
                                    ref = c_ast.cp.get(m_idx)
                                    if ref and ref[0] == 'Ref2':
                                        c_n = c_ast.cp.get(c_ast.cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                                        nat = c_ast.cp.get(ref[1][1])
                                        m_n = nat[0] if nat else ''
                                        m_d = nat[1] if nat else ''
                                        m_name_str = c_ast.cp.get(m_n, ('', ''))[1] if isinstance(m_n, int) else ''
                                        m_desc_str = c_ast.cp.get(m_d, ('', ''))[1] if isinstance(m_d, int) else ''
                                        if is_extension_package(c_n) and last_fp_name:
                                            ext_str = f"{c_n}->{m_name_str}{m_desc_str}".lstrip('L').rstrip(';')
                                            ast_fp_bindings[last_fp_name] = (ext_str, "")
                                else:
                                    idx += 1

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
                        if "Constructor" in fp_simple or fp_name.endswith("Constructor") or "Ctor" in fp_simple:
                            fp_def['method_name'] = "<init>"
                            if 'return_type' not in fp_def or not fp_def.get('return_type'):
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

                        # 1. Check exact AST binding first
                        best_ext = None
                        smali_ctx = all_text
                        if fp_name in ast_fp_bindings:
                            best_ext, smali_ctx = ast_fp_bindings[fp_name]
                        elif fp_simple in ast_fp_bindings:
                            best_ext, smali_ctx = ast_fp_bindings[fp_simple]

                        # 2. Match to best extension call by token overlap in available calls
                        if not best_ext and available_ext_calls:
                            words = [w for w in re.split(r'[^a-z0-9]', re.sub(r'([a-z])([A-Z])', r'\1 \2', fp_name).lower()) if len(w) > 3]
                            for ext in available_ext_calls:
                                mtd = ext.split("->")[1].split("(")[0].lower()
                                if any(w in mtd for w in words) or mtd in fp_name.lower() or fp_name.lower() in mtd:
                                    best_ext = ext
                                    break
                            if not best_ext and len(available_ext_calls) == 1:
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
                            smali_ctx,
                            target_method=target_mtd,
                            target_return=fp_def.get('return_type', '')
                        )

                        # CRITICAL SAFETY GUARD:
                        # An unconstrained query (*#* with no method and no strong strings)
                        # must NEVER be mapped as RETURN_TRANSFORM or REPLACE!
                        is_unconstrained = not target_cls and not target_mtd
                        if is_unconstrained and action in ("RETURN_TRANSFORM", "REPLACE", "METHOD_REPLACE"):
                            valid_strings = [s for s in fp_def.get('strings', []) if len(s) >= 6]
                            if not valid_strings:
                                continue
                            action = "AFTER"

                        # Guard against type mismatch in RETURN_TRANSFORM
                        target_ret = clean_type(fp_def.get('return_type', ''))
                        ext_ret = clean_type(best_ext.split(')')[-1]) if ')' in best_ext else ''
                        if action == "RETURN_TRANSFORM" and target_ret and ext_ret:
                            if target_ret != ext_ret and target_ret in ("boolean", "int", "void", "long", "float", "double"):
                                action = "AFTER"

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
