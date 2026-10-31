import json
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from ..parser.classfile_ast import ClassfileAst
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
        "android."
    ))


def is_valid_class_name(name: str) -> bool:
    """Validate that a string is a clean, fully-qualified Java class name via identifier AST rules."""
    if not name or len(name) < 2:
        return False
    if any(c in name for c in (";", "->", " ", "(", ")", ":", "[", "<", ">", "$$")):
        return False
    if is_extension_package(name):
        return False
    parts = name.split(".")
    for part in parts:
        if not part:
            return False
        # Each part can contain inner-class '$' delimiters (e.g. Outer$Inner or Activity$1)
        for sub in part.split("$"):
            if not sub or not (sub.isidentifier() or sub.isdigit()):
                return False
    return True


def is_extension_package(name: str) -> bool:
    """Return True if class or path belongs to a runtime extension package rather than the host app or patcher."""
    clean = name.lstrip("L").replace("/", ".")
    if clean.startswith((
        "app.morphe.patches.", "app.morphe.patcher.", "app.morphe.util.",
        "app.hushgram.patches.", "app.hushgram.patcher.", "app.hushgram.util.",
        "app.revanced.patches.", "app.revanced.patcher.", "app.revanced.util."
    )):
        return False
    return ".extension." in clean or clean.endswith(".extension") or ".extension" in clean


def parse_jvm_class(data: bytes) -> Tuple[List[str], List[str], List[int]]:
    """
    Parse a compiled JVM .class file binary to extract string constants,
    Utf8 symbols, and integer literals from the constant pool via ClassfileAst.
    """
    ast = ClassfileAst(data)
    strings = [
        ast.cp[v[1]][1]
        for v in ast.cp.values()
        if v[0] == 'String' and v[1] in ast.cp and ast.cp[v[1]][0] == 'Utf8'
    ]
    utf8s = [v[1] for v in ast.cp.values() if v[0] == 'Utf8']
    ints = [v[1] for v in ast.cp.values() if v[0] == 'Int']

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
        dex_classes = MppArchive._extract_dex_classes(data)
        for cls_desc in dex_classes:
            if "$" in cls_desc:
                continue
            if cls_desc.endswith("/SettingsEntry;"):
                cls_name = cls_desc[1:-1].replace('/', '.')
                ep = f"{cls_name}#onApplicationCreate"
                if ep not in seen:
                    seen.add(ep)
                    entrypoints.append(ep)
            elif cls_desc.endswith("/AddOnApi;"):
                cls_name = cls_desc[1:-1].replace('/', '.')
                ep = f"{cls_name}#initialize"
                if ep not in seen:
                    seen.add(ep)
                    entrypoints.append(ep)
            elif cls_desc.endswith("/Utils;"):
                cls_name = cls_desc[1:-1].replace('/', '.')
                if is_extension_package(cls_name):
                    ep = f"{cls_name}#setContext"
                    if ep not in seen:
                        seen.add(ep)
                        entrypoints.append(ep)
            elif cls_desc.endswith("/ResourceUtils;") or cls_desc.endswith("/ResourceUtilsKt;"):
                cls_name = cls_desc[1:-1].replace('/', '.')
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


KNOWN_LIFECYCLE_METHODS = {
    "<init>",
    "onCreate",
    "onStart",
    "onResume",
    "onPause",
    "onStop",
    "onDestroy",
    "onClick",
    "onViewCreated",
    "getView",
    "onMeasure",
    "onDraw",
    "dispatchTouchEvent",
    "onNewIntent",
    "finish",
    "run",
    "attachBaseContext",
}


PATCHER_FRAMEWORK_FIELDS = {
    'PUBLIC', 'PRIVATE', 'PROTECTED', 'STATIC', 'FINAL', 'SYNCHRONIZED',
    'VOLATILE', 'TRANSIENT', 'NATIVE', 'INTERFACE', 'ABSTRACT', 'STRICTFP',
    'SYNTHETIC', 'ANNOTATION', 'ENUM', 'CONSTRUCTOR', 'DECLARED_SYNCHRONIZED',
    'STRING', 'ID', 'LAYOUT', 'DRAWABLE', 'COLOR', 'ANIM', 'ATTR', 'DIMEN',
}


def is_valid_dex_string(s: str) -> bool:
    """
    Validate whether a string is a genuine DEX bytecode identifier or literal,
    rather than a patch description, compiler exception message, or diagnostic log.
    """
    if not s or len(s) < 3 or len(s) > 80:
        return False
    if any(ord(c) < 32 or ord(c) > 126 for c in s):
        return False
    if any(x in s for x in ("->", "{", "}", "\n", "\t", "\\")):
        return False
    if s in ('this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'true', 'false', 'null', 'none', 'what', 'type') or s.startswith('<') or s.endswith('>'):
        return False
    lower = s.lower()
    # Reject English sentences, author diagnostics, and patch metadata
    if any(k in lower for k in (
        "expected", "found", "missing", "isn't", "aren't", "doesn't", "don't", "can't",
        "cannot", "must", "should", "failed", "error", "exception", "warning", "unknown",
        "report", "rebuild", "reopen", "retry", "branch", "bridge", "getter", "setter",
        "has no", "no public", "not public", "in this build", "left out", "in one place",
        "extension", "patch", "fingerprint", "targets", "predicate", "element",
        "no declared preference", "adds settings for morphe", "remove viewer discretion",
        "unexpected fields", "unexpected popup", "restore trust", "lock your",
        "show hidden", "remove build", "hushgram", "morphe", "answers", "another",
        "holds", "where", "which", "instruction", "status bar height"
    )):
        return False
    # Multi-word English sentences
    if s.count(' ') >= 2:
        return False
    # Single-space allowed only for short formatting tokens like 'MMMM d' or '%s %s'
    if ' ' in s and not (len(s) <= 10 and (s.startswith('%') or 'd' in s or 'M' in s)):
        return False
    return True


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
        or "Init" in file_name
        or file_name.endswith("InitFingerprint")
    )

    stack: List[Any] = []
    idx = 0
    instructions: List[Tuple[str, Any, Any]] = []
    resource_strings: Set[str] = set()
    res_literal_info: Optional[Tuple[str, str]] = None

    while idx < len(init_code):
        op = init_code[idx]
        if op == 0x01:  # aconst_null
            stack.append(None); idx += 1
        elif op == 0x2a:  # aload_0 (this)
            stack.append('this'); idx += 1
        elif op == 0xb2:  # getstatic
            if idx + 2 >= len(init_code): break
            f_idx, = struct.unpack_from('>H', init_code, idx+1); idx += 3
            ref = ast.cp.get(f_idx)
            if ref and ref[0] == 'Ref2':
                c_n = ast.cp.get(ast.cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                nat = ast.cp.get(ref[1][1])
                f_n = ast.cp.get(nat[1][0], (None, ''))[1] if nat else ''
                f_d = ast.cp.get(nat[1][1], (None, ''))[1] if nat else ''
                instructions.append(('getstatic', f'{c_n}->{f_n}:{f_d}', c_n))
                if 'AccessFlags' in c_n or 'Opcode' in c_n or 'ResourceType' in c_n or f_n in PATCHER_FRAMEWORK_FIELDS:
                    stack.append(('patcher_flag', c_n, f_n))
                else:
                    stack.append(('getstatic', c_n, f_n))
            else:
                stack.append(('getstatic', None, None))
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
            # Detect if this literal is immediately consumed by invokestatic listOf(...)
            is_followed_by_list = False
            if idx < len(init_code) and init_code[idx] == 0xb8 and idx + 2 < len(init_code):
                next_m_idx, = struct.unpack_from('>H', init_code, idx+1)
                next_ref = ast.cp.get(next_m_idx)
                if next_ref and next_ref[0] == 'Ref2':
                    next_nat = ast.cp.get(next_ref[1][1])
                    next_m_name = ast.cp.get(next_nat[1][0], (None, ''))[1] if next_nat else ''
                    if 'listOf' in next_m_name:
                        is_followed_by_list = True
            instructions.append(('ldc', entry[0] if entry else None, val, is_followed_by_list))
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

                if 'resourceLiteral' in m_n:
                    # Filter out AAPT resource names from Dalvik string pools and record resource query
                    res_name = None
                    res_type = 'string'
                    for item in reversed(stack):
                        if isinstance(item, tuple) and len(item) > 2 and item[0] == 'ldc' and item[1] == 'String':
                            if item[2] and isinstance(item[2], str):
                                res_name = item[2]
                                resource_strings.add(res_name)
                                break
                        elif isinstance(item, str) and item not in ('this', '<this>'):
                            res_name = item
                            resource_strings.add(res_name)
                            break
                    for item in stack:
                        if isinstance(item, tuple) and len(item) > 2 and item[0] in ('getstatic', 'patcher_flag'):
                            if 'ResourceType' in str(item[1]):
                                res_type = str(item[2]).lower()
                    if res_name:
                        res_literal_info = (res_name, res_type)

                if 'listOf' in m_n or 'emptyList' in m_n:
                    if 'emptyList' in m_n:
                        stack.append([])
                    elif 'listOf' in m_n:
                        if stack:
                            top = stack.pop()
                            if isinstance(top, list):
                                stack.append(top)
                            else:
                                if isinstance(top, tuple) and len(top) > 2 and top[0] == 'patcher_flag':
                                    pass
                                else:
                                    val = top[2] if isinstance(top, tuple) and len(top) > 2 else top
                                    if val and val not in PATCHER_FRAMEWORK_FIELDS:
                                        stack.append([val])
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
    if res_literal_info:
        fp['resource_name'] = res_literal_info[0]
        fp['resource_type'] = res_literal_info[1]
    pending_list: List[Tuple[Optional[str], Any]] = []
    in_array = False
    param_types: List[str] = []
    candidate_strings: List[str] = []

    for inst in instructions:
        itype = inst[0]
        const_tag = inst[1]
        ival = inst[2]
        is_followed_by_list = inst[3] if len(inst) > 3 else False
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
                        if not is_followed_by_list and 'return_type' not in fp:
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
                        and s_clean.isidentifier()
                        and (s_clean[0].islower() or s_clean[0] in ('_', '$'))
                        and s_clean not in (
                            'this', '<this>', 'patchContext', 'patch', 'method', 'invoke', 'injected', 'true', 'false'
                        )
                    ):
                        if s_clean in KNOWN_LIFECYCLE_METHODS:
                            if 'method_name' not in fp:
                                fp['method_name'] = s_clean
                        elif 'declaring_class' in fp and 'method_name' not in fp and not s_clean.startswith("app"):
                            fp['method_name'] = s_clean
                        elif (
                            len(s_clean) >= 4
                            and not is_extension_package(s_clean)
                            and "Fingerprint" not in s_clean
                            and not s_clean.endswith("(...)")
                            and not any(ord(c) < 32 for c in s_clean)
                        ):
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
                        and s not in PATCHER_FRAMEWORK_FIELDS
                    ):
                        if s not in candidate_strings:
                            candidate_strings.append(s)

    # Inspect predicate lambdas (_init_$lambda$0, etc.) for classDef / method criteria
    for (m_name, _), code in ast.methods.items():
        if 'lambda' not in m_name or not code:
            continue
        l_idx = 0
        l_strings: List[str] = []
        while l_idx < len(code):
            op = code[l_idx]
            if op in (0x12, 0x13):
                if op == 0x12:
                    if l_idx + 1 >= len(code): break
                    c_idx = code[l_idx+1]; l_idx += 2
                else:
                    if l_idx + 2 >= len(code): break
                    c_idx, = struct.unpack_from('>H', code, l_idx+1); l_idx += 3
                entry = ast.cp.get(c_idx)
                if entry and entry[0] == 'String':
                    val_utf = ast.cp.get(entry[1])
                    val = val_utf[1] if val_utf else None
                    if val and isinstance(val, str):
                        l_strings.append(val)
            else:
                l_idx += 1

        for s in l_strings:
            s_clean = s.strip()
            if s_clean.startswith('L') and s_clean.endswith(';'):
                ct = clean_type(s_clean)
                if ct and is_valid_class_name(ct) and not is_framework_class(ct):
                    if not any(ct.endswith(m) for m in ('Item', 'Media', 'Model', 'Data', 'Entity', 'Args', 'Arguments')):
                        if 'declaring_class' not in fp:
                            fp['declaring_class'] = ct
                    elif 'declaring_class' not in fp and 'fragment' in ct.lower():
                        fp['declaring_class'] = ct
            elif s_clean in KNOWN_LIFECYCLE_METHODS or s_clean in ('toString', 'onBackPressed', 'handleMessage'):
                if 'method_name' not in fp:
                    fp['method_name'] = s_clean
            elif is_valid_dex_string(s_clean) and s_clean not in ('method', 'classDef', 'getParameterTypes(...)', 'this', '<this>', '<unused var>'):
                if s_clean not in candidate_strings:
                    candidate_strings.append(s_clean)

    # Track parent fingerprint inheritance from constructor getstatic
    for item in stack:
        if isinstance(item, tuple) and len(item) > 2 and item[0] == 'getstatic':
            c_name = item[1]
            if c_name and 'Fingerprint' in c_name and c_name != class_name:
                fp['parent_fingerprint'] = c_name.replace('/', '.')
                break

    if is_constructor:
        fp['method_name'] = "<init>"
        if 'return_type' not in fp:
            fp['return_type'] = "void"

    if param_types:
        fp['param_types'] = param_types
        fp['param_count'] = len(param_types)

    # Discard non-discriminating strings and resource literals
    GENERIC_DISCRIMINATORS = {'this', '<this>', 'patchContext', 'patch', 'method', '<init>', 'invoke', 'true', 'false', 'null'}
    cleaned_strings = [
        s for s in candidate_strings
        if s not in GENERIC_DISCRIMINATORS and s not in resource_strings and s not in PATCHER_FRAMEWORK_FIELDS and is_valid_dex_string(s)
    ]
    if cleaned_strings:
        fp['strings'] = cleaned_strings[:5]

    fp['fingerprint_class'] = class_name.replace('/', '.').removesuffix('.class')

    # Clean overly broad or framework declaring classes
    declaring_cls = fp.get('declaring_class')
    if declaring_cls:
        if is_framework_class(declaring_cls):
            if 'return_type' not in fp:
                fp['return_type'] = declaring_cls
            del fp['declaring_class']
        elif declaring_cls in param_types:
            # Mistaken parameter type pushed during singleton listOf()
            del fp['declaring_class']
        elif declaring_cls in ('java.lang.Object', 'android.content.res.Resources', 'android.view.View'):
            if not fp.get('method_name'):
                del fp['declaring_class']

    # CRITICAL GUARD: A fingerprint MUST have at least one specific discriminator
    # (method_name, non-empty strings, a literal number, or a concrete non-framework parameter type).
    has_concrete_param = any(
        p != 'L' and len(p) > 5 and not is_framework_class(p) and '.' in p
        for p in fp.get('param_types', [])
    )
    has_discriminator = bool(
        fp.get('method_name') or
        fp.get('strings') or
        fp.get('literal') is not None or
        fp.get('resource_name') or
        has_concrete_param
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
        and not fp.get("resource_name")
    ):
        return None

    return fp


def classify_action_from_signature(ext_call: str, smali_text: str = "", target_method: str = "", target_return: str = "") -> str:
    """Classify LibXposed hook action based on extension method descriptor and bytecode."""
    # Critical invariant: Constructors and Android lifecycle methods must ALWAYS run AFTER
    if target_method == "<init>" or target_method in ("onCreate", "onActivityCreated", "attachBaseContext", "onResume", "onStart", "onPause", "onStop", "onDestroy"):
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

    # Check for return type mismatch with primitive targets or void targets
    ext_clean = clean_type(ret_part)
    target_clean = clean_type(target_return) if target_return else ""
    if target_clean in ("void", "V", "") or (target_clean and ext_clean != target_clean and target_clean in ("boolean", "int", "long", "float", "double")):
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
    if archive and Path(archive.path).exists():
        app_tag = app_info.app_tag

        retained_set = set(retained_patches) if retained_patches is not None else None

        with zipfile.ZipFile(Path(archive.path), "r") as z:
            names = z.namelist()

            # Dynamically discover all app tags present in this archive (avoiding hardcoded app lists)
            archive_tags = {
                n.split("app/morphe/patches/")[1].split("/")[0]
                for n in names
                if "app/morphe/patches/" in n and "/" in n.split("app/morphe/patches/")[1]
            } - {"shared", "all", ""}
            other_known_tags = archive_tags - {app_tag}

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

            if retained_patches:
                patch_classes = [
                    f"{c}.class" if not c.endswith(".class") else c
                    for c in retained_patches
                    if (f"{c}.class" if not c.endswith(".class") else c) in names
                ]
            elif app_info and app_info.patch_classes:
                patch_classes = [
                    f"{c}.class" if not c.endswith(".class") else c
                    for c in app_info.patch_classes
                    if (f"{c}.class" if not c.endswith(".class") else c) in names
                ]
            else:
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
                    ast_fp_bindings: Dict[str, List[Tuple[str, str]]] = {}

                    def record_binding(fp_k: str, ext_k: str, ctx_k: str):
                        if fp_k not in ast_fp_bindings:
                            ast_fp_bindings[fp_k] = []
                        if not any(e == ext_k for e, _ in ast_fp_bindings[fp_k]):
                            ast_fp_bindings[fp_k].append((ext_k, ctx_k))

                    for c_ast in all_asts:
                        bsms = c_ast.bootstrap_methods
                        for (m_name, _), code in c_ast.methods.items():
                            if not code:
                                continue
                            idx = 0
                            last_fp_name = None
                            last_ldc_strings: List[str] = []
                            while idx < len(code):
                                op = code[idx]
                                if op == 0xb2 and idx + 2 < len(code):  # getstatic
                                    f_idx, = struct.unpack_from('>H', code, idx+1); idx += 3
                                    ref = c_ast.cp.get(f_idx)
                                    if ref and ref[0] == 'Ref2':
                                        c_n = c_ast.cp.get(c_ast.cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                                        if 'Fingerprint' in c_n:
                                            last_fp_name = c_n.split('/')[-1].replace('Fingerprint', '')
                                elif op == 0x12 and idx + 1 < len(code):  # ldc
                                    s_idx = code[idx+1]; idx += 2
                                    s_entry = c_ast.cp.get(s_idx)
                                    if s_entry and s_entry[0] == 'String':
                                        s_val = c_ast.cp.get(s_entry[1], ('', ''))[1]
                                        last_ldc_strings.append(s_val)
                                        if len(last_ldc_strings) > 6:
                                            last_ldc_strings.pop(0)
                                        if ('invoke-static' in s_val or 'invoke-virtual' in s_val or ';->' in s_val) and last_fp_name:
                                            ext_m = re.search(r'([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', s_val)
                                            if ext_m:
                                                ext_str = ext_m.group(1).lstrip('L').rstrip(';')
                                                if is_extension_package(ext_str.split('->')[0]):
                                                    record_binding(last_fp_name, ext_str, s_val)
                                elif op == 0x13 and idx + 2 < len(code):  # ldc_w
                                    s_idx, = struct.unpack_from('>H', code, idx+1); idx += 3
                                    s_entry = c_ast.cp.get(s_idx)
                                    if s_entry and s_entry[0] == 'String':
                                        s_val = c_ast.cp.get(s_entry[1], ('', ''))[1]
                                        last_ldc_strings.append(s_val)
                                        if len(last_ldc_strings) > 6:
                                            last_ldc_strings.pop(0)
                                        if ('invoke-static' in s_val or 'invoke-virtual' in s_val or ';->' in s_val) and last_fp_name:
                                            ext_m = re.search(r'([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', s_val)
                                            if ext_m:
                                                ext_str = ext_m.group(1).lstrip('L').rstrip(';')
                                                if is_extension_package(ext_str.split('->')[0]):
                                                    record_binding(last_fp_name, ext_str, s_val)
                                elif op == 0xba and idx + 4 < len(code):  # invokedynamic
                                    id_idx, = struct.unpack_from('>H', code, idx+1); idx += 5
                                    entry = c_ast.cp.get(id_idx)
                                    if entry and entry[0] == 'InvokeDynamic':
                                        bsm_idx = entry[1][0]
                                        if bsm_idx < len(bsms):
                                            bsm_args = bsms[bsm_idx]
                                            for b_arg in bsm_args:
                                                if isinstance(b_arg, str) and ('invoke-static' in b_arg or 'invoke-virtual' in b_arg or ';->' in b_arg):
                                                    ext_match = re.search(r'([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', b_arg)
                                                    if ext_match and last_fp_name:
                                                        ext_str = ext_match.group(1).lstrip('L').rstrip(';')
                                                        if is_extension_package(ext_str.split('->')[0]):
                                                            record_binding(last_fp_name, ext_str, b_arg)
                                elif op in (0xb7, 0xb8) and idx + 2 < len(code):  # invokespecial, invokestatic
                                    m_idx, = struct.unpack_from('>H', code, idx+1); idx += 3
                                    ref = c_ast.cp.get(m_idx)
                                    if ref and ref[0] == 'Ref2':
                                        c_n = c_ast.cp.get(c_ast.cp.get(ref[1][0], (None, None))[1], (None, ''))[1]
                                        nat = c_ast.cp.get(ref[1][1])
                                        if nat and nat[0] == 'NameAndType':
                                            m_n_idx, m_d_idx = nat[1]
                                            m_name_str = c_ast.cp.get(m_n_idx, ('', ''))[1]
                                            m_desc_str = c_ast.cp.get(m_d_idx, ('', ''))[1]
                                            if m_name_str == 'injectHideViewCall' and len(last_ldc_strings) >= 2 and last_fp_name:
                                                c_str = next((s for s in reversed(last_ldc_strings) if ';->' in s or ('extension' in s and '/' in s)), None)
                                                m_str = next((s for s in reversed(last_ldc_strings) if s and ('/' not in s) and (';' not in s) and not s.startswith('$')), None)
                                                if c_str and m_str:
                                                    clean_c = c_str.strip('L;')
                                                    record_binding(last_fp_name, f"{clean_c}->{m_str}(Landroid/view/View;)V", "")
                                            elif is_extension_package(c_n) and m_name_str and last_fp_name:
                                                ext_str = f"{c_n}->{m_name_str}{m_desc_str}".lstrip('L').rstrip(';')
                                                record_binding(last_fp_name, ext_str, "")
                                else:
                                    idx += 1

                    # Discover all fingerprints and extension calls referenced in this patch or its companion classes via Constant Pool AST
                    fp_refs = set()
                    ext_calls_raw = set()
                    for c_ast in all_asts:
                        for k, entry in c_ast.cp.items():
                            if entry[0] == 'Class':
                                c_str = c_ast.get_constant_string(k)
                                if c_str and c_str.endswith('Fingerprint') and 'patches/' in c_str:
                                    fp_refs.add(c_str)
                            elif entry[0] == 'String':
                                s_str = c_ast.get_constant_string(k)
                                if s_str and ';->' in s_str:
                                    ext_m = re.search(r'([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', s_str)
                                    if ext_m:
                                        ext_calls_raw.add(ext_m.group(1))
                            elif entry[0] == 'Utf8':
                                u_str = entry[1]
                                if u_str.endswith('Fingerprint') and 'patches/' in u_str:
                                    fp_refs.add(u_str.lstrip('L').rstrip(';'))
                                elif ';->' in u_str:
                                    ext_m = re.search(r'([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', u_str)
                                    if ext_m:
                                        ext_calls_raw.add(ext_m.group(1))

                    # Fallback to byte scan only if constant pool AST found no references
                    if not fp_refs:
                        fp_matches = re.findall(rb'(?:L)?(app/[a-zA-Z0-9_/]+/[a-zA-Z0-9_]+Fingerprint)', combined_bytes)
                        fp_refs = set(m.decode("utf-8", errors="ignore") for m in fp_matches)

                    if not ext_calls_raw:
                        ext_matches = re.findall(rb'(?:L)?([a-zA-Z0-9_/]+;->[a-zA-Z0-9_<>$]+\([^\)]*\)[a-zA-Z0-9_/$;\[]*)', combined_bytes)
                        ext_calls_raw = set(m.decode("utf-8", errors="ignore") for m in ext_matches)

                    ext_calls = [e.lstrip("L").rstrip(";") for e in ext_calls_raw]
                    # Filter out non-extension calls or calls from other app tags
                    ext_calls = [
                        e for e in ext_calls
                        if is_extension_package(e.split("->")[0])
                        and not any(f".{other}." in e or f"/{other}/" in e for other in other_known_tags)
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
                        if "Constructor" in fp_simple or fp_name.endswith("Constructor") or "Ctor" in fp_simple or "Init" in fp_simple or fp_name.endswith("Init"):
                            fp_def['method_name'] = "<init>"
                            if 'return_type' not in fp_def or not fp_def.get('return_type'):
                                fp_def['return_type'] = "void"

                        # Parent fingerprint inheritance
                        if not fp_def.get('declaring_class') and fp_def.get('parent_fingerprint'):
                            parent_simple = fp_def['parent_fingerprint'].split('.')[-1]
                            parent_file = fp_file_map.get(parent_simple + ".class")
                            if parent_file:
                                parent_def = extract_fingerprint_def(parent_file, z.read(parent_file))
                                if parent_def:
                                    if parent_def.get('declaring_class'):
                                        fp_def['declaring_class'] = parent_def['declaring_class']
                                    else:
                                        fp_def['parent_query'] = parent_def

                        # Derive method name from fingerprint class name if missing but declaring class is known
                        if not fp_def.get('method_name') and fp_def.get('declaring_class'):
                            cls_simple = fp_def['declaring_class'].split('.')[-1]
                            derived = fp_name
                            if cls_simple and cls_simple in derived:
                                derived = derived.replace(cls_simple, "")
                            if derived and derived.isidentifier():
                                fp_def['method_name'] = derived[0].lower() + derived[1:]

                        # Guard against wildcard queries in Path A:
                        # Must have method_name, non-empty strings, literal, or concrete param type
                        has_concrete_param = any(
                            p != 'L' and len(p) > 5 and not is_framework_class(p) and '.' in p
                            for p in fp_def.get('param_types', [])
                        )
                        if not fp_def.get('method_name') and not fp_def.get('strings') and fp_def.get('literal') is None and not has_concrete_param:
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

                        # 1. Check exact AST bindings first
                        candidate_bindings: List[Tuple[str, str]] = []
                        if fp_name in ast_fp_bindings:
                            candidate_bindings = ast_fp_bindings[fp_name]
                        elif fp_simple in ast_fp_bindings:
                            candidate_bindings = ast_fp_bindings[fp_simple]

                        # 2. Match to best extension call by token overlap in available calls if no AST bindings
                        if not candidate_bindings and available_ext_calls:
                            words = [w for w in re.split(r'[^a-z0-9]', re.sub(r'([a-z])([A-Z])', r'\1 \2', fp_name).lower()) if len(w) > 3]
                            for ext in available_ext_calls:
                                mtd = ext.split("->")[1].split("(")[0].lower()
                                if any(w in mtd for w in words) or mtd in fp_name.lower() or fp_name.lower() in mtd:
                                    candidate_bindings = [(ext, all_text)]
                                    break
                            if not candidate_bindings and len(available_ext_calls) == 1:
                                candidate_bindings = [(available_ext_calls[0], all_text)]

                        for best_ext, smali_ctx in candidate_bindings:
                            if not best_ext or "->" not in best_ext or best_ext.endswith("->"):
                                continue
                            ext_parts = best_ext.split("->")
                            ext_class_candidate = clean_type(ext_parts[0])
                            ext_method_candidate = ext_parts[1].split("(")[0].strip()
                            if not ext_method_candidate or not is_extension_package(ext_class_candidate):
                                continue

                            # Deduplicate identical (target_class, target_method, extension_call) hooks
                            target_key = (target_cls, target_mtd, best_ext)
                            if target_cls and target_mtd and target_key in seen_target_exts:
                                continue

                            patch_id_prefix = re.sub(r"[^a-z0-9]+", "_", (patch_name or pf.split("/")[-1]).lower())[:15]
                            hook_id = f"{patch_id_prefix}_{fp_name.lower()}".strip("_")
                            if hook_id in seen_hook_ids:
                                ext_suffix = re.sub(r"[^a-z0-9]+", "_", ext_method_candidate.lower())[:12]
                                hook_id = f"{hook_id}_{ext_suffix}".strip("_")
                            if hook_id in seen_hook_ids:
                                hook_id = f"{hook_id}_{len(hooks)}"
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
                            if x.startswith('L')
                            and x.endswith(';')
                            and '/' in x
                            and not x.startswith(('Lcom/android/tools/', 'Lapp/morphe/', 'Lkotlin/', 'Ljava/'))
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
                                        and is_valid_dex_string(s)
                                        and s not in PATCHER_FRAMEWORK_FIELDS
                                    ):
                                        comp_strings.append(s)
                                    if s in ('Z', 'V', 'I'):
                                        comp_return = clean_type(s)

                        if not comp_strings:
                            for s in p_strings:
                                if (
                                    4 < len(s) < 50
                                    and not s.startswith(('L', '[', '('))
                                    and not s.endswith(('(...)', ';'))
                                    and not any(ord(c) < 32 for c in s)
                                    and not is_extension_package(s)
                                    and is_valid_dex_string(s)
                                    and s not in ('patchContext', 'classDef', 'method', '<init>', 'true', 'false', 'null')
                                    and s not in PATCHER_FRAMEWORK_FIELDS
                                ):
                                    comp_strings.append(s)

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

                            # Disambiguate Activity lifecycle targets and decouple data models
                            if target_mtd in ('onBackPressed', 'onCreate', 'onStart', 'onResume', 'onPause', 'onStop', 'onDestroy', 'onNewIntent', 'finish'):
                                if not target_cls or is_framework_class(target_cls) or any(target_cls.endswith(m) for m in ('Item', 'Media', 'Model', 'Data')):
                                    target_cls = 'android.app.Activity'
                            elif target_mtd in ('onClick', 'getView', 'onViewCreated'):
                                if target_cls and any(target_cls.endswith(m) for m in ('Item', 'Media', 'Model', 'Data', 'Entity')):
                                    target_cls = None

                            # CRITICAL GUARD: Never emit a wildcard hook without method name or unique strings
                            if not target_mtd and not comp_strings:
                                continue

                            b_fp: Dict[str, Any] = {}
                            if target_cls:
                                b_fp['declaring_class'] = target_cls
                            if target_mtd:
                                b_fp['method_name'] = target_mtd

                            if target_mtd == 'onClick' and not target_cls:
                                has_dialog_interface = any(
                                    'DialogInterface' in s
                                    for cf in companion_classes
                                    for s in parse_jvm_class(z.read(cf))[0]
                                )
                                if has_dialog_interface:
                                    b_fp['param_types'] = ['android.content.DialogInterface', 'int']
                                    b_fp['param_count'] = 2

                            # Only include strings if we don't have an exact class + method target
                            if comp_strings and (not target_cls or not target_mtd):
                                b_fp['strings'] = comp_strings[:3]
                            if comp_return:
                                b_fp['return_type'] = comp_return

                            # Reject unconstrained queries (must have declaring_class, param_types, strings, or literal)
                            if not b_fp.get('declaring_class') and not b_fp.get('strings') and b_fp.get('literal') is None and not b_fp.get('param_types'):
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
                            if not b_ext_class or not b_ext_method or not is_extension_package(b_ext_class):
                                continue

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
