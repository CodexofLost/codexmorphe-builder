from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FingerprintDef:
    name: str
    declaring_class: Optional[str] = None
    method_name: Optional[str] = None
    return_type: Optional[str] = None
    param_types: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    opcodes: List[str] = field(default_factory=list)
    access_flags: List[str] = field(default_factory=list)


def clean_type(t: str) -> str:
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


def transpile_fingerprint_to_dexkit(fp: FingerprintDef) -> str:
    """
    Translate a FingerprintDef into a DexKit MethodMatcher block.
    """
    lines = ["dexKit.findMethod {", "    matcher {"]
    if fp.declaring_class:
        clean_class = fp.declaring_class.strip("L;").replace("/", ".")
        lines.append(f'        declaredClass = "{clean_class}"')
    if fp.method_name:
        lines.append(f'        name = "{fp.method_name}"')
    if fp.return_type:
        lines.append(f'        returnType = "{clean_type(fp.return_type)}"')
    if fp.param_types:
        clean_params = [f'"{clean_type(p)}"' for p in fp.param_types]
        lines.append(f'        paramTypes = listOf({", ".join(clean_params)})')
    if fp.strings:
        clean_strings = [f'"{s}"' for s in fp.strings]
        lines.append(f'        usingStrings = listOf({", ".join(clean_strings)})')
    if fp.access_flags:
        flags = " or ".join([f"Modifier.{f.upper()}" for f in fp.access_flags])
        lines.append(f"        modifiers = {flags}")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)
