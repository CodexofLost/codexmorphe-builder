import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class BytecodeHookAction:
    action_type: str  # "EARLY_RETURN_SUPPRESSOR", "ARG_REWRITE", "RETURN_TRANSFORM", "CONSTANT_REPLACE", "METHOD_REPLACE"
    target_fingerprint: str
    extension_call: Optional[str] = None
    constant_val: Optional[Any] = None
    arg_index: Optional[int] = None
    condition: Optional[str] = None


def classify_bytecode_action(target_fp: str, smali_text: str) -> BytecodeHookAction:
    """
    Classify injected smali instructions into one of the 5 universal AST hook patterns.
    """
    normalized = smali_text.strip()

    # Pattern 4: Constant replacement / return-void
    if normalized == "return-void":
        return BytecodeHookAction(action_type="CONSTANT_REPLACE", target_fingerprint=target_fp, constant_val="void")

    m_const_bool = re.search(r"const/4\s+v\d+,\s*(0x[01]|0|1)\s*\n\s*return\s+v\d+", normalized)
    if m_const_bool:
        val = m_const_bool.group(1) in ("0x1", "1")
        return BytecodeHookAction(action_type="CONSTANT_REPLACE", target_fingerprint=target_fp, constant_val=val)

    m_const_int = re.search(r"const(?:/16)?\s+v\d+,\s*(-?\d+)\s*\n\s*return\s+v\d+", normalized)
    if m_const_int:
        return BytecodeHookAction(action_type="CONSTANT_REPLACE", target_fingerprint=target_fp, constant_val=int(m_const_int.group(1)))

    # Pattern 1: Early return suppressor (invoke extension -> if-eqz/if-nez -> return-void)
    m_suppress = re.search(r"invoke-static\s*\{[^}]*\},?\s*([^;\n]+;->[^\(\n]+[^\n]*)\s*\n\s*move-result\s+v\d+\s*\n\s*if-(?:eqz|nez)\s+v\d+.*?\n\s*return(?:-void)?", normalized, re.DOTALL)
    if m_suppress:
        ext_call = m_suppress.group(1)
        return BytecodeHookAction(action_type="EARLY_RETURN_SUPPRESSOR", target_fingerprint=target_fp, extension_call=ext_call)

    # Pattern 2: Argument interception (invoke extension with pX -> move-result-object pX)
    m_arg = re.search(r"invoke-static\s*\{(?:\s*v\d+\s*,)?\s*p(\d+)[^}]*\},?\s*([^;\n]+;->[^\(\n]+[^\n]*)\s*\n\s*move-result-object\s+p\1", normalized)
    if m_arg:
        arg_idx = int(m_arg.group(1))
        ext_call = m_arg.group(2)
        return BytecodeHookAction(action_type="ARG_REWRITE", target_fingerprint=target_fp, extension_call=ext_call, arg_index=arg_idx)

    # Pattern 3: Return value transformation (invoke extension at return -> return result)
    m_ret = re.search(r"invoke-static\s*\{[^}]*\},?\s*([^;\n]+;->[^\(\n]+[^\n]*)\s*\n\s*move-result(?:-object)?\s+(v\d+)\s*\n\s*return(?:-object)?\s+\1", normalized)
    if m_ret:
        ext_call = m_ret.group(1)
        return BytecodeHookAction(action_type="RETURN_TRANSFORM", target_fingerprint=target_fp, extension_call=ext_call)

    # Pattern 5: Direct method replacement / callsite redirection
    m_method_rep = re.search(r"invoke-static\s*\{[^}]*\},?\s*([^;\n]+;->[^\(\n]+[^\n]*)", normalized)
    if m_method_rep:
        return BytecodeHookAction(action_type="METHOD_REPLACE", target_fingerprint=target_fp, extension_call=m_method_rep.group(1))

    # Default fallback to Method Replacement
    return BytecodeHookAction(action_type="METHOD_REPLACE", target_fingerprint=target_fp)
