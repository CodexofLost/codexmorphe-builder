import re
from typing import List, Tuple
from .classifier import BytecodeHookAction
from .fingerprint import FingerprintDef, clean_type, transpile_fingerprint_to_dexkit


class HookGenerator:
    """
    Assembles complete DexKit/LibXposed Kotlin hook recipes.
    """

    @staticmethod
    def generate_hook_snippet(fp: FingerprintDef, action: BytecodeHookAction) -> str:
        dexkit_matcher = transpile_fingerprint_to_dexkit(fp)
        hook_impl = HookGenerator._render_action(action, fp)
        return f"{dexkit_matcher}{hook_impl}"

    @staticmethod
    def _render_action(action: BytecodeHookAction, fp: FingerprintDef) -> str:
        if action.action_type == "CONSTANT_REPLACE":
            if action.constant_val == "void" or action.constant_val is None:
                return ".hookReplace {\n    // Morphe: return-void\n    null\n}"
            elif isinstance(action.constant_val, bool):
                return f".hookReplace {{\n    // Morphe: returnConstant({str(action.constant_val).lower()})\n    {str(action.constant_val).lower()}\n}}"
            elif isinstance(action.constant_val, int):
                return f".hookReplace {{\n    // Morphe: returnConstant({action.constant_val})\n    {action.constant_val}\n}}"
            elif isinstance(action.constant_val, str):
                return f'.hookReplace {{\n    // Morphe: returnConstant("{action.constant_val}")\n    "{action.constant_val}"\n}}'
            else:
                return f".hookReplace {{\n    {action.constant_val}\n}}"

        elif action.action_type == "EARLY_RETURN_SUPPRESSOR":
            ext = HookGenerator._clean_ext_call(action.extension_call)
            return f""".hookBefore {{ param ->
    // Morphe Early Return Suppressor
    if ({ext}()) {{
        param.result = null
    }}
}}"""

        elif action.action_type == "ARG_REWRITE":
            ext = HookGenerator._clean_ext_call(action.extension_call)
            idx = action.arg_index if action.arg_index is not None else 0
            return f""".hookBefore {{ param ->
    // Morphe Argument Interception
    val originalArg = param.args[{idx}]
    param.args[{idx}] = {ext}(originalArg)
}}"""

        elif action.action_type == "RETURN_TRANSFORM":
            ext = HookGenerator._clean_ext_call(action.extension_call)
            ret_type = clean_type(fp.return_type or "Object")
            return f""".hookAfter {{ param ->
    // Morphe Return Value Transformation
    val original = param.result as? {ret_type}
    if (original != null) {{
        param.result = {ext}(original)
    }}
}}"""

        elif action.action_type == "METHOD_REPLACE":
            ext = HookGenerator._clean_ext_call(action.extension_call) if action.extension_call else None
            if ext:
                return f""".hookReplace {{ param ->
    // Morphe Method Replacement
    {ext}(param.thisObject, *param.args)
}}"""
            return ".hookReplace {\n    null\n}"

        return "// Unknown hook action"

    @staticmethod
    def _clean_ext_call(desc: str | None) -> str:
        if not desc:
            return "Extension"
        m = re.match(r"L?([^;]+);?->([^\(\n]+)", desc)
        if m:
            cls = m.group(1).replace("/", ".")
            method = m.group(2)
            short_cls = cls.split(".")[-1]
            return f"{short_cls}.{method}"
        return desc
