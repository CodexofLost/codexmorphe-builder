"""
Universal AST Transpiler mapping Morphe bytecode transforms into DexKit / LibXposed hooks.
"""

from .fingerprint import FingerprintDef, transpile_fingerprint_to_dexkit
from .classifier import BytecodeHookAction, classify_bytecode_action
from .generator import HookGenerator

__all__ = [
    "FingerprintDef",
    "transpile_fingerprint_to_dexkit",
    "BytecodeHookAction",
    "classify_bytecode_action",
    "HookGenerator"
]
