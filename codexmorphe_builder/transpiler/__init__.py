"""
Universal AST Transpiler mapping Morphe bytecode transforms into DexKit / LibXposed hooks.
"""

from .recipe_builder import (
    clean_type,
    generate_hook_recipe_json,
)

__all__ = [
    "clean_type",
    "generate_hook_recipe_json",
]
