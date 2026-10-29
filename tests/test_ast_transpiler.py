import unittest
from codexmorphe_builder.transpiler.classifier import BytecodeHookAction, classify_bytecode_action
from codexmorphe_builder.transpiler.fingerprint import FingerprintDef, transpile_fingerprint_to_dexkit
from codexmorphe_builder.transpiler.generator import HookGenerator


class TestAstTranspiler(unittest.TestCase):
    def test_fingerprint_to_dexkit(self):
        fp = FingerprintDef(
            name="TestFingerprint",
            declaring_class="Lcom/test/app/MainActivity;",
            method_name="onCreate",
            return_type="V",
            param_types=["Landroid/os/Bundle;"]
        )
        query = transpile_fingerprint_to_dexkit(fp)
        self.assertIn('declaredClass = "com.test.app.MainActivity"', query)
        self.assertIn('name = "onCreate"', query)
        self.assertIn('returnType = "void"', query)
        self.assertIn('paramTypes = listOf("android.os.Bundle")', query)

    def test_pattern_1_early_return_suppressor(self):
        smali = """
        invoke-static { }, Lapp/morphe/extension/test/Patches;->shouldBlock()Z
        move-result v0
        if-eqz v0, :show
        return-void
        :show
        """
        action = classify_bytecode_action("TestFp", smali)
        self.assertEqual(action.action_type, "EARLY_RETURN_SUPPRESSOR")
        self.assertEqual(action.extension_call, "Lapp/morphe/extension/test/Patches;->shouldBlock()Z")

        fp = FingerprintDef(name="TestFp")
        code = HookGenerator.generate_hook_snippet(fp, action)
        self.assertIn("param.result = null", code)
        self.assertIn("Patches.shouldBlock()", code)

    def test_pattern_4_constant_replace(self):
        smali = "return-void"
        action = classify_bytecode_action("TestFp", smali)
        self.assertEqual(action.action_type, "CONSTANT_REPLACE")
        self.assertEqual(action.constant_val, "void")

        fp = FingerprintDef(name="TestFp")
        code = HookGenerator.generate_hook_snippet(fp, action)
        self.assertIn("null", code)


if __name__ == "__main__":
    unittest.main()
