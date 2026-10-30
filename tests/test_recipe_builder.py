import json
import unittest
from pathlib import Path
from codexmorphe_builder.transpiler.recipe_builder import clean_type, generate_hook_recipe_json
from codexmorphe_builder.parser.compatibility import DiscoveredApp
from codexmorphe_builder.parser.mpp_archive import MppArchive


class TestRecipeBuilder(unittest.TestCase):
    def test_clean_type(self):
        self.assertEqual(clean_type("V"), "void")
        self.assertEqual(clean_type("Z"), "boolean")
        self.assertEqual(clean_type("I"), "int")
        self.assertEqual(clean_type("Ljava/lang/String;"), "java.lang.String")
        self.assertEqual(clean_type("[Landroid/os/Bundle;"), "android.os.Bundle[]")

    def test_generate_hook_recipe_json_empty_archive(self):
        app_info = DiscoveredApp(
            package_name="com.example.test",
            app_name="Test App",
            app_tag="test"
        )
        res = generate_hook_recipe_json("com.example.test", app_info)
        data = json.loads(res)
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["package_name"], "com.example.test")
        self.assertIn("entrypoints", data)
        self.assertIn("hooks", data)

    def test_generate_hook_recipe_json_real_mpp(self):
        mpp_path = Path("/storage/emulated/0/Download/All projects/codexmorphe-builder/.cache/mpp/hushgram-v0.0.17-hushgram.mpp")
        if not mpp_path.exists():
            self.skipTest("Hushgram MPP not present in cache")

        archive = MppArchive.from_file(mpp_path)
        app_info = DiscoveredApp(
            package_name="com.instagram.android",
            app_name="Instagram",
            app_tag="instagram"
        )
        res = generate_hook_recipe_json("com.instagram.android", app_info, archive=archive)
        data = json.loads(res)
        self.assertEqual(data["package_name"], "com.instagram.android")
        self.assertTrue(len(data["hooks"]) >= 200)
        self.assertTrue(len(data["entrypoints"]) > 0)
        # Verify no hooks contain compiler paths or extension classes
        for h in data["hooks"]:
            fp = h.get("fingerprint", {})
            dc = fp.get("declaring_class", "")
            self.assertFalse(dc.startswith("app.morphe") or dc.startswith("app.hushgram"))
            for s in fp.get("strings", []):
                self.assertFalse("Fingerprint" in s or "app/morphe" in s or "app/hushgram" in s)
        first_hook = data["hooks"][0]
        self.assertIn("id", first_hook)
        self.assertIn("action", first_hook)
        self.assertIn("fingerprint", first_hook)


if __name__ == "__main__":
    unittest.main()
