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
        self.assertEqual(clean_type("L"), "")
        self.assertEqual(clean_type("android.view.View;->findViewById(I)Landroid.view.View;"), "")

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

    def test_generate_hook_recipe_json_hushgram(self):
        cache_dir = Path(__file__).parents[1] / ".cache" / "mpp"
        mpp_candidates = list(cache_dir.glob("*hushgram*.mpp"))
        if not mpp_candidates:
            self.skipTest("Hushgram MPP not present in cache")

        archive = MppArchive.from_file(mpp_candidates[0])
        app_info = DiscoveredApp(
            package_name="com.instagram.android",
            app_name="Instagram",
            app_tag="instagram"
        )
        res = generate_hook_recipe_json("com.instagram.android", app_info, archive=archive)
        data = json.loads(res)
        self.assertEqual(data["package_name"], "com.instagram.android")
        self.assertTrue(len(data["hooks"]) > 100)
        self.assertTrue(len(data["entrypoints"]) > 0)
        self.assertIn("resource_fallbacks", data)
        self.assertTrue(any("ResourceUtils" in rf for rf in data["resource_fallbacks"]))

        for h in data["hooks"]:
            fp = h.get("fingerprint", {})
            dc = fp.get("declaring_class", "")
            # Verify no extension classes leaked
            self.assertFalse(dc.startswith("app.morphe") or dc.startswith("app.hushgram"))
            # Verify no method descriptors treated as classes
            self.assertFalse("->" in dc or ";" in dc)
            # Verify no wildcards in param_types
            for pt in fp.get("param_types", []):
                self.assertNotEqual(pt, "L")
                self.assertFalse(";" in pt or "->" in pt)
            for s in fp.get("strings", []):
                self.assertFalse("Fingerprint" in s or "app/morphe" in s or "app/hushgram" in s)
            # Verify action schema
            self.assertIn(h["action"], ("BEFORE", "AFTER", "REPLACE", "RETURN_TRANSFORM", "ARG_REWRITE", "CONSTANT_REPLACE"))
            if h.get("extension_class"):
                self.assertFalse(h["extension_class"].endswith(";"))

        # Invariant: Zero wildcard class queries without method or strings
        wildcards = [
            h for h in data["hooks"]
            if h.get("fingerprint", {}).get("declaring_class")
            and not h.get("fingerprint", {}).get("method_name")
            and not h.get("fingerprint", {}).get("strings")
            and h.get("fingerprint", {}).get("literal") is None
        ]
        self.assertEqual(len(wildcards), 0)

    def test_generate_hook_recipe_json_youtube_lifecycle_safety(self):
        cache_dir = Path(__file__).parents[1] / ".cache" / "mpp"
        mpp_candidates = list(cache_dir.glob("*official*.mpp"))
        if not mpp_candidates:
            self.skipTest("Official MPP not present in cache")

        archive = MppArchive.from_file(mpp_candidates[0])
        app_info = DiscoveredApp(
            package_name="com.google.android.youtube",
            app_name="YouTube",
            app_tag="youtube"
        )
        res = generate_hook_recipe_json("com.google.android.youtube", app_info, archive=archive)
        data = json.loads(res)
        self.assertEqual(data["package_name"], "com.google.android.youtube")

        main_activity_on_create_hooks = [
            h for h in data["hooks"]
            if h.get("fingerprint", {}).get("method_name") == "onCreate"
            and "MainActivity" in h.get("fingerprint", {}).get("declaring_class", "")
        ]

        # Verify GoogleApiActivity carries the YouTubeActivityHook settings hook
        google_api_hooks = [
            h for h in data["hooks"]
            if "GoogleApiActivity" in h.get("fingerprint", {}).get("declaring_class", "")
        ]
        self.assertTrue(len(google_api_hooks) >= 1)
        self.assertIn("YouTubeActivityHook->initialize", google_api_hooks[0]["extension_call"])

        # Verify MainActivity.onCreate hooks are genuine UI feature hooks, NOT YouTubeActivityHook
        self.assertTrue(len(main_activity_on_create_hooks) >= 1)
        for h in main_activity_on_create_hooks:
            self.assertEqual(h["action"], "AFTER")
            self.assertNotIn("YouTubeActivityHook->initialize", h["extension_call"])

        # Verify constructor discrimination
        init_hooks = [
            h for h in data["hooks"]
            if h.get("fingerprint", {}).get("method_name") == "<init>"
        ]
        self.assertTrue(len(init_hooks) >= 50)

        # Invariant: Zero wildcard class queries without method or strings
        wildcards = [
            h for h in data["hooks"]
            if h.get("fingerprint", {}).get("declaring_class")
            and not h.get("fingerprint", {}).get("method_name")
            and not h.get("fingerprint", {}).get("strings")
            and h.get("fingerprint", {}).get("literal") is None
        ]
        self.assertEqual(len(wildcards), 0)

        # Verify no music extensions leaked
        for h in data["hooks"]:
            self.assertNotIn("app/morphe/extension/music", h["extension_call"])

    def test_constructor_and_discriminator_safety(self):
        cache_dir = Path(__file__).parents[1] / ".cache" / "mpp"
        mpp_candidates = list(cache_dir.glob("*official*.mpp"))
        if not mpp_candidates:
            self.skipTest("Official MPP not present in cache")

        archive = MppArchive.from_file(mpp_candidates[0])
        app_info = DiscoveredApp(
            package_name="com.google.android.youtube",
            app_name="YouTube",
            app_tag="youtube"
        )
        res = generate_hook_recipe_json("com.google.android.youtube", app_info, archive=archive)
        data = json.loads(res)

        # 1. autonavconstructor must target <init> with "main_app_autonav" in strings
        autonav = next((h for h in data["hooks"] if "autonavconstructor" in h["id"]), None)
        self.assertIsNotNone(autonav)
        self.assertEqual(autonav["fingerprint"]["method_name"], "<init>")
        self.assertEqual(autonav["fingerprint"]["return_type"], "void")
        self.assertIn("main_app_autonav", autonav["fingerprint"].get("strings", []))

        # 2. No UPPERCASE constants as method_name
        for h in data["hooks"]:
            fp = h["fingerprint"]
            m_name = fp.get("method_name")
            if m_name and m_name != "<init>":
                self.assertFalse(m_name.isupper() and len(m_name) > 3, f"Constant assigned as method_name: {m_name} in {h['id']}")


if __name__ == "__main__":
    unittest.main()
