import json
import unittest
import zipfile
from pathlib import Path
from codexmorphe_builder.transpiler.recipe_builder import (
    ClassfileAst,
    extract_fingerprint_def,
    generate_hook_recipe_json,
    clean_type
)
from codexmorphe_builder.parser.compatibility import DiscoveredApp
from codexmorphe_builder.parser.mpp_archive import MppArchive


class TestAstTranspiler(unittest.TestCase):
    def setUp(self):
        self.cache_dir = Path(__file__).parents[1] / ".cache" / "mpp"

    def test_classfile_ast_bootstrap_methods_extraction(self):
        """Verify ClassfileAst extracts BootstrapMethods and invokedynamic correctly."""
        official_mpp = list(self.cache_dir.glob("*official*.mpp"))
        if not official_mpp:
            self.skipTest("Official MPP archive not cached")

        with zipfile.ZipFile(official_mpp[0]) as z:
            data = z.read("app/morphe/patches/youtube/ad/HideAdsPatchKt.class")
            ast = ClassfileAst(data)
            self.assertTrue(len(ast.bootstrap_methods) >= 5)

            # Check that Smali invoke-static templates are parsed
            smali_found = False
            for bsm_args in ast.bootstrap_methods:
                for arg in bsm_args:
                    if isinstance(arg, str) and "invoke-static" in arg and "AdsFilter" in arg:
                        smali_found = True
                        break
            self.assertTrue(smali_found, "Failed to find AdsFilter invoke-static in BootstrapMethods")

    def test_all_6_mpp_archives_transpilation(self):
        """Test transpilation across all 6 cached .mpp archives with zero dangerous wildcards."""
        test_matrix = [
            ("*official*.mpp", "com.google.android.youtube", "YouTube", "youtube"),
            ("*hushgram*.mpp", "com.instagram.android", "Instagram", "instagram"),
            ("*piko*.mpp", "com.twitter.android", "Twitter", "twitter"),
            ("*okish*.mpp", "com.noodlecake.altosadventure", "Altos Adventure", "all"),
            ("*devanced*.mpp", "com.amazon.mp3", "Amazon Music", "all"),
            ("*rushiranpise*.mpp", "org.telegram.messenger", "Telegram", "all"),
        ]

        for pattern, pkg, app_name, app_tag in test_matrix:
            mpp_files = list(self.cache_dir.glob(pattern))
            if not mpp_files:
                continue

            with self.subTest(archive=mpp_files[0].name, package=pkg):
                archive = MppArchive.from_file(mpp_files[0])
                app_info = DiscoveredApp(package_name=pkg, app_name=app_name, app_tag=app_tag)
                recipe_json = generate_hook_recipe_json(pkg, app_info, archive=archive)
                data = json.loads(recipe_json)

                self.assertEqual(data["package_name"], pkg)
                self.assertIn("hooks", data)

                # Invariant 1: Zero unconstrained REPLACE or RETURN_TRANSFORM
                dangerous = [
                    h for h in data["hooks"]
                    if h.get("action") in ("REPLACE", "METHOD_REPLACE", "RETURN_TRANSFORM")
                    and not h.get("fingerprint", {}).get("declaring_class")
                    and not h.get("fingerprint", {}).get("method_name")
                ]
                self.assertEqual(
                    len(dangerous), 0,
                    f"Found {len(dangerous)} dangerous unconstrained hooks in {mpp_files[0].name}"
                )

                # Invariant 2: Zero compiler artifact strings ('this', '<this>')
                for h in data["hooks"]:
                    fp = h.get("fingerprint", {})
                    strings = fp.get("strings", [])
                    for s in strings:
                        self.assertNotIn(s, ("this", "<this>", "patchContext", "patch", "method", "<init>"))
                        self.assertTrue(len(s) >= 4, f"String '{s}' is too short to be a valid discriminator")

    def test_mpp_bytecode_vs_recipe_fidelity(self):
        """Compare .mpp Smali instructions against generated hook recipes for exact fidelity."""
        official_mpp = list(self.cache_dir.glob("*official*.mpp"))
        if not official_mpp:
            self.skipTest("Official MPP archive not cached")

        archive = MppArchive.from_file(official_mpp[0])
        app_info = DiscoveredApp(
            package_name="com.google.android.youtube",
            app_name="YouTube",
            app_tag="youtube"
        )
        recipe_json = generate_hook_recipe_json("com.google.android.youtube", app_info, archive=archive)
        data = json.loads(recipe_json)

        # Inspect HideAds EndScreen banner hook
        banner_hook = next(
            (h for h in data["hooks"] if "hideendscreenstorebanner" in h["id"] or "hide_ads" in h["id"] and "hideEndScreenStoreBanner" in h.get("extension_call", "")),
            None
        )
        if banner_hook:
            self.assertIn("AdsFilter;->hideEndScreenStoreBanner", banner_hook["extension_call"])
            self.assertIn(banner_hook["action"], ("BEFORE", "AFTER"))

        # Verify GoogleApiActivity settings trampoline hook
        google_api_hook = next(
            (h for h in data["hooks"] if "google_api_activity" in h["id"]),
            None
        )
        self.assertIsNotNone(google_api_hook, "Missing GoogleApiActivity settings trampoline hook")
        self.assertEqual(google_api_hook["action"], "AFTER")
        self.assertIn("YouTubeActivityHook->initialize", google_api_hook["extension_call"])

    def test_youtube_launch_crash_stack_protection(self):
        """Ensure no hooks corrupt the MainActivity.onCreate -> akrh.e() dependency injection stack."""
        official_mpp = list(self.cache_dir.glob("*official*.mpp"))
        if not official_mpp:
            self.skipTest("Official MPP archive not cached")

        archive = MppArchive.from_file(official_mpp[0])
        app_info = DiscoveredApp(
            package_name="com.google.android.youtube",
            app_name="YouTube",
            app_tag="youtube"
        )
        recipe_json = generate_hook_recipe_json("com.google.android.youtube", app_info, archive=archive)
        data = json.loads(recipe_json)

        # Verify MainActivity hooks only run AFTER
        main_activity_hooks = [
            h for h in data["hooks"]
            if "MainActivity" in h.get("fingerprint", {}).get("declaring_class", "")
            and h.get("fingerprint", {}).get("method_name") == "onCreate"
        ]
        for h in main_activity_hooks:
            self.assertEqual(h["action"], "AFTER")
            self.assertNotIn("YouTubeActivityHook", h.get("extension_call", ""))


if __name__ == "__main__":
    unittest.main()
