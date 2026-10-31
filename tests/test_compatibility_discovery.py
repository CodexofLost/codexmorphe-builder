import tempfile
import unittest
from pathlib import Path

from codexmorphe_builder.parser.compatibility import discover_compatible_apps
from codexmorphe_builder.parser.mpp_archive import MppArchive


class TestCompatibilityDiscovery(unittest.TestCase):
    def setUp(self):
        self.cache_dir = Path(__file__).parents[1] / ".cache" / "mpp"

    def test_all_6_archives_genuine_app_discovery(self):
        """
        Assert genuine application counts and zero fake packages across all 6 cached archives.
        """
        expected_counts = {
            "official": 3,
            "hushgram": 1,
            "piko": 2,
            "devanced": 25,
            "okish": 50,
            "rushiranpise": 227,
        }

        fake_prohibited = {
            "com.premium.app",
            "com.cloud.app",
            "com.login.app",
            "com.aaad.app",
            "com.allreader.app",
            "com.pro.app",
            "com.vip.app",
            "com.plus.app"
        }

        for source_key, expected_count in expected_counts.items():
            matches = list(self.cache_dir.glob(f"*{source_key}*.mpp"))
            if not matches:
                self.skipTest(f"Archive {source_key} not cached")

            archive = MppArchive.from_file(matches[0])
            discovered = discover_compatible_apps(archive)

            self.assertEqual(
                len(discovered),
                expected_count,
                f"Source {source_key} expected {expected_count} apps, got {len(discovered)}"
            )

            # Assert ZERO fake prohibited bundles are present
            discovered_pkgs = set(discovered.keys())
            overlap = discovered_pkgs.intersection(fake_prohibited)
            self.assertEqual(
                len(overlap),
                0,
                f"Source {source_key} produced prohibited fake package(s): {overlap}"
            )

    def test_universal_patches_excluded_from_closures(self):
        """
        Assert that offline repackaging patches in /patches/all/ (CloneApp, SpoofSignature, etc.)
        are completely excluded from application patch closures.
        """
        official_mpp = list(self.cache_dir.glob("*official*.mpp"))
        if not official_mpp:
            self.skipTest("Official MPP archive not cached")

        archive = MppArchive.from_file(official_mpp[0])
        discovered = discover_compatible_apps(archive)

        for pkg, app in discovered.items():
            for p_cls in app.patch_classes:
                self.assertNotIn(
                    "/patches/all/",
                    p_cls,
                    f"App {pkg} contains universal repackaging patch in closure: {p_cls}"
                )

    def test_extension_extraction_completeness(self):
        """
        Verify that YouTube, YouTube Music, and Reddit extract their required extensions.
        """
        official_mpp = list(self.cache_dir.glob("*official*.mpp"))
        if not official_mpp:
            self.skipTest("Official MPP archive not cached")

        archive = MppArchive.from_file(official_mpp[0])
        discovered = discover_compatible_apps(archive)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)

            # 1. YouTube
            yt = discovered["com.google.android.youtube"]
            yt_exts = {
                e.name for e in archive.extract_extensions_for_app(
                    yt.app_tag, tmp / "yt", app_pkg=yt.package_name, patch_classes=yt.patch_classes
                )
            }
            self.assertIn("youtube.dex", yt_exts)
            self.assertIn("shared-youtube.dex", yt_exts)
            self.assertIn("shared.dex", yt_exts)

            # 2. YouTube Music (must have shared-youtube.dex and music.dex, but NOT youtube.dex)
            music = discovered["com.google.android.apps.youtube.music"]
            music_exts = {
                e.name for e in archive.extract_extensions_for_app(
                    music.app_tag, tmp / "music", app_pkg=music.package_name, patch_classes=music.patch_classes
                )
            }
            self.assertIn("music.dex", music_exts)
            self.assertIn("shared-youtube.dex", music_exts)
            self.assertIn("shared.dex", music_exts)
            self.assertNotIn("youtube.dex", music_exts)

            # 3. Reddit
            reddit = discovered["com.reddit.frontpage"]
            reddit_exts = {
                e.name for e in archive.extract_extensions_for_app(
                    reddit.app_tag, tmp / "reddit", app_pkg=reddit.package_name, patch_classes=reddit.patch_classes
                )
            }
            self.assertIn("reddit.dex", reddit_exts)
            self.assertIn("shared.dex", reddit_exts)
            self.assertNotIn("youtube.dex", reddit_exts)

    def test_resource_extraction_fidelity_and_isolation(self):
        """
        Verify that shared and app-specific resources are properly isolated without cross-contamination:
        1. YouTube includes youtube_strings.xml and shared-youtube_strings.xml, but NOT music_strings.xml.
        2. YouTube Music includes music_strings.xml and shared-youtube_strings.xml, but NOT youtube_strings.xml.
        3. Reddit includes reddit_strings.xml, but NOT youtube or music strings.
        4. Waze in rushiranpise extracts waze root assets into assets/.
        """
        official_mpp = list(self.cache_dir.glob("*official*.mpp"))
        if not official_mpp:
            self.skipTest("Official MPP archive not cached")

        archive = MppArchive.from_file(official_mpp[0])
        discovered = discover_compatible_apps(archive)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)

            # 1. YouTube
            yt = discovered["com.google.android.youtube"]
            yt_res = tmp / "yt_res"
            yt_assets = tmp / "yt_assets"
            archive.extract_resources_for_app(
                yt.app_tag, yt_res, dest_assets_dir=yt_assets, app_pkg=yt.package_name, patch_classes=yt.patch_classes
            )
            yt_files = {f.name for f in yt_res.rglob("*.xml")}
            self.assertIn("youtube_strings.xml", yt_files)
            self.assertIn("shared-youtube_strings.xml", yt_files)
            self.assertIn("shared_strings.xml", yt_files)
            self.assertNotIn("music_strings.xml", yt_files)

            # 2. YouTube Music
            music = discovered["com.google.android.apps.youtube.music"]
            music_res = tmp / "music_res"
            music_assets = tmp / "music_assets"
            archive.extract_resources_for_app(
                music.app_tag, music_res, dest_assets_dir=music_assets, app_pkg=music.package_name, patch_classes=music.patch_classes
            )
            music_files = {f.name for f in music_res.rglob("*.xml")}
            self.assertIn("music_strings.xml", music_files)
            self.assertIn("shared-youtube_strings.xml", music_files)
            self.assertIn("shared_strings.xml", music_files)
            self.assertNotIn("youtube_strings.xml", music_files)

            # 3. Reddit
            reddit = discovered["com.reddit.frontpage"]
            reddit_res = tmp / "reddit_res"
            reddit_assets = tmp / "reddit_assets"
            archive.extract_resources_for_app(
                reddit.app_tag, reddit_res, dest_assets_dir=reddit_assets, app_pkg=reddit.package_name, patch_classes=reddit.patch_classes
            )
            reddit_files = {f.name for f in reddit_res.rglob("*.xml")}
            self.assertIn("reddit_strings.xml", reddit_files)
            self.assertIn("shared_strings.xml", reddit_files)
            self.assertNotIn("youtube_strings.xml", reddit_files)
            self.assertNotIn("music_strings.xml", reddit_files)

        # 4. Rushiranpise Waze Assets
        rush_mpp = list(self.cache_dir.glob("*rushiranpise*.mpp"))
        if rush_mpp:
            rush_archive = MppArchive.from_file(rush_mpp[0])
            rush_discovered = discover_compatible_apps(rush_archive)
            waze = rush_discovered.get("com.waze")
            if waze:
                with tempfile.TemporaryDirectory() as tmp_dir2:
                    tmp2 = Path(tmp_dir2)
                    waze_res = tmp2 / "waze_res"
                    waze_assets = tmp2 / "waze_assets"
                    rush_archive.extract_resources_for_app(
                        waze.app_tag, waze_res, dest_assets_dir=waze_assets, app_pkg=waze.package_name, patch_classes=waze.patch_classes
                    )
                    extracted_assets = list(waze_assets.rglob("*"))
                    self.assertTrue(len(extracted_assets) > 0, "Expected Waze root assets to be extracted into assets/")


if __name__ == "__main__":
    unittest.main()
