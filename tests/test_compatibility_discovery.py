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


if __name__ == "__main__":
    unittest.main()
