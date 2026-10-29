import unittest
from codexmorphe_builder.filter.root_filter import filter_redundant_patches, is_patch_redundant


class TestRootFilter(unittest.TestCase):
    def test_redundant_patches_identified(self):
        redundant_samples = [
            "Lapp/morphe/patches/youtube/misc/gms/GmsCoreSupportPatchKt;",
            "Lapp/morphe/patches/youtube/misc/fix/signature/SpoofSignaturePatchKt;",
            "Lapp/morphe/patches/reddit/misc/clone/CloneAppPatchKt;",
            "Lapp/morphe/patches/all/misc/pairip/PairipBypassSignaturePatchKt;",
            "Lapp/morphe/patches/youtube/misc/update/DisablePlayStoreUpdatesPatchKt;"
        ]
        for p in redundant_samples:
            is_red, reason = is_patch_redundant(p)
            self.assertTrue(is_red, f"Should identify {p} as redundant")

    def test_genuine_feature_patches_retained(self):
        genuine_samples = [
            "Lapp/morphe/patches/youtube/ad/HideAdsPatchKt;",
            "Lapp/morphe/patches/youtube/misc/backgroundplayback/BackgroundPlaybackPatchKt;",
            "Lapp/morphe/patches/reddit/misc/privacy/SanitizeSharingLinksPatchKt;",
            "Lapp/morphe/patches/amznmusic/ads/SkipAdsPatchKt;",
            "Lapp/altosadventure/patches/iap/AltoIAPUnlockPatchKt;"
        ]
        for p in genuine_samples:
            is_red, _ = is_patch_redundant(p)
            self.assertFalse(is_red, f"Should retain genuine patch {p}")

    def test_filter_list(self):
        mixed = [
            "Lapp/morphe/patches/youtube/ad/HideAdsPatchKt;",
            "Lapp/morphe/patches/youtube/misc/gms/GmsCoreSupportPatchKt;",
            "Lapp/morphe/patches/youtube/misc/backgroundplayback/BackgroundPlaybackPatchKt;"
        ]
        retained, dropped = filter_redundant_patches(mixed)
        self.assertEqual(len(retained), 2)
        self.assertEqual(len(dropped), 1)
        self.assertIn("GmsCoreSupportPatchKt", dropped[0][0])


if __name__ == "__main__":
    unittest.main()
