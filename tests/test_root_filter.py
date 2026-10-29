import unittest
from codexmorphe_builder.filter.root_filter import filter_redundant_patches, is_patch_redundant


class TestRootFilter(unittest.TestCase):
    def test_all_nine_categories_identified(self):
        samples_by_category = {
            "Cat 1 - Branding": "Lapp/morphe/patches/youtube/layout/branding/CustomBrandingPatchKt;",
            "Cat 1 - App Icon": "Lapp/crimera/patches/twitter/misc/appicon/AppIconPatchKt;",
            "Cat 2 - Signature": "Lapp/morphe/patches/all/misc/fix/spoofsignature/SpoofSignaturePatchKt;",
            "Cat 2 - Cert Hash": "Lapp/template/patches/shared/firebase/SpoofFirebaseCertHashPatchKt;",
            "Cat 2 - Transparency": "Lapp/template/patches/excel/integrity/BypassCodeTransparencyPatchKt;",
            "Cat 3 - GmsCore": "Lapp/morphe/patches/youtube/misc/gms/GmsCoreSupportPatchKt;",
            "Cat 3 - Play Version": "Lapp/morphe/patches/youtube/misc/playservice/VersionCheckPatchKt;",
            "Cat 4 - Clone": "Lapp/crimera/patches/instagram/misc/clone/ClonePatchKt;",
            "Cat 4 - Coexist": "Lapp/morphe/patches/instagram/coexist/InstallNextToInstagramPatchKt;",
            "Cat 5 - Play Store Updates": "Lapp/morphe/patches/all/misc/updates/DisablePlayStoreUpdatesPatchKt;",
            "Cat 5 - Screen Update": "Lapp/crimera/patches/twitter/misc/blockUpdateScreen/BlockUpdateScreenPatchKt;",
            "Cat 6 - Manifest SharedUserId": "Lapp/template/patches/excel/manifest/RemoveSharedUserIdPatchKt;",
            "Cat 6 - Duplicate Permissions": "Lapp/template/patches/amazon/manifest/FixDuplicatePermissionsPatchKt;",
            "Cat 7 - PairIP Anti-Tamper": "Lapp/bighunter/patches/license/BigHunterPairipBypassPatchKt;",
            "Cat 7 - Native Kill Gate": "Lapp/swiftbackup/patches/tamper/SwiftBackupNativeKillGatePatchKt;",
            "Cat 8 - Fix Content Provider": "Lapp/morphe/patches/youtube/misc/fix/contentprovider/FixContentProviderPatchKt;",
            "Cat 8 - Fix Preference Icon": "Lapp/morphe/extension/youtube/patches/FixPreferenceIconPatch;",
            "Cat 9 - Debugging": "Lapp/morphe/patches/all/misc/debugging/EnableAndroidDebuggingPatchKt;",
            "Cat 9 - Overflow Debug": "Lapp/crimera/patches/instagram/misc/overflowMenuButton/posts/debugOverflowButton/DebugOverflowMenuButtonPatchKt;"
        }
        for desc, cls in samples_by_category.items():
            is_red, reason = is_patch_redundant(cls)
            self.assertTrue(is_red, f"Should identify {desc} ({cls}) as redundant. Reason: {reason}")

    def test_genuine_features_strictly_retained(self):
        genuine_samples = [
            # Core feature patches
            "Lapp/morphe/patches/youtube/ad/HideAdsPatchKt;",
            "Lapp/morphe/patches/youtube/misc/backgroundplayback/BackgroundPlaybackPatchKt;",
            "Lapp/morphe/patches/reddit/misc/privacy/SanitizeSharingLinksPatchKt;",
            "Lapp/morphe/patches/amznmusic/ads/SkipAdsPatchKt;",
            "Lapp/altosadventure/patches/iap/AltoIAPUnlockPatchKt;",
            # Proof of Origin (essential for YouTube playback)
            "Lapp/morphe/patches/youtube/misc/potoken/PoTokenProviderPatchKt;",
            "Lapp/morphe/extension/shared/patches/PoTokenProviderPatch;",
            # UI styling inside video player / shorts (not launcher icons)
            "Lapp/morphe/patches/youtube/layout/player/icons/PlayerIconStylePatchKt;",
            "Lapp/morphe/patches/youtube/layout/shortsicons/ShortsIconStylePatchKt;",
            # Messenger external link handler (distinct from GmsCore link handler)
            "Lapp/morphe/patches/messenger/linkhandling/OpenLinksExternallyPatchKt;",
            # In-app unlocks
            "Lapp/template/patches/oxygenupdater/premium/OxygenUpdaterPremiumPatchKt;"
        ]
        for p in genuine_samples:
            is_red, reason = is_patch_redundant(p)
            self.assertFalse(is_red, f"Should retain genuine feature {p}, but got rejected with: {reason}")

    def test_filter_list(self):
        mixed = [
            "Lapp/morphe/patches/youtube/ad/HideAdsPatchKt;",
            "Lapp/morphe/patches/youtube/misc/gms/GmsCoreSupportPatchKt;",
            "Lapp/morphe/patches/youtube/misc/potoken/PoTokenProviderPatchKt;",
            "Lapp/morphe/patches/youtube/layout/branding/CustomBrandingPatchKt;"
        ]
        retained, dropped = filter_redundant_patches(mixed)
        self.assertEqual(len(retained), 2)
        self.assertEqual(len(dropped), 2)
        self.assertIn("HideAdsPatchKt", retained[0])
        self.assertIn("PoTokenProviderPatchKt", retained[1])


if __name__ == "__main__":
    unittest.main()
