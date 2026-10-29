import unittest
from codexmorphe_builder.filter.root_filter import filter_redundant_patches, is_patch_redundant


class TestRootFilter(unittest.TestCase):
    def test_strictly_redundant_categories_identified(self):
        samples_by_category = {
            "Cat 1 - Custom Branding": "Lapp/morphe/patches/youtube/layout/branding/CustomBrandingPatchKt;",
            "Cat 1 - App Launcher Icon": "Lapp/crimera/patches/twitter/misc/appicon/AppIconPatchKt;",
            "Cat 1 - Change Header": "Lapp/morphe/patches/music/layout/branding/header/ChangeHeaderPatchKt;",
            "Cat 2 - GmsCore Redirection": "Lapp/morphe/patches/youtube/misc/gms/GmsCoreSupportPatchKt;",
            "Cat 2 - Play Version Check": "Lapp/morphe/patches/youtube/misc/playservice/VersionCheckPatchKt;",
            "Cat 3 - App Cloning": "Lapp/crimera/patches/instagram/misc/clone/ClonePatchKt;",
            "Cat 3 - Coexist Cloning": "Lapp/morphe/patches/instagram/coexist/InstallNextToInstagramPatchKt;",
            "Cat 4 - Manifest SharedUserId": "Lapp/template/patches/excel/manifest/RemoveSharedUserIdPatchKt;",
            "Cat 4 - Duplicate Permissions": "Lapp/template/patches/amazon/manifest/FixDuplicatePermissionsPatchKt;",
            "Cat 5 - Fix Content Provider": "Lapp/morphe/patches/youtube/misc/fix/contentprovider/FixContentProviderPatchKt;",
            "Cat 5 - Fix Preference Icon": "Lapp/morphe/extension/youtube/patches/FixPreferenceIconPatch;",
            "Cat 6 - Debugging Mode": "Lapp/morphe/patches/all/misc/debugging/EnableAndroidDebuggingPatchKt;",
            "Cat 6 - Overflow Debug": "Lapp/crimera/patches/instagram/misc/overflowMenuButton/posts/debugOverflowButton/DebugOverflowMenuButtonPatchKt;"
        }
        for desc, cls in samples_by_category.items():
            is_red, reason = is_patch_redundant(cls)
            self.assertTrue(is_red, f"Should identify {desc} ({cls}) as redundant. Reason: {reason}")

    def test_sideloading_compatibility_and_features_retained(self):
        sideloading_and_feature_samples = [
            # 1. PairIP & Native Anti-Tamper Kill Gates (Prevents System.exit(0) on sideloaded APKs)
            "Lapp/lumina/patches/license/LuminaPairipBypassPatchKt;",
            "Lapp/bighunter/patches/license/BigHunterPairipBypassPatchKt;",
            "Lapp/minutestilldawn/patches/pairip/PairipBypassPatchKt;",
            "Lapp/onlyone/patches/pairip/OnlyOnePairIpRemovalPatchKt;",
            "Lapp/swiftbackup/patches/tamper/SwiftBackupNativeKillGatePatchKt;",
            # 2. In-App Forced Update Blockers (Prevents undismissable popups on older supported versions)
            "Lapp/crimera/patches/twitter/misc/blockUpdateScreen/BlockUpdateScreenPatchKt;",
            "Lapp/morphe/patches/youtube/layout/hide/updatescreen/HideUpdateScreenPatchKt;",
            "Lapp/morphe/patches/photomath/misc/annoyances/HideUpdatePopupPatchKt;",
            "Lapp/template/patches/telegram/ads/TelegramDisableAutoUpdatePatchKt;",
            # 3. Google Play Store Auto-Update Blocker (Prevents Play Store overwriting supported version)
            "Lapp/morphe/patches/all/misc/updates/DisablePlayStoreUpdatesPatchKt;",
            "Lapp/morphe/extension/all/versioncode/DisablePlayStoreUpdatesPatch;",
            # 4. Code Transparency & Certificate Pinning Bypasses
            "Lapp/template/patches/excel/integrity/BypassCodeTransparencyPatchKt;",
            "Lapp/template/patches/word/integrity/BypassCodeTransparencyPatchKt;",
            "Lapp/morphe/patches/all/misc/network/OverrideCertificatePinningPatchKt;",
            # 5. Core Feature Patches & In-App Unlocks
            "Lapp/morphe/patches/youtube/ad/HideAdsPatchKt;",
            "Lapp/morphe/patches/youtube/misc/backgroundplayback/BackgroundPlaybackPatchKt;",
            "Lapp/morphe/patches/reddit/misc/privacy/SanitizeSharingLinksPatchKt;",
            "Lapp/morphe/patches/youtube/misc/potoken/PoTokenProviderPatchKt;",
            "Lapp/altosadventure/patches/iap/AltoIAPUnlockPatchKt;",
            "Lapp/morphe/patches/messenger/linkhandling/OpenLinksExternallyPatchKt;"
        ]
        for p in sideloading_and_feature_samples:
            is_red, reason = is_patch_redundant(p)
            self.assertFalse(is_red, f"Should retain sideloading/feature patch {p}, but got rejected with: {reason}")

    def test_filter_list(self):
        mixed = [
            "Lapp/morphe/patches/youtube/ad/HideAdsPatchKt;",
            "Lapp/morphe/patches/youtube/misc/gms/GmsCoreSupportPatchKt;",
            "Lapp/lumina/patches/license/LuminaPairipBypassPatchKt;",
            "Lapp/crimera/patches/twitter/misc/blockUpdateScreen/BlockUpdateScreenPatchKt;",
            "Lapp/morphe/patches/youtube/layout/branding/CustomBrandingPatchKt;"
        ]
        retained, dropped = filter_redundant_patches(mixed)
        self.assertEqual(len(retained), 3)
        self.assertEqual(len(dropped), 2)
        self.assertIn("HideAdsPatchKt", retained[0])
        self.assertIn("LuminaPairipBypassPatchKt", retained[1])
        self.assertIn("BlockUpdateScreenPatchKt", retained[2])


if __name__ == "__main__":
    unittest.main()
