import tempfile
import unittest
from pathlib import Path
from codexmorphe_builder.fetcher.cache_ledger import CacheLedger


class TestCacheLedger(unittest.TestCase):
    def test_ledger_update_and_lookup(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ledger_file = Path(tmp_dir) / "test-ledger.json"
            ledger = CacheLedger(ledger_file)

            dummy_file = Path(tmp_dir) / "dummy.mpp"
            dummy_file.write_text("sample content")

            ledger.update(
                source_id="test_repo",
                tag="v1.0.0",
                asset_name="dummy.mpp",
                asset_id=101,
                sha256="abc123",
                file_path=dummy_file,
                file_size=dummy_file.stat().st_size
            )

            # Reload ledger from disk
            ledger2 = CacheLedger(ledger_file)
            self.assertTrue(ledger2.is_up_to_date("test_repo", "v1.0.0", 101))
            self.assertFalse(ledger2.is_up_to_date("test_repo", "v1.0.1", 101))
            self.assertFalse(ledger2.is_up_to_date("unknown", "v1.0.0", 101))


if __name__ == "__main__":
    unittest.main()
