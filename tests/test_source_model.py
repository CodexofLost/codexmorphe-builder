import unittest
from pathlib import Path
from codexmorphe_builder.config import SOURCES_DIR
from codexmorphe_builder.fetcher.source_model import load_all_sources, SourceDescriptor


class TestSourceModel(unittest.TestCase):
    def test_load_all_sources(self):
        sources = load_all_sources(SOURCES_DIR)
        self.assertGreaterEqual(len(sources), 5, "Should have loaded at least 5 configured sources")
        self.assertIn("official", sources)
        self.assertIn("hushgram", sources)
        self.assertIn("piko", sources)

    def test_official_source_schema(self):
        sources = load_all_sources(SOURCES_DIR)
        official = sources["official"]
        self.assertEqual(official.id, "official")
        self.assertEqual(official.repository, "MorpheApp/morphe-patches")
        self.assertTrue(official.matches_asset("patches-1.48.0.mpp"))
        self.assertFalse(official.matches_asset("other-file.zip"))


if __name__ == "__main__":
    unittest.main()
