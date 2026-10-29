"""Tests for assessment-specific artifact paths."""

import unittest

from modules.artifacts import assessment_artifact_paths


class ArtifactPathTests(unittest.TestCase):
    def test_two_assessments_have_distinct_preserved_paths(self) -> None:
        first = assessment_artifact_paths(1)
        second = assessment_artifact_paths(2)

        self.assertNotEqual(first.capture, second.capture)
        self.assertNotEqual(first.report, second.report)
        self.assertEqual(first.capture.as_posix(), "data/assessments/1/capture.pcap")
        self.assertEqual(second.report.as_posix(), "reports/assessments/2/report.html")


if __name__ == "__main__":
    unittest.main()
