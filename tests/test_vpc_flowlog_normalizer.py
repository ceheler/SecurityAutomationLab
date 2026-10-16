import unittest
from scripts.vpc_flowlog_normalizer import normalize_record, normalize_file
from tempfile import TemporaryDirectory
from pathlib import Path

class VPCFlowLogNormalizerTests(unittest.TestCase):

    def test_normalize_record_valid_tcp_reject(self):
        test_string = "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 22 6 1 60 1792065600 1792065660 REJECT OK"
        result = normalize_record(test_string)

        self.assertIsNotNone(result)
        self.assertEqual(22, result["DestinationPort"])
        self.assertEqual("TCP", result["Protocol"])
        self.assertEqual("NetworkConnectionBlocked", result["EventType"])

    def test_no_results_from_accept_traffic(self):
        test_string = "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 22 6 1 60 1792065600 1792065660 ACCEPT OK"
        result = normalize_record(test_string)

        self.assertIsNone(result)

    def test_no_results_from_truncated_record(self):
        test_string = "2 123456789012 eni-0abc1234 192.0.2.10"
        result = normalize_record(test_string)

        self.assertIsNone(result)

    def test_no_results_from_unsupported_protocol(self):
        test_string = "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 22 47 1 60 1792065600 1792065660 REJECT OK"
        result = normalize_record(test_string)

        self.assertIsNone(result)

    def test_invalid_numeric_fields_return_none(self):
        test_string = "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 22 6 1 60 1792065600 1792065660 REJECT OK"


        invalid_index_values = [
            (6, "-"),
            (7, "invalid"),
            (10, "invalid")
        ]

        for index, value in invalid_index_values:
            with self.subTest(index=index):
                raw_result = test_string.split()
                raw_result[index] = value
                new_string = " ".join(raw_result)
                result = normalize_record(new_string)
                self.assertIsNone(result)

    def test_normalize_file_skips_invalid_records(self):
        records = [
            "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 22 6 1 60 1792065600 1792065660 REJECT OK",
            "2 123456789012 eni-0abc1234 192.0.2.10",
            "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 80 6 1 60 1792065610 1792065670 ACCEPT OK",
            "2 123456789012 eni-0abc1234 192.0.2.10 198.51.100.20 51514 443 6 1 60 1792065620 1792065680 REJECT OK"
        ]

        with TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "test_vpc_flowlog.txt"

            test_path.write_text("\n".join(records), encoding="utf-8")

            results = normalize_file(test_path)

            self.assertEqual(2, len(results))
            self.assertEqual(22, results[0]["DestinationPort"])
            self.assertEqual(443, results[1]["DestinationPort"])
