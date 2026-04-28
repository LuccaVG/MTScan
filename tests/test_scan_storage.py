import unittest
from pathlib import Path

from src import scan_storage


class ScanStorageTests(unittest.TestCase):
    def test_file_store_saves_lists_and_fetches_scan_records(self):
        history_file = Path("tests") / "_scan_history.jsonl"
        history_file.unlink(missing_ok=True)
        store = scan_storage.FileScanStore(history_file)

        try:
            store.save_scan(
                {
                    "id": "abc123def456",
                    "target": "example.com",
                    "mode": "chain",
                    "status": "completed",
                    "created_at": "2026-04-28T01:00:00",
                    "finished_at": "2026-04-28T01:01:00",
                    "summary": {
                        "open_ports": 2,
                        "http_services": 1,
                        "security_findings": 0,
                        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
                    },
                    "results": [{"tool": "naabu", "success": True}],
                    "report_file": "vulnerability_report.md",
                }
            )

            scans = store.list_scans()
            fetched = store.get_scan("abc123def456")
        finally:
            history_file.unlink(missing_ok=True)

        self.assertEqual(len(scans), 1)
        self.assertIsNotNone(fetched)
        self.assertEqual(scans[0]["target"], "example.com")
        self.assertEqual(scans[0]["summary"]["open_ports"], 2)
        self.assertEqual(fetched["report_file"], "vulnerability_report.md")

    def test_invalid_cassandra_identifier_is_rejected(self):
        with self.assertRaises(RuntimeError):
            scan_storage._cql_identifier("bad-name")


if __name__ == "__main__":
    unittest.main()
