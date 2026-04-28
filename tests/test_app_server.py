import unittest
from pathlib import Path
from typing import List, cast

from src import app_server
from src import tool_runner


class AppServerTests(unittest.TestCase):
    def test_build_scan_options_merges_profile_and_payload(self):
        options = app_server.build_scan_options(
            {
                "profile": "stealth",
                "options": {
                    "top_ports": "50",
                    "timeout": "120",
                    "tool_silent": "true",
                },
            }
        )

        self.assertEqual(options["top_ports"], "50")
        self.assertEqual(options["timeout"], "120")
        self.assertTrue(options["tool_silent"])
        self.assertEqual(options["scan_type"], "connect")

    def test_requested_tools_for_chain_returns_all_tools(self):
        self.assertEqual(tuple(app_server.requested_tools_for_mode("chain")), app_server.tool_runner.SECURITY_TOOLS)

    def test_serialize_results_redacts_commands_and_paths(self):
        result = tool_runner.ToolResult(
            tool="httpx",
            command=[
                "/usr/local/bin/httpx",
                "-u",
                "https://example.com",
                "-H",
                "Authorization: Bearer secret",
                "-o",
                "C:\\Users\\lucca\\Desktop\\scan\\httpx_results.txt",
            ],
            success=True,
            output_file=Path("C:\\Users\\lucca\\Desktop\\scan\\httpx_results.txt"),
        )

        public = app_server.serialize_results([result])[0]
        command_preview = cast(List[str], public["command_preview"])

        self.assertEqual(public["output_file"], "httpx_results.txt")
        self.assertIn("[redacted]", command_preview)
        self.assertNotIn("secret", " ".join(command_preview))
        self.assertNotIn("C:\\Users", " ".join(command_preview))

    def test_health_payload_does_not_expose_local_paths(self):
        health = app_server.health_payload()
        text = str(health)

        self.assertIn("storage", health)
        self.assertNotIn("C:\\Users", text)
        self.assertNotIn("/usr/local/bin", text)

    def test_prune_jobs_keeps_recent_finished_jobs(self):
        old_jobs = app_server.JOBS.copy()
        try:
            app_server.JOBS.clear()
            for index in range(app_server.MAX_RETAINED_JOBS + 5):
                job = app_server.ScanJob(f"example{index}.com", "chain", {}, True, True)
                job.status = "completed"
                job.finished_at = f"2026-04-28T00:{index:02d}:00"
                app_server.JOBS[job.id] = job

            app_server.prune_jobs()

            self.assertLessEqual(len(app_server.JOBS), app_server.MAX_RETAINED_JOBS)
        finally:
            app_server.JOBS.clear()
            app_server.JOBS.update(old_jobs)


if __name__ == "__main__":
    unittest.main()
