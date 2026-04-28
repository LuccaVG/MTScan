import unittest
from pathlib import Path
from unittest.mock import patch

from src import tool_runner


class ToolRunnerTests(unittest.TestCase):
    def test_extract_naabu_targets_ignores_banner_lines(self):
        lines = [
            "projectdiscovery.io",
            "[INF] Current naabu version 2.1.8 (outdated)",
            "127.0.0.1:80",
            '{"host":"localhost","port":443}',
            '{"host":"localhost","port":"not-a-port"}',
        ]

        self.assertEqual(
            tool_runner._extract_naabu_targets(lines),
            [
                "127.0.0.1:80",
                "localhost:443",
            ],
        )

    def test_scanner_status_lines_are_not_security_findings(self):
        lines = [
            "[WRN] Found 1 templates with syntax error (use -validate flag for further examination)",
            "[INF] Skipped 127.0.0.1:80 from target list as found unresponsive 30 times",
            "[INF] No results found. Better luck next time!",
        ]

        self.assertFalse(any(tool_runner.is_security_finding_line(line) for line in lines))
        self.assertFalse(any(tool_runner.is_informational_finding_line(line) for line in lines))

    def test_only_security_severity_nuclei_results_count_as_risks(self):
        high_result = "[exposed-panel] [http] [high] http://127.0.0.1:8080"
        info_result = "[tech-detect] [http] [info] http://127.0.0.1:8080"

        self.assertTrue(tool_runner.is_security_finding_line(high_result))
        self.assertFalse(tool_runner.is_security_finding_line(info_result))
        self.assertTrue(tool_runner.is_informational_finding_line(info_result))

    def test_scan_request_validation_rejects_unsafe_or_invalid_input(self):
        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_scan_request("example.com; rm -rf /", {})

        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_scan_request("example.com", {"ports": "443-80"})

        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_scan_request("example.com", {"severity": "urgent"})

    def test_security_findings_report_separates_observations_from_risks(self):
        output_dir = Path("tests") / "_report_output"
        output_dir.mkdir(exist_ok=True)
        nuclei_file = output_dir / "nuclei_results.txt"
        report = output_dir / "security_findings_report.md"
        nuclei_file.write_text(
            "\n".join(
                [
                    "[tech-detect] [http] [info] http://127.0.0.1:8080",
                    "[exposed-panel] [http] [high] http://127.0.0.1:8080",
                ]
            ),
            encoding="utf-8",
        )

        try:
            tool_runner.write_security_findings_report(
                output_dir,
                "127.0.0.1",
                [
                    tool_runner.ToolResult(
                        tool="nuclei",
                        command=["nuclei"],
                        success=True,
                        output_file=nuclei_file,
                    )
                ],
            )
            text = report.read_text(encoding="utf-8")
        finally:
            nuclei_file.unlink(missing_ok=True)
            report.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        self.assertIn("- Total security findings: 1", text)
        self.assertIn("- Informational observations: 1", text)
        self.assertIn("exposed-panel", text)
        self.assertNotIn("| INFO |", text)

    def test_run_chain_falls_back_to_original_target_when_naabu_has_no_targets(self):
        calls = []

        def fake_run_command(tool, command, timeout=None, output_file=None, dry_run=False, on_line=None):
            calls.append((tool, list(command), Path(output_file) if output_file else None))
            output_lines = ["projectdiscovery.io", "[INF] Current naabu version 2.1.8"] if tool == "naabu" else []
            return tool_runner.ToolResult(
                tool=tool,
                command=list(command),
                success=True,
                returncode=0,
                output_lines=output_lines,
                output_file=Path(output_file) if output_file else None,
            )

        output_dir = Path("tests") / "_chain_output"
        created_files = [
            output_dir / "nuclei_targets.txt",
            output_dir / "nuclei_results.txt",
            output_dir / "comprehensive_scan_report.txt",
            output_dir / "security_findings_report.md",
        ]
        output_dir.mkdir(exist_ok=True)
        for path in created_files:
            path.unlink(missing_ok=True)

        try:
            with patch.object(tool_runner, "get_executable_path", lambda tool: tool):
                with patch.object(tool_runner, "run_command", fake_run_command):
                    results = tool_runner.run_chain("127.0.0.1", output_dir=output_dir, on_line=lambda _line: None)
        finally:
            for path in created_files:
                path.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        httpx_call = next(command for tool, command, _ in calls if tool == "httpx")
        self.assertIn("-u", httpx_call)
        self.assertIn("127.0.0.1", httpx_call)
        self.assertNotIn("-l", httpx_call)
        self.assertEqual([tool for tool, _, _ in calls], ["naabu", "httpx"])
        self.assertEqual(results[-1].tool, "nuclei")
        self.assertEqual(results[-1].command, [])
        self.assertTrue(results[-1].success)

    def test_summarize_scan_results_counts_surface_and_findings(self):
        output_dir = Path("tests") / "_summary_output"
        output_dir.mkdir(exist_ok=True)
        nuclei_file = output_dir / "nuclei_results.txt"
        nuclei_file.write_text(
            "\n".join(
                [
                    "[tech-detect] [http] [info] http://127.0.0.1:8080",
                    "[exposed-panel] [http] [high] http://127.0.0.1:8080",
                ]
            ),
            encoding="utf-8",
        )

        try:
            summary = tool_runner.summarize_scan_results(
                "127.0.0.1",
                [
                    tool_runner.ToolResult("naabu", ["naabu"], True, output_lines=["127.0.0.1:80"]),
                    tool_runner.ToolResult("httpx", ["httpx"], True, output_lines=["http://127.0.0.1:80"]),
                    tool_runner.ToolResult("nuclei", ["nuclei"], True, output_file=nuclei_file),
                ],
            )
        finally:
            nuclei_file.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        self.assertEqual(summary["open_ports"], 1)
        self.assertEqual(summary["http_services"], 1)
        self.assertEqual(summary["security_findings"], 1)
        self.assertEqual(summary["observations"], 1)


if __name__ == "__main__":
    unittest.main()
