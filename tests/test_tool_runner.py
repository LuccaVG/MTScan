import json
import unittest
from pathlib import Path
from typing import Dict, List, cast
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

    def test_default_output_dir_keeps_long_targets_short(self):
        long_target = "https://" + ("very-long-subdomain." * 40) + "example.com/path"
        output_dir = tool_runner.default_output_dir(long_target)

        self.assertLessEqual(len(output_dir.name), len("results_") + tool_runner.MAX_OUTPUT_TARGET_SLUG + 1 + 10 + 1 + 15)
        self.assertNotIn("/", output_dir.name)

    def test_vulnerability_report_separates_observations_from_risks(self):
        output_dir = Path("tests") / "_report_output"
        output_dir.mkdir(exist_ok=True)
        nuclei_file = output_dir / "nuclei_results.txt"
        report = output_dir / tool_runner.REPORT_FILENAME
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
            tool_runner.write_vulnerability_report(
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

        self.assertIn("| Security findings | 1 |", text)
        self.assertIn("| Informational observations | 1 |", text)
        self.assertIn("exposed-panel", text)
        self.assertIn("## Informational Observations", text)
        self.assertIn("| INFO | General Finding | tech-detect |", text)

    def test_vulnerability_report_extracts_cve_context_and_fix_guidance(self):
        output_dir = Path("tests") / "_cve_report_output"
        output_dir.mkdir(exist_ok=True)
        nuclei_file = output_dir / "nuclei_results.jsonl"
        report = output_dir / tool_runner.REPORT_FILENAME
        finding = {
            "template-id": "CVE-2024-12345-example-rce",
            "matched-at": "https://example.com/admin",
            "matcher-name": "version-check",
            "extracted-results": ["Example Product 1.0.0"],
            "info": {
                "name": "Example Product Remote Code Execution",
                "severity": "critical",
                "description": "Example Product before 1.2.3 allows remote command execution.",
                "impact": "Attackers may execute commands as the service user.",
                "remediation": "Upgrade Example Product to version 1.2.3 or later.",
                "reference": ["https://vendor.example/advisory/CVE-2024-12345"],
                "tags": ["cve", "rce"],
                "classification": {
                    "cve-id": "CVE-2024-12345",
                    "cwe-id": "CWE-78",
                },
            },
        }
        nuclei_file.write_text(json.dumps(finding) + "\n", encoding="utf-8")

        try:
            summary = tool_runner.summarize_scan_results(
                "example.com",
                [tool_runner.ToolResult("nuclei", ["nuclei"], True, output_file=nuclei_file)],
            )
            tool_runner.write_vulnerability_report(
                output_dir,
                "example.com",
                [tool_runner.ToolResult("nuclei", ["nuclei"], True, output_file=nuclei_file)],
            )
            text = report.read_text(encoding="utf-8")
        finally:
            nuclei_file.unlink(missing_ok=True)
            report.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        findings = cast(List[Dict[str, object]], summary.get("findings"))
        parsed = next(iter(findings))
        cves = cast(List[str], parsed.get("cve"))
        cwes = cast(List[str], parsed.get("cwe"))

        self.assertEqual(cves, ["CVE-2024-12345"])
        self.assertEqual(cwes, ["CWE-78"])
        self.assertEqual(summary.get("cve_findings"), 1)
        self.assertIn("chart_data", summary)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-12345", text)
        self.assertIn("Upgrade Example Product to version 1.2.3 or later.", text)
        self.assertIn("Example Product 1.0.0", text)

    def test_text_nuclei_output_extracts_cve_from_template_id(self):
        output_dir = Path("tests") / "_text_cve_output"
        output_dir.mkdir(exist_ok=True)
        nuclei_file = output_dir / "nuclei_results.txt"
        nuclei_file.write_text(
            "[CVE-2024-99999-panel] [http] [high] https://example.com\n",
            encoding="utf-8",
        )

        try:
            findings = tool_runner.parse_nuclei_findings(nuclei_file)
        finally:
            nuclei_file.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        parsed = next(iter(findings))
        cves = cast(List[str], parsed.get("cve"))

        self.assertEqual(cves, ["CVE-2024-99999"])

    def test_report_redacts_sensitive_command_values(self):
        output_dir = Path("tests") / "_redacted_report_output"
        output_dir.mkdir(exist_ok=True)
        report = output_dir / tool_runner.REPORT_FILENAME

        try:
            tool_runner.write_vulnerability_report(
                output_dir,
                "127.0.0.1",
                [
                    tool_runner.ToolResult(
                        tool="httpx",
                        command=[
                            "/usr/local/bin/httpx",
                            "-u",
                            "https://example.com",
                            "-H",
                            "Authorization: Bearer secret-token",
                            "-o",
                            str(output_dir / "httpx_results.txt"),
                        ],
                        success=True,
                        output_file=output_dir / "httpx_results.txt",
                    )
                ],
            )
            text = report.read_text(encoding="utf-8")
        finally:
            report.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        self.assertIn("-H [redacted]", text)
        self.assertIn("[redacted]", text)
        self.assertNotIn("secret-token", text)
        self.assertNotIn(str(output_dir), text)

    def test_report_redacts_nuclei_short_form_sensitive_values(self):
        output_dir = Path("tests") / "_redacted_nuclei_report_output"
        output_dir.mkdir(exist_ok=True)
        report = output_dir / tool_runner.REPORT_FILENAME

        try:
            tool_runner.write_vulnerability_report(
                output_dir,
                "https://example.com",
                [
                    tool_runner.ToolResult(
                        tool="nuclei",
                        command=[
                            "/usr/local/bin/nuclei",
                            "-u",
                            "https://example.com",
                            "-proxy",
                            "http://user:secret-proxy@example.net:8080",
                            "-interactsh-token",
                            "secret-interactsh-token",
                            "-var",
                            "api_key=secret-variable",
                            "-markdown-export",
                            str(output_dir / "markdown"),
                            "-sarif-export",
                            str(output_dir / "nuclei.sarif"),
                            "-store-resp-dir",
                            str(output_dir / "responses"),
                        ],
                        success=True,
                    )
                ],
            )
            text = report.read_text(encoding="utf-8")
        finally:
            report.unlink(missing_ok=True)
            try:
                output_dir.rmdir()
            except OSError:
                pass

        self.assertIn("-proxy [redacted]", text)
        self.assertIn("-interactsh-token [redacted]", text)
        self.assertIn("-var [redacted]", text)
        self.assertIn("-markdown-export markdown", text)
        self.assertIn("-sarif-export nuclei.sarif", text)
        self.assertIn("-store-resp-dir responses", text)
        self.assertNotIn("secret-proxy", text)
        self.assertNotIn("secret-interactsh-token", text)
        self.assertNotIn("secret-variable", text)
        self.assertNotIn(str(output_dir), text)

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
            output_dir / tool_runner.REPORT_FILENAME,
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

    def test_run_chain_dry_run_uses_direct_nuclei_target(self):
        calls = []

        def fake_run_command(tool, command, timeout=None, output_file=None, dry_run=False, on_line=None):
            calls.append((tool, list(command), dry_run))
            return tool_runner.ToolResult(
                tool=tool,
                command=list(command),
                success=True,
                returncode=0,
                dry_run=dry_run,
                output_file=Path(output_file) if output_file else None,
            )

        output_dir = Path("tests") / "_dry_chain_output"
        try:
            with patch.object(tool_runner, "get_executable_path", lambda tool: tool):
                with patch.object(tool_runner, "run_command", fake_run_command):
                    results = tool_runner.run_chain("example.com", output_dir=output_dir, dry_run=True)
        finally:
            try:
                output_dir.rmdir()
            except OSError:
                pass

        nuclei_call = next(command for tool, command, _dry_run in calls if tool == "nuclei")

        self.assertIn("-u", nuclei_call)
        self.assertIn("http://example.com", nuclei_call)
        self.assertNotIn("-l", nuclei_call)
        self.assertTrue(all(dry_run for _tool, _command, dry_run in calls))
        self.assertEqual([result.tool for result in results], ["naabu", "httpx", "nuclei"])

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
