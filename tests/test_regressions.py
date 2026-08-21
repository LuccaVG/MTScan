import tempfile
import unittest
from pathlib import Path

from src.tool_runner import (
    ScanInputError,
    ToolResult,
    build_naabu_command,
    build_nuclei_command,
    cleanup_intermediate_outputs,
    redact_command,
    run_chain,
    validate_scan_request,
    write_summary,
)


class UrlTargetRegressionTests(unittest.TestCase):
    def test_naabu_receives_hostname_from_url_target(self):
        command = build_naabu_command(
            target="https://example.com:8443/path?q=1",
            tool_path="naabu",
        )

        host_index = command.index("-host") + 1
        self.assertEqual(command[host_index], "example.com")

    def test_chain_keeps_original_url_for_http_stages(self):
        target = "https://example.com:8443/path?q=1"
        with tempfile.TemporaryDirectory() as tmp_dir:
            results = run_chain(
                target,
                output_dir=Path(tmp_dir) / "results",
                save_output=False,
                dry_run=True,
                on_line=lambda _line: None,
            )

        commands = {result.tool: result.command for result in results}
        naabu = commands["naabu"]
        httpx = commands["httpx"]
        nuclei = commands["nuclei"]

        self.assertEqual(naabu[naabu.index("-host") + 1], "example.com")
        self.assertEqual(httpx[httpx.index("-u") + 1], target)
        self.assertEqual(nuclei[nuclei.index("-u") + 1], target)


class TargetValidationRegressionTests(unittest.TestCase):
    def test_rejects_credential_bearing_url(self):
        with self.assertRaises(ScanInputError):
            validate_scan_request("https://admin:secret@example.com/")

    def test_rejects_invalid_url_port(self):
        with self.assertRaises(ScanInputError):
            validate_scan_request("https://example.com:99999/")

    def test_rejects_invalid_host_port(self):
        with self.assertRaises(ScanInputError):
            validate_scan_request("example.com:99999")

    def test_rejects_invalid_cidr_address(self):
        with self.assertRaises(ScanInputError):
            validate_scan_request("999.999.999.999/24")

    def test_rejects_malformed_hostname(self):
        with self.assertRaises(ScanInputError):
            validate_scan_request("example..com")

    def test_accepts_supported_targets(self):
        targets = (
            "example.com",
            "example.com:443",
            "192.0.2.10",
            "192.0.2.0/24",
            "2001:db8::10",
            "[2001:db8::10]:443",
            "https://example.com:8443/path?q=1",
        )
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(validate_scan_request(target), target)

    def test_command_preview_redacts_url_userinfo_defensively(self):
        preview = " ".join(
            redact_command(["httpx", "-u", "https://admin:secret@example.com/"])
        )
        self.assertNotIn("admin:secret", preview)
        self.assertIn("[redacted]@example.com", preview)


class NucleiProfileRegressionTests(unittest.TestCase):
    def test_default_profile_signature_does_not_apply_positive_tag_filter(self):
        command = build_nuclei_command(
            target="https://example.com",
            tags="exposure,misconfig",
            severity="critical,high,medium",
            rate_limit=75,
            concurrency=10,
            tool_path="nuclei",
        )
        self.assertNotIn("-tags", command)

    def test_fast_profile_signature_does_not_apply_positive_tag_filter(self):
        command = build_nuclei_command(
            target="https://example.com",
            tags="exposure,misconfig,panel",
            severity="critical,high",
            rate_limit=100,
            concurrency=8,
            tool_path="nuclei",
        )
        self.assertNotIn("-tags", command)

    def test_stealth_profile_signature_does_not_apply_positive_tag_filter(self):
        command = build_nuclei_command(
            target="https://example.com",
            tags="exposure,misconfig",
            severity="critical,high,medium",
            rate_limit=5,
            concurrency=5,
            tool_path="nuclei",
        )
        self.assertNotIn("-tags", command)

    def test_explicit_custom_tags_are_preserved(self):
        command = build_nuclei_command(
            target="https://example.com",
            tags="cve,rce",
            severity="critical,high",
            rate_limit=75,
            concurrency=10,
            tool_path="nuclei",
        )
        self.assertIn("-tags", command)
        self.assertEqual(command[command.index("-tags") + 1], "cve,rce")


class RawEvidenceRegressionTests(unittest.TestCase):
    def test_cleanup_keeps_raw_scanner_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            raw_files = [
                output_dir / "naabu_results.txt",
                output_dir / "httpx_results.json",
                output_dir / "nuclei_results.jsonl",
            ]
            handoff_files = [
                output_dir / "httpx_targets.txt",
                output_dir / "nuclei_targets.txt",
            ]

            for path in raw_files + handoff_files:
                path.write_text("test\n", encoding="utf-8")

            cleanup_intermediate_outputs(output_dir)

            self.assertTrue(all(path.exists() for path in raw_files))
            self.assertTrue(all(not path.exists() for path in handoff_files))

    def test_write_summary_preserves_output_file_references(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            naabu_file = output_dir / "naabu_results.txt"
            httpx_file = output_dir / "httpx_results.txt"
            nuclei_file = output_dir / "nuclei_results.txt"

            naabu_file.write_text("example.com:443\n", encoding="utf-8")
            httpx_file.write_text("https://example.com\n", encoding="utf-8")
            nuclei_file.write_text("", encoding="utf-8")

            results = [
                ToolResult("naabu", [], True, output_file=naabu_file),
                ToolResult("httpx", [], True, output_file=httpx_file),
                ToolResult("nuclei", [], True, output_file=nuclei_file),
            ]

            report = write_summary(output_dir, "https://example.com", results)

            self.assertTrue(report.exists())
            self.assertTrue(naabu_file.exists())
            self.assertTrue(httpx_file.exists())
            self.assertTrue(nuclei_file.exists())
            self.assertEqual(results[0].output_file, naabu_file)
            self.assertEqual(results[1].output_file, httpx_file)
            self.assertEqual(results[2].output_file, nuclei_file)


if __name__ == "__main__":
    unittest.main()
