import unittest

from src import tool_runner


class TargetValidationHardeningTests(unittest.TestCase):
    def test_rejects_url_credentials(self):
        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_target("https://admin:secret@example.com/")

    def test_rejects_invalid_url_port(self):
        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_target("https://example.com:99999/")

    def test_rejects_invalid_host_port(self):
        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_target("example.com:99999")

    def test_rejects_invalid_ipv4_cidr(self):
        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_target("999.999.999.999/24")

    def test_rejects_empty_hostname_label(self):
        with self.assertRaises(tool_runner.ScanInputError):
            tool_runner.validate_target("example..com")

    def test_accepts_supported_targets(self):
        accepted = (
            "example.com",
            "example.com:443",
            "192.0.2.10",
            "192.0.2.0/24",
            "2001:db8::10",
            "[2001:db8::10]:443",
            "https://example.com:8443/path?q=1",
        )
        for target in accepted:
            with self.subTest(target=target):
                self.assertEqual(tool_runner.validate_target(target), target)


class NucleiProfileHardeningTests(unittest.TestCase):
    def test_default_profile_signature_does_not_apply_restrictive_tags(self):
        command = tool_runner.build_nuclei_command(
            target="https://example.com",
            tags="exposure,misconfig",
            severity="critical,high,medium",
            rate_limit=75,
            concurrency=10,
            tool_path="nuclei",
        )
        self.assertNotIn("-tags", command)

    def test_fast_profile_signature_does_not_apply_restrictive_tags(self):
        command = tool_runner.build_nuclei_command(
            target="https://example.com",
            tags="exposure,misconfig,panel",
            severity="critical,high",
            rate_limit=100,
            concurrency=8,
            tool_path="nuclei",
        )
        self.assertNotIn("-tags", command)

    def test_stealth_profile_signature_does_not_apply_restrictive_tags(self):
        command = tool_runner.build_nuclei_command(
            target="https://example.com",
            tags="exposure,misconfig",
            severity="critical,high,medium",
            rate_limit=5,
            concurrency=5,
            tool_path="nuclei",
        )
        self.assertNotIn("-tags", command)

    def test_explicit_custom_tags_are_preserved(self):
        command = tool_runner.build_nuclei_command(
            target="https://example.com",
            tags="cve,rce",
            severity="critical,high",
            rate_limit=75,
            concurrency=10,
            tool_path="nuclei",
        )
        self.assertIn("-tags", command)
        self.assertEqual(command[command.index("-tags") + 1], "cve,rce")


class RedactionHardeningTests(unittest.TestCase):
    def test_command_preview_redacts_url_userinfo_defensively(self):
        command = ["httpx", "-u", "https://admin:secret@example.com/"]
        redacted = tool_runner.redact_command(command)
        preview = " ".join(redacted)
        self.assertNotIn("admin:secret", preview)
        self.assertIn("[redacted]@example.com", preview)


if __name__ == "__main__":
    unittest.main()
