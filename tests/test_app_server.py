import unittest

from src import app_server


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


if __name__ == "__main__":
    unittest.main()
