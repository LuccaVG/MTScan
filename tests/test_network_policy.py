import argparse
import unittest
from unittest import mock

from src import workflow


class NetworkPolicyRegressionTests(unittest.TestCase):
    def test_non_public_target_classification(self):
        targets = (
            "127.0.0.1",
            "http://127.0.0.1:8080/",
            "10.10.20.30",
            "192.168.50.0/24",
            "[fd00::10]:443",
            "fd00::/8",
            "localhost",
        )
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue(workflow.target_is_non_public(target))

    def test_public_targets_are_not_classified_as_private(self):
        targets = ("example.com", "8.8.8.8", "https://example.com/")
        for target in targets:
            with self.subTest(target=target):
                self.assertFalse(workflow.target_is_non_public(target))

    def test_private_target_skips_public_connectivity_probe(self):
        args = argparse.Namespace(
            dry_run=False,
            skip_network_check=False,
            update_templates=False,
            target="127.0.0.1",
            host=None,
        )
        with mock.patch.object(workflow.tool_runner, "check_network_connectivity") as probe, mock.patch(
            "builtins.input"
        ) as prompt:
            workflow.check_network(args)
        probe.assert_not_called()
        prompt.assert_not_called()

    def test_template_update_keeps_connectivity_probe_for_private_target(self):
        args = argparse.Namespace(
            dry_run=False,
            skip_network_check=False,
            update_templates=True,
            target="10.0.0.15",
            host=None,
        )
        with mock.patch.object(
            workflow.tool_runner, "check_network_connectivity", return_value=True
        ) as probe:
            workflow.check_network(args)
        probe.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
