import ast
import unittest
from pathlib import Path


class AuthSecurityTests(unittest.TestCase):
    def test_default_password_is_not_a_hardcoded_string(self):
        source = Path("src/app_server.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if "DEFAULT_PASSWORD" in names:
                self.assertFalse(isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
                return
        self.fail("DEFAULT_PASSWORD assignment not found")


if __name__ == "__main__":
    unittest.main()
