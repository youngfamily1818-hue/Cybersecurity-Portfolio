"""
Nmap Guardian - Basic Application Tests

Tests:
1. Verify app.py exists.
2. Verify Python syntax is valid.
3. Check whether Nmap is installed.
4. Verify expected scanning profiles are defined.

No network scans are performed.
"""

import ast
import shutil
import unittest
from pathlib import Path


APP_PATH = Path(__file__).resolve().parent / "app.py"


class TestNmapGuardian(unittest.TestCase):

    def test_application_exists(self):
        """Verify the main application exists."""
        self.assertTrue(
            APP_PATH.is_file(),
            "app.py was not found."
        )

    def test_python_syntax(self):
        """Check application syntax without executing it."""
        source = APP_PATH.read_text(encoding="utf-8")
        ast.parse(source, filename=str(APP_PATH))

    def test_nmap_installed(self):
        """Check whether Nmap is available on the system."""
        self.assertIsNotNone(
            shutil.which("nmap"),
            "Nmap is not installed or is missing from PATH."
        )

    def test_scan_profiles(self):
        """Verify the expected scanning profiles exist."""
        source = APP_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)

        profiles = None

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "PROFILES"
                    ):
                        profiles = ast.literal_eval(node.value)

        self.assertIsNotNone(
            profiles,
            "PROFILES configuration was not found."
        )

        expected = [
            "Host discovery",
            "TCP ports (top 100)",
            "Services (top 100)",
            "Safe security checks"
        ]

        for profile in expected:
            self.assertIn(profile, profiles)


if __name__ == "__main__":
    unittest.main(verbosity=2)
