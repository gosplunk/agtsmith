#!/usr/bin/env python3
"""Static and API tests for the Configuration Setup Lanes page."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_ROOT))

_layout_spec = importlib.util.spec_from_file_location(
    "test_web_ui_layout",
    SCRIPTS_ROOT / "tests" / "test_web_ui_layout.py",
)
_layout_mod = importlib.util.module_from_spec(_layout_spec)
assert _layout_spec.loader is not None
_layout_spec.loader.exec_module(_layout_mod)
_layout_mod._install_stub_modules()

import web_ui_server as wus  # noqa: E402


class ConfigurePageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = wus._configure_page_body_rendered()

    def test_lane_nav_and_sticky_footer_markers(self) -> None:
        for marker in (
            'id="cfg-lane-nav"',
            'id="cfg-lane-health"',
            'id="cfg-sticky-footer"',
            'id="cfg-ui-tag"',
            'id="cfg-next-action"',
            'id="cfg-core-only-mode"',
            'id="connect"',
            'id="models"',
            'id="validate"',
            'id="ground"',
            'id="cfg-validation-status"',
            'id="cfg-ground-status"',
            'class="cfg-validate-shell"',
            'class="cfg-ground-shell"',
        ):
            self.assertIn(marker, self.html, msg=f"missing {marker}")

    def test_family_select_not_pick_walls_in_default_lane(self) -> None:
        family_grid_start = self.html.find('id="cfg-family-grid"')
        advanced_start = self.html.find('id="cfg-model-advanced"')
        self.assertGreater(family_grid_start, 0)
        self.assertGreater(advanced_start, family_grid_start)
        family_area = self.html[family_grid_start:advanced_start]
        self.assertNotIn("cfg-model-picks", family_area)
        script = self.html[self.html.index("<script>") :]
        self.assertIn("cfg-family-select", script)

    def test_configure_script_brace_balance(self) -> None:
        start = self.html.index("<script>")
        end = self.html.index("</script>", start)
        script = self.html[start + len("<script>") : end]
        self.assertEqual(script.count("{"), script.count("}"))

    def test_config_snapshot_includes_configure_ui_tag(self) -> None:
        snapshot = wus._config_snapshot()
        self.assertIn("configure_ui_tag", snapshot)
        self.assertTrue(str(snapshot["configure_ui_tag"]).startswith("configure-ui"))


class ConfigureApiSnapshotTests(unittest.TestCase):
    def test_snapshot_model_stack_keys(self) -> None:
        snapshot = wus._config_snapshot()
        self.assertIn("model_stack", snapshot)
        self.assertIn("expected_models", snapshot)
        self.assertIsInstance(snapshot["expected_models"], list)


if __name__ == "__main__":
    unittest.main()
