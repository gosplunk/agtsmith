"""Regression tests for the documented fresh-deployment auth contract."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DeploymentAuthContractTests(unittest.TestCase):
    def test_deploy_compose_does_not_enable_seed_auth(self) -> None:
        compose = (ROOT / "docker-compose.deploy.yml").read_text(encoding="utf-8")
        self.assertNotIn("AGTSMITH_DEV_SEED_AUTH: \"1\"", compose)

    def test_deploy_compose_keeps_config_private_to_named_volume(self) -> None:
        compose = (ROOT / "docker-compose.deploy.yml").read_text(encoding="utf-8")
        self.assertIn("agtsmith_deploy_config:/app/config", compose)
        self.assertIn("agtsmith_deploy_config:", compose)
        self.assertNotIn("./config/ui.env:/app/config/ui.env", compose)

    def test_example_config_leaves_ui_credentials_for_first_run(self) -> None:
        example = (ROOT / "config" / "ui.env.example").read_text(encoding="utf-8")
        self.assertIn("SOC_UI_AUTH_INITIALIZED=0", example)
        self.assertNotRegex(example, r"(?m)^SOC_UI_AUTH_(USERNAME|PASSWORD)=")
        self.assertNotIn("change" + "me", example.lower())

    def test_make_deploy_uses_ui_first_run_and_named_volume_lifecycle(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        deploy_target = makefile.split("\ndocker-deploy-up:\n", 1)[1].split(
            "\ndocker-deploy-hotpatch:\n", 1
        )[0]
        self.assertIn("/setup/first-run", deploy_target)
        self.assertIn("private named config volume", deploy_target)
        self.assertIn("restart persistence", deploy_target)
        self.assertIn("reset auth", deploy_target)
        self.assertNotIn("config/ui.env", deploy_target)
        self.assertNotIn("bind-mounted", deploy_target)
        self.assertNotIn("admin / " + "change" + "me", makefile)
        self.assertNotIn("docker-deploy-reset-auth", makefile)

    def test_local_ui_env_workflow_remains_explicit(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        helper = (ROOT / "scripts" / "setup_local_ui_env.sh").read_text(encoding="utf-8")
        self.assertIn("setup-local-ui-env", makefile)
        self.assertIn("bash ./scripts/setup_local_ui_env.sh", makefile)
        self.assertIn("config/ui.env", helper)

    def test_explicit_seed_path_requires_runtime_password(self) -> None:
        helper = (ROOT / "scripts" / "ui_auth_docker.py").read_text(encoding="utf-8")
        self.assertIn("AGTSMITH_DEV_SEED_PASSWORD", helper)
        self.assertNotIn("DEFAULT_DEV_" + "PASSWORD", helper)
        self.assertNotIn("DEFAULT_E2E_" + "PASSWORD", helper)

    def test_first_run_route_and_gate_remain_available(self) -> None:
        server = (ROOT / "scripts" / "web_ui_server.py").read_text(encoding="utf-8")
        self.assertIn("def _first_run_setup_required", server)
        self.assertIn('"/setup/first-run"', server)


if __name__ == "__main__":
    unittest.main()
