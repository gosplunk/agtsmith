"""Regression tests for host-compatible, revision-pinned Docker deployment."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import docker_deploy


ROOT = Path(__file__).resolve().parents[2]


class DockerDeployContractTests(unittest.TestCase):
    def test_base_compose_is_host_compatible_and_gpu_is_opt_in(self) -> None:
        base = (ROOT / "docker-compose.deploy.yml").read_text(encoding="utf-8")
        nvidia = (ROOT / "docker-compose.deploy.nvidia.yml").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("/dev/nvidia", base)
        self.assertNotIn("/usr/bin/nvidia-smi", base)
        self.assertIn("/dev/nvidiactl", nvidia)
        self.assertIn("/usr/bin/nvidia-smi", nvidia)

    def test_compose_preserves_private_volumes_and_requires_build_identity(self) -> None:
        compose = (ROOT / "docker-compose.deploy.yml").read_text(encoding="utf-8")

        self.assertIn("agtsmith_deploy_config:/app/config", compose)
        self.assertIn("agtsmith_deploy_artifacts:/app/artifacts", compose)
        self.assertIn("AGTSMITH_DEPLOY_IMAGE:?", compose)
        self.assertIn("AGTSMITH_SOURCE_REVISION:?", compose)
        self.assertIn("AGTSMITH_BUILD_ID:?", compose)
        self.assertIn("pull_policy: never", compose)
        self.assertNotIn("agtsmith-ui-deploy:local", compose)

    def test_deployment_image_carries_revision_and_build_identity(self) -> None:
        dockerfile = (ROOT / "Dockerfile.deploy").read_text(encoding="utf-8")

        self.assertIn("ARG AGTSMITH_SOURCE_REVISION", dockerfile)
        self.assertIn("ARG AGTSMITH_BUILD_ID", dockerfile)
        self.assertIn("org.opencontainers.image.revision", dockerfile)
        self.assertIn("io.agtsmith.build-id", dockerfile)

    def test_image_verification_rejects_stale_revision(self) -> None:
        identity = docker_deploy.SourceIdentity(
            revision="a" * 40,
            build_id="a" * 40,
        )
        stale = {
            "Id": "sha256:stale",
            "Config": {
                "Labels": {
                    docker_deploy.REVISION_LABEL: "b" * 40,
                    docker_deploy.BUILD_ID_LABEL: identity.build_id,
                }
            },
        }

        with patch.object(docker_deploy, "_inspect", return_value=stale):
            with self.assertRaisesRegex(RuntimeError, "image revision mismatch"):
                docker_deploy.verify_image(identity)

    def test_running_mismatch_is_removed_instead_of_left_serving(self) -> None:
        identity = docker_deploy.SourceIdentity(
            revision="a" * 40,
            build_id="a" * 40,
        )
        stale = {
            "Id": "container-stale",
            "Image": "sha256:stale",
            "State": {"Running": True},
            "Config": {"Labels": {}},
        }

        with patch.object(
            docker_deploy, "_inspect", return_value=stale
        ), patch.object(
            docker_deploy.time, "sleep"
        ), patch.object(
            docker_deploy.subprocess, "run"
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "verification failed"):
                docker_deploy.verify_running(identity, "sha256:current")

        self.assertEqual(
            run.call_args.args[0],
            ["docker", "rm", "-f", docker_deploy.CONTAINER_NAME],
        )

    def test_normal_deploy_builds_before_compose_up_and_verifies(self) -> None:
        identity = docker_deploy.SourceIdentity(
            revision="a" * 40,
            build_id="a" * 40,
        )
        with patch.object(
            docker_deploy, "build", return_value="sha256:current"
        ) as build, patch.object(
            docker_deploy, "_remove_unmanaged_container"
        ) as remove_unmanaged, patch.object(
            docker_deploy.subprocess, "run"
        ) as run, patch.object(
            docker_deploy, "verify_running"
        ) as verify:
            docker_deploy.deploy(identity)

        build.assert_called_once_with(identity, nvidia=False)
        remove_unmanaged.assert_called_once_with()
        self.assertIn("--no-build", run.call_args.args[0])
        verify.assert_called_once_with(identity, "sha256:current")

    def test_no_direct_run_or_hotpatch_fallback_remains(self) -> None:
        deploy_script = (ROOT / "scripts" / "docker_deploy.py").read_text(
            encoding="utf-8"
        )
        manual_script = (ROOT / "scripts" / "docker-deploy-manual.sh").read_text(
            encoding="utf-8"
        )
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertNotIn('"docker", "run"', deploy_script)
        self.assertNotIn("docker run", manual_script)
        hotpatch = makefile.split("\ndocker-deploy-hotpatch:\n", 1)[1].split(
            "\ndocker-deploy-down:\n", 1
        )[0]
        self.assertIn("disabled", hotpatch)
        self.assertNotIn("docker cp", hotpatch)


if __name__ == "__main__":
    unittest.main()
