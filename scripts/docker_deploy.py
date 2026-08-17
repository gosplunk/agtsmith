#!/usr/bin/env python3
"""Build and run the revision-pinned Docker deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = ROOT / "docker-compose.deploy.yml"
NVIDIA_COMPOSE = ROOT / "docker-compose.deploy.nvidia.yml"
CONTAINER_NAME = "agtsmith-ui-deploy"
REVISION_LABEL = "org.opencontainers.image.revision"
BUILD_ID_LABEL = "io.agtsmith.build-id"


@dataclass(frozen=True)
class SourceIdentity:
    revision: str
    build_id: str

    @property
    def image(self) -> str:
        return f"agtsmith-ui-deploy:{self.build_id}"

    def environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "AGTSMITH_SOURCE_REVISION": self.revision,
                "AGTSMITH_BUILD_ID": self.build_id,
                "AGTSMITH_DEPLOY_IMAGE": self.image,
            }
        )
        return env


def _git_output(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def source_identity() -> SourceIdentity:
    revision = _git_output("rev-parse", "HEAD").decode("ascii").strip()
    tracked_diff = _git_output("diff", "--binary", "HEAD", "--", ".")
    untracked_raw = _git_output("ls-files", "--others", "--exclude-standard", "-z")
    untracked = sorted(item for item in untracked_raw.split(b"\0") if item)
    if not tracked_diff and not untracked:
        return SourceIdentity(revision=revision, build_id=revision)

    digest = hashlib.sha256()
    digest.update(b"tracked-diff\0")
    digest.update(tracked_diff)
    for raw_path in untracked:
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("git returned an unsafe untracked path")
        path = ROOT / relative
        digest.update(b"\0untracked\0")
        digest.update(raw_path)
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.fsencode(os.readlink(path)))
        else:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return SourceIdentity(
        revision=revision,
        build_id=f"{revision}-dirty-{digest.hexdigest()[:12]}",
    )


def compose_command(*args: str, nvidia: bool = False) -> list[str]:
    command = ["docker", "compose", "-f", str(BASE_COMPOSE)]
    if nvidia:
        command.extend(["-f", str(NVIDIA_COMPOSE)])
    command.extend(args)
    return command


def _inspect(kind: str, name: str) -> dict[str, Any]:
    output = subprocess.check_output(
        ["docker", kind, "inspect", name],
        cwd=ROOT,
        text=True,
    )
    return json.loads(output)[0]


def verify_image(identity: SourceIdentity) -> str:
    image = _inspect("image", identity.image)
    labels = image.get("Config", {}).get("Labels") or {}
    if labels.get(REVISION_LABEL) != identity.revision:
        raise RuntimeError(
            f"image revision mismatch: expected {identity.revision}, "
            f"got {labels.get(REVISION_LABEL, 'missing')}"
        )
    if labels.get(BUILD_ID_LABEL) != identity.build_id:
        raise RuntimeError(
            f"image build identity mismatch: expected {identity.build_id}, "
            f"got {labels.get(BUILD_ID_LABEL, 'missing')}"
        )
    return str(image["Id"])


def verify_running(identity: SourceIdentity, expected_image_id: str) -> None:
    last_error = "container did not appear"
    for _ in range(15):
        try:
            container = _inspect("container", CONTAINER_NAME)
        except subprocess.CalledProcessError:
            time.sleep(1)
            continue
        labels = container.get("Config", {}).get("Labels") or {}
        state = container.get("State", {})
        checks = {
            "running state": state.get("Running") is True,
            "image id": container.get("Image") == expected_image_id,
            "revision label": labels.get(REVISION_LABEL) == identity.revision,
            "build identity label": labels.get(BUILD_ID_LABEL) == identity.build_id,
        }
        failed = [name for name, ok in checks.items() if not ok]
        if not failed:
            print(
                "[docker-deploy] verified "
                f"container={str(container['Id'])[:12]} "
                f"image={expected_image_id[:19]} "
                f"build_id={identity.build_id}"
            )
            return
        last_error = ", ".join(failed)
        time.sleep(1)
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER_NAME],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    raise RuntimeError(f"running deployment verification failed: {last_error}")


def build(identity: SourceIdentity, *, nvidia: bool = False) -> str:
    print(
        "[docker-deploy] building current source "
        f"revision={identity.revision} build_id={identity.build_id}"
    )
    subprocess.run(
        compose_command("build", nvidia=nvidia),
        cwd=ROOT,
        env=identity.environment(),
        check=True,
    )
    if source_identity() != identity:
        raise RuntimeError("source changed during image build; rerun deployment")
    image_id = verify_image(identity)
    print(f"[docker-deploy] verified image={image_id[:19]}")
    return image_id


def _remove_unmanaged_container() -> None:
    try:
        container = _inspect("container", CONTAINER_NAME)
    except subprocess.CalledProcessError:
        return
    labels = container.get("Config", {}).get("Labels") or {}
    is_compose_service = (
        labels.get("com.docker.compose.service") == CONTAINER_NAME
        and labels.get("com.docker.compose.project") == "agtsmith"
    )
    if is_compose_service:
        return
    print(
        "[docker-deploy] replacing unmanaged UI container; "
        "named volumes are preserved"
    )
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER_NAME],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def deploy(identity: SourceIdentity, *, nvidia: bool = False) -> None:
    image_id = build(identity, nvidia=nvidia)
    _remove_unmanaged_container()
    subprocess.run(
        compose_command("up", "-d", "--no-build", nvidia=nvidia),
        cwd=ROOT,
        env=identity.environment(),
        check=True,
    )
    verify_running(identity, image_id)


def run_compose_action(
    identity: SourceIdentity,
    action: str,
    *,
    nvidia: bool = False,
) -> None:
    extra = ("--tail=200", "-f") if action == "logs" else ()
    subprocess.run(
        compose_command(action, *extra, nvidia=nvidia),
        cwd=ROOT,
        env=identity.environment(),
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "up", "down", "logs", "config"))
    parser.add_argument(
        "--nvidia",
        action="store_true",
        help="add the explicit NVIDIA host-device overlay",
    )
    args = parser.parse_args()
    identity = source_identity()
    try:
        if args.action == "build":
            build(identity, nvidia=args.nvidia)
        elif args.action == "up":
            deploy(identity, nvidia=args.nvidia)
        elif args.action == "config":
            run_compose_action(identity, "config", nvidia=args.nvidia)
        else:
            run_compose_action(identity, args.action, nvidia=args.nvidia)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[docker-deploy] failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
