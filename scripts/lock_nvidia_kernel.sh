#!/usr/bin/env bash
# Pin boot to 7.0.0-28-generic (NVIDIA working) and remove old 6.17 kernels.
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/lock_nvidia_kernel.sh" >&2
  exit 1
fi

RUNNING="$(uname -r)"
TARGET="7.0.0-28-generic"

if [[ "${RUNNING}" != "${TARGET}" ]]; then
  echo "Boot ${TARGET} first (currently on ${RUNNING}), then rerun this script." >&2
  exit 1
fi

if ! nvidia-smi >/dev/null 2>&1; then
  echo "nvidia-smi failed — fix GPU before locking the kernel." >&2
  exit 1
fi

echo "[lock-kernel] pinning GRUB to ${TARGET}..."
cp /etc/default/grub "/etc/default/grub.bak.$(date +%Y%m%d%H%M%S)"
cat > /etc/default/grub <<'EOF'
# If you change this file, run 'update-grub' afterwards.
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=0
GRUB_DISTRIBUTOR=`( . /etc/os-release; echo ${NAME:-Ubuntu} ) 2>/dev/null || echo Ubuntu`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
EOF

echo "[lock-kernel] removing 6.17.0-35 and 6.17.0-40 kernels..."
DEBIAN_FRONTEND=noninteractive apt-get purge -y \
  'linux-image-6.17.0-35-generic' \
  'linux-headers-6.17.0-35-generic' \
  'linux-modules-6.17.0-35-generic' \
  'linux-modules-extra-6.17.0-35-generic' \
  'linux-tools-6.17.0-35-generic' \
  'linux-hwe-6.17-headers-6.17.0-35' \
  'linux-hwe-6.17-tools-6.17.0-35' \
  'linux-image-6.17.0-40-generic' \
  'linux-modules-6.17.0-40-generic' \
  'linux-modules-nvidia-595-open-6.17.0-40-generic' \
  'linux-modules-nvidia-595-open-6.17.0-35-generic' \
  2>/dev/null || true

DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y
update-grub

echo ""
echo "[lock-kernel] done."
echo "  Running kernel:  $(uname -r)"
echo "  GRUB default:    entry 0 (Ubuntu HWE → ${TARGET})"
echo "  Remaining images:"
dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/ && /generic/ {print "    " $2}'
echo ""
echo "Optional: keep prime on nvidia for Ollama —  sudo prime-select query"
