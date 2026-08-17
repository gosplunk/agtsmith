#!/usr/bin/env bash
# Fix NVIDIA on Ubuntu 24.04 with Secure Boot enabled.
#
# Secure Boot is NOT the problem: linux-modules-nvidia-* packages are signed by
# Canonical and load fine with SB on. The usual failure mode is booting a kernel
# that has no matching nvidia module package installed.
#
# This script:
#   1) Installs kernel 6.17.0-40 + matching nvidia-595-open modules (595.84)
#   2) Makes GRUB visible and defaults to that kernel
#   3) Removes the broken 6.17.0-35 image (optional but recommended)
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/fix_nvidia_driver.sh" >&2
  exit 1
fi

TARGET_KERNEL="6.17.0-40-generic"
TARGET_IMAGE="linux-image-${TARGET_KERNEL}"
TARGET_MODULES="linux-modules-nvidia-595-open-${TARGET_KERNEL}"

echo "[nvidia-fix] Secure Boot: $(mokutil --sb-state 2>/dev/null || echo unknown)"
echo "[nvidia-fix] current kernel: $(uname -r)"
echo "[nvidia-fix] installing ${TARGET_IMAGE} + ${TARGET_MODULES}..."

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  "${TARGET_IMAGE}" \
  "${TARGET_MODULES}" \
  nvidia-driver-595-open

# GRUB: show menu briefly and default to the kernel we just installed.
if [[ -f /etc/default/grub ]]; then
  cp /etc/default/grub "/etc/default/grub.bak.$(date +%Y%m%d%H%M%S)"
  sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' /etc/default/grub
  sed -i 's/^GRUB_TIMEOUT_STYLE=.*/GRUB_TIMEOUT_STYLE=menu/' /etc/default/grub
  sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"Advanced options for Ubuntu>Ubuntu, with Linux ${TARGET_KERNEL}\"|" /etc/default/grub
  update-grub
  echo "[nvidia-fix] GRUB updated: 5s menu, default = ${TARGET_KERNEL}"
fi

CURRENT_KERNEL="$(uname -r)"
if [[ "${CURRENT_KERNEL}" == "6.17.0-35-generic" ]]; then
  echo "[nvidia-fix] NOT removing 6.17.0-35 while it is the running kernel."
  echo "[nvidia-fix] After nvidia-smi works on ${TARGET_KERNEL}, optionally run:"
  echo "  sudo apt purge linux-image-6.17.0-35-generic linux-modules-nvidia-595-open-6.17.0-35-generic"
fi

echo ""
echo "============================================================"
echo " REBOOT NOW"
echo " At GRUB, confirm the highlighted entry is:"
echo "   Ubuntu, with Linux ${TARGET_KERNEL}"
echo " After login:  uname -r && nvidia-smi"
echo ""
echo " Secure Boot can stay ENABLED — no BIOS change needed."
echo " Only remove 6.17.0-35 AFTER you have booted ${TARGET_KERNEL}."
echo "============================================================"
