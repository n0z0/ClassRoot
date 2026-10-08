#!/usr/bin/env bash
#
# ClassRoot WebRTC Decoy Installer / Upgrader for Linux
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/n0z0/ClassRoot/main/install.sh | bash
#   atau
#   ./install.sh [version]
#
set -euo pipefail

REPO="n0z0/ClassRoot"
VERSION="${1:-latest}"
INSTALL_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/classroot"

USE_SUDO=false
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    USE_SUDO=true
  else
    INSTALL_DIR="${HOME}/.local/bin"
    SHARE_DIR="${HOME}/.local/share/classroot"
  fi
fi

echo "=========================================="
echo " ClassRoot WebRTC Decoy Installer (Linux) "
echo "=========================================="

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  *)
    echo "[!] Arsitektur ${ARCH} belum didukung binary pre-built."
    exit 1
    ;;
esac

if [ "${VERSION}" = "latest" ]; then
  echo "[*] Memeriksa rilis terbaru dari GitHub..."
  TARGET_TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  if [ -z "${TARGET_TAG}" ]; then
    echo "[!] Gagal mendapatkan tag rilis terbaru dari GitHub."
    exit 1
  fi
else
  case "${VERSION}" in
    v*) TARGET_TAG="${VERSION}" ;;
    *)  TARGET_TAG="v${VERSION}" ;;
  esac
fi

echo "[*] Target versi: ${TARGET_TAG} (linux/${TARGET_ARCH})"

# Cek versi terpasang
EXISTING_BIN="$(command -v classroot 2>/dev/null || true)"
if [ -n "${EXISTING_BIN}" ]; then
  CURRENT_VER="$(${EXISTING_BIN} -version 2>/dev/null || echo "unknown")"
  echo "[*] Versi terpasang saat ini: ${CURRENT_VER}"
  if [[ "${CURRENT_VER}" == *"${TARGET_TAG}"* ]]; then
    echo "[OK] ClassRoot sudah versi terbaru (${TARGET_TAG})."
    exit 0
  fi
fi

# Buat direktori instalasi
if [ "${USE_SUDO}" = true ]; then
  sudo mkdir -p "${INSTALL_DIR}" "${SHARE_DIR}"
else
  mkdir -p "${INSTALL_DIR}" "${SHARE_DIR}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

TAR_URL="https://github.com/${REPO}/releases/download/${TARGET_TAG}/classroot_${TARGET_TAG}_linux_${TARGET_ARCH}.tar.gz"

echo "[*] Mengunduh arsip paket dari ${TAR_URL}..."
if curl -fsSL "${TAR_URL}" -o "${TMP_DIR}/pkg.tar.gz" 2>/dev/null; then
  tar -xzf "${TMP_DIR}/pkg.tar.gz" -C "${TMP_DIR}"
  PKG_DIR="$(find "${TMP_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  
  if [ "${USE_SUDO}" = true ]; then
    sudo cp "${PKG_DIR}/classroot" "${INSTALL_DIR}/classroot"
    sudo chmod +x "${INSTALL_DIR}/classroot"
    if [ -f "${PKG_DIR}/classrootctl" ]; then
      sudo cp "${PKG_DIR}/classrootctl" "${INSTALL_DIR}/classrootctl"
      sudo chmod +x "${INSTALL_DIR}/classrootctl"
    fi
    if [ -d "${PKG_DIR}/static" ]; then
      sudo cp -r "${PKG_DIR}/static" "${SHARE_DIR}/"
    fi
  else
    cp "${PKG_DIR}/classroot" "${INSTALL_DIR}/classroot"
    chmod +x "${INSTALL_DIR}/classroot"
    if [ -f "${PKG_DIR}/classrootctl" ]; then
      cp "${PKG_DIR}/classrootctl" "${INSTALL_DIR}/classrootctl"
      chmod +x "${INSTALL_DIR}/classrootctl"
    fi
    if [ -d "${PKG_DIR}/static" ]; then
      cp -r "${PKG_DIR}/static" "${SHARE_DIR}/"
    fi
  fi
else
  echo "[*] Arsip tidak ditemukan, mengunduh binary langsung..."
  DIRECT_URL="https://github.com/${REPO}/releases/download/${TARGET_TAG}/classroot_linux_${TARGET_ARCH}"
  if [ "${USE_SUDO}" = true ]; then
    sudo curl -fsSL "${DIRECT_URL}" -o "${INSTALL_DIR}/classroot"
    sudo chmod +x "${INSTALL_DIR}/classroot"
  else
    curl -fsSL "${DIRECT_URL}" -o "${INSTALL_DIR}/classroot"
    chmod +x "${INSTALL_DIR}/classroot"
  fi
fi

# Cek PATH
if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
  echo "[!] Peringatan: ${INSTALL_DIR} belum ada di PATH Anda."
  echo "    Tambahkan baris ini ke ~/.bashrc atau ~/.zshrc:"
  echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo "=========================================="
echo " Sukses! ClassRoot WebRTC Decoy terpasang."
echo " Versi : ${TARGET_TAG}"
echo " Lokasi: ${INSTALL_DIR}/classroot"
echo "=========================================="
echo "Jalankan dengan perintah (HTTPS bawaan dengan auto-cert):"
echo "   classroot -http :8443 -ctilog classroot_cti.jsonl"
