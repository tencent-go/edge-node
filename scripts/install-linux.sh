#!/usr/bin/env bash

set -euo pipefail

REPO="${GITHUB_REPO:-tencent-go/edge-node}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_PATH="${INSTALL_DIR}/edgenode"
CONFIG_DIR="${CONFIG_DIR:-/etc/edgenode}"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
DATA_DIR="${DATA_DIR:-/var/lib/edgenode}"
SERVICE_PATH="/etc/systemd/system/edgenode.service"

usage() {
  cat <<'EOF'
Edge Node 安裝腳本

環境變量：
  GITHUB_REPO   來源 GitHub 倉庫（預設：tencent-go/edge-node）
  INSTALL_DIR   可執行檔目錄（預設：/usr/local/bin）
  CONFIG_DIR    配置目錄（預設：/etc/edgenode）
  DATA_DIR      工作資料目錄（預設：/var/lib/edgenode）

使用方式：
  sudo bash install-linux.sh
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "缺少必要命令：$1" >&2
    exit 1
  fi
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "請使用 root 或 sudo 執行此腳本" >&2
  exit 1
fi

require_command curl
require_command sha256sum
require_command systemctl

API_URL="https://api.github.com/repos/${REPO}/releases/latest"
RELEASE_JSON=$(curl -fsSL "${API_URL}")

if [[ -z ${RELEASE_JSON} ]]; then
  echo "無法取得最新 release 資訊" >&2
  exit 1
fi

TAG=$(echo "${RELEASE_JSON}" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')

if [[ -z ${TAG} ]]; then
  echo "無法解析 release tag" >&2
  exit 1
fi

ASSET_NAME="edgenode"
CHECKSUM_NAME="edgenode_${TAG}_SHA256SUMS"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download/${TAG}"

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

echo "下載 ${ASSET_NAME}..."
curl -fSL "${DOWNLOAD_BASE}/${ASSET_NAME}" -o "${WORKDIR}/${ASSET_NAME}"

echo "下載校驗檔 ${CHECKSUM_NAME}..."
curl -fSL "${DOWNLOAD_BASE}/${CHECKSUM_NAME}" -o "${WORKDIR}/${CHECKSUM_NAME}"

echo "驗證檔案 SHA256..."
(cd "${WORKDIR}" && sha256sum -c "${CHECKSUM_NAME}")

if [[ ! -f ${WORKDIR}/edgenode ]]; then
  echo "未找到下載的 edgenode 可執行檔" >&2
  exit 1
fi

install -d "${INSTALL_DIR}"

if [[ -f ${BINARY_PATH} ]]; then
  BACKUP_PATH="${BINARY_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  echo "備份既有二進制至 ${BACKUP_PATH}"
  mv "${BINARY_PATH}" "${BACKUP_PATH}"
fi

install -m 0755 "${WORKDIR}/edgenode" "${BINARY_PATH}"

install -d "${CONFIG_DIR}"
install -d "${DATA_DIR}"

if [[ ! -f ${CONFIG_FILE} ]]; then
  echo "生成預設配置 ${CONFIG_FILE}"
  (cd "${DATA_DIR}" && "${BINARY_PATH}" config > "${CONFIG_FILE}")
else
  echo "保留現有配置 ${CONFIG_FILE}"
fi

echo "安裝 systemd 服務描述至 ${SERVICE_PATH}"
cat <<EOF > "${SERVICE_PATH}"
[Unit]
Description=Edge Node Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BINARY_PATH} start --config ${CONFIG_FILE}
WorkingDirectory=${DATA_DIR}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "${SERVICE_PATH}"
systemctl daemon-reload

cat <<EOF

安裝完成。
下一步請執行：
  1. 編輯 ${CONFIG_FILE}
  2. systemctl enable edgenode
  3. systemctl start edgenode

如需查看狀態：
  systemctl status edgenode
EOF

