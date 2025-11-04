# edge-node

## 自動發布流程

- 任何提交推送至 `main` 會觸發 GitHub Actions：
  - 自動根據 SemVer 規則以 `vX.Y.Z` 形式遞增版本（預設 Patch）。
  - 建置 `linux/amd64` 二進制，產生壓縮包與 SHA256 校驗檔。
  - 使用新版本 tag 建立 GitHub Release 並附上產物。

## Linux 節點一鍵部署

1. 下載並執行腳本（需 root）：
   ```bash
   curl -fsSL https://raw.githubusercontent.com/tencent-go/edge-node/main/scripts/install-linux.sh | sudo bash
   ```
2. 修改配置：
   ```bash
   sudo vi /etc/edgenode/config.yaml
   ```
   - 首次安裝若未存在配置檔，腳本會自動執行 `edgenode config > /etc/edgenode/config.yaml` 產生預設內容。
3. 啟用並啟動服務：
   ```bash
   sudo systemctl enable edgenode
   sudo systemctl start edgenode
   ```
4. 常用管理命令：
   ```bash
   sudo systemctl status edgenode
   sudo journalctl -u edgenode -f
   ```

## 其他需求

- 若需自訂安裝來源，可透過下列環境變量覆寫腳本行為：
  - `GITHUB_REPO`（預設 `tencent-go/edge-node`）
  - `INSTALL_DIR`（預設 `/usr/local/bin`）
  - `CONFIG_DIR`（預設 `/etc/edgenode`）
- Docker 相關部署（若仍需）可參考 [Docker 官方說明](https://docs.docker.com/engine/install/ubuntu/)。
