package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bitbucket.org/tencent-international/go-pkg/errx"
	"github.com/sirupsen/logrus"
)

type Config struct {
	CertDir          string
	CertValidityDays int
	ZeroSSLApiKey    string
	ZeroSSLBaseURL   string
	PublicIps        []string
}

type Manager interface {
	Load() (*x509.Certificate, error)
	Obtain(ctx context.Context) error
}

type manager struct {
	Config
	mu sync.RWMutex
}

// NewManager 創建新的證書管理器實例
func NewManager(cfg Config) (Manager, error) {
	// 創建證書目錄
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to create certificate directory").Err()
	}
	m := &manager{
		Config: cfg,
	}
	return m, nil
}

// Load 從內存或磁盤加載證書
func (m *manager) Load() (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// 1. 加載證書
	cert, err := m.loadCertFromDisk()
	if err != nil {
		return nil, err
	}

	// 2. 校驗證書
	if err := m.validateCert(cert); err != nil {
		logrus.Errorf("Certificate validation failed: %v", err)
		return nil, nil
	}

	return cert, nil
}

// Obtain 申請新證書
func (m *manager) Obtain(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logrus.Infof("Starting ZeroSSL certificate request for IPs %v...", m.PublicIps)
	logrus.Info("ZeroSSL certificate validity: 90 days")
	return m.obtainCertificate(ctx)
}

// loadCertFromDisk 從磁盤加載證書
func (m *manager) loadCertFromDisk() (*x509.Certificate, error) {
	certPath := filepath.Join(m.CertDir, "cert.pem")
	keyPath := filepath.Join(m.CertDir, "privkey.pem")

	// 檢查文件是否存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, errx.NotFound.AppendMsg("certificate file not found").Err()
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, errx.NotFound.AppendMsg("private key file not found").Err()
	}

	// 讀取證書
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to read certificate file").Err()
	}

	// 解析證書
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, errx.Validation.AppendMsg("failed to decode certificate PEM").Err()
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to parse certificate").Err()
	}

	return cert, nil
}

// validateCert 校驗證書
func (m *manager) validateCert(cert *x509.Certificate) error {
	// 1. 驗證證書是否過期
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errx.Validation.AppendMsg("certificate not yet valid").Err()
	}
	if now.After(cert.NotAfter) {
		return errx.Validation.AppendMsg("certificate expired").Err()
	}

	// 2. 驗證配置的所有 IP 是否都在證書中
	// 收集證書中的所有 IP
	certIPs := make(map[string]bool)

	// 從 CommonName 收集
	if cert.Subject.CommonName != "" {
		certIPs[cert.Subject.CommonName] = true
	}

	// 從 IPAddresses 收集
	for _, ip := range cert.IPAddresses {
		certIPs[ip.String()] = true
	}

	// 從 DNSNames 收集（有些證書可能把 IP 放在這裡）
	for _, dns := range cert.DNSNames {
		certIPs[dns] = true
	}

	// 檢查每個配置的 IP 是否都在證書中
	for _, publicIP := range m.PublicIps {
		if !certIPs[publicIP] {
			logrus.Errorf("Certificate IP mismatch, expected IP %s not found in certificate", publicIP)
			logrus.Errorf("Certificate contains: CommonName=%s, IPAddresses=%v, DNSNames=%v",
				cert.Subject.CommonName, cert.IPAddresses, cert.DNSNames)
			return errx.Validation.AppendMsgf("certificate missing required IP: %s", publicIP).Err()
		}
		logrus.Infof("Certificate contains required IP: %s", publicIP)
	}

	logrus.Infof("All required IPs (%v) found in certificate", m.PublicIps)
	return nil
}

// obtainCertificate 申請證書的內部實現
func (m *manager) obtainCertificate(ctx context.Context) error {
	logrus.Info("Using ZeroSSL REST API to request IP certificate...")

	certPath := filepath.Join(m.CertDir, "cert.pem")
	chainPath := filepath.Join(m.CertDir, "chain.pem")
	fullchainPath := filepath.Join(m.CertDir, "fullchain.pem")

	// 1. 生成 CSR
	csr, err := m.generateCSR()
	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to generate CSR").Err()
	}
	logrus.Info("CSR generated successfully")

	// 2. 創建證書
	createReq := CreateCertificateRequest{
		CertificateDomains:      strings.Join(m.PublicIps, ","),
		CertificateCSR:          csr,
		CertificateValidityDays: m.CertValidityDays,
	}

	createResp, err := createCertificate(ctx, createReq, m.ZeroSSLApiKey, m.ZeroSSLBaseURL)
	if err != nil {
		return err
	}

	// 3. 獲取所有 IP 的驗證詳情
	logrus.Info("Getting validation details...")
	if len(m.PublicIps) == 0 {
		return errx.New("no public IPs configured")
	}

	// 驗證所有 IP 都有驗證信息
	for _, ip := range m.PublicIps {
		if _, ok := createResp.Validation.OtherMethods[ip]; !ok {
			validationJSON, _ := json.MarshalIndent(createResp.Validation, "", "  ")
			logrus.Errorf("Validation data: %s", string(validationJSON))
			return errx.Newf("IP validation info not found for: %s", ip)
		}
	}

	// 4. 啟動臨時 HTTP 服務器用於驗證（傳入所有驗證信息）
	logrus.Info("Starting validation server...")
	if err := startValidationServer(ctx, createResp.Validation.OtherMethods); err != nil {
		return errx.Wrap(err).AppendMsg("failed to start validation server").Err()
	}

	// 等待一下讓服務器啟動
	time.Sleep(2 * time.Second)

	// 6. 觸發驗證
	verifyReq := VerifyChallengeRequest{
		ValidationMethod: "HTTP_CSR_HASH",
	}

	if err = verifyChallenge(ctx, createResp.ID, m.ZeroSSLApiKey, verifyReq, m.ZeroSSLBaseURL); err != nil {
		return err
	}

	// 7. 輪詢檢查證書狀態並下載
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):

		}
		statusData, err := getCertificateStatus(ctx, createResp.ID, m.ZeroSSLApiKey, m.ZeroSSLBaseURL)
		if err != nil {
			return err
		}
		switch statusData.Status {
		case "issued":
			logrus.Info("Certificate issued!")
			return m.saveCertificate(ctx, createResp.ID, certPath, chainPath, fullchainPath)

		case "draft":
			logrus.Info("Waiting for validation...")

		case "pending_validation":
			logrus.Info("Validation in progress...")

		default:
			logrus.Warningf("Unknown status: %s", statusData.Status)
		}
	}
}

// generateCSR 生成 CSR (Certificate Signing Request)
func (m *manager) generateCSR() (string, error) {
	logrus.Info("Generating CSR...")

	keyPath := filepath.Join(m.CertDir, "privkey.pem")

	// 生成私鑰
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", errx.Wrap(err).AppendMsg("failed to generate private key").Err()
	}

	// 保存私鑰 (privkey.pem)
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return "", errx.Wrap(err).AppendMsg("failed to create private key file").Err()
	}
	defer keyFile.Close()

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if _, err := keyFile.Write(keyPEM); err != nil {
		return "", errx.Wrap(err).AppendMsg("failed to write private key").Err()
	}
	logrus.Infof("Private key saved: %s", keyPath)

	// 生成 CSR
	commonName := m.PublicIps[0]
	if len(m.PublicIps) > 1 {
		// 如果有多個 IP，使用逗號連接作為 CommonName
		commonName = strings.Join(m.PublicIps, ",")
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", errx.Wrap(err).AppendMsg("failed to create CSR").Err()
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	logrus.Info("CSR generated successfully")
	return string(csrPEM), nil
}

// startValidationServer 啟動臨時 HTTP 服務器用於驗證
// 根據不同的 IP 對應的路徑返回不同的驗證內容
func startValidationServer(ctx context.Context, otherMethods OtherMethods) error {
	// 構建路徑到驗證內容的映射
	pathToContent := make(map[string]string)

	for ip, details := range otherMethods {
		if details.FileValidationURLHTTP == "" || len(details.FileValidationContent) == 0 {
			logrus.Warningf("Incomplete validation info for IP %s", ip)
			continue
		}

		// 從 URL 中提取路徑
		// URL 格式: http://ip/.well-known/pki-validation/xxx.txt
		urlParts := strings.Split(details.FileValidationURLHTTP, "/")
		if len(urlParts) >= 2 {
			// 獲取路徑部分（/.well-known/pki-validation/xxx.txt）
			path := "/" + strings.Join(urlParts[3:], "/")
			content := strings.Join(details.FileValidationContent, "\n")
			pathToContent[path] = content
			logrus.Infof("Mapped validation path for IP %s: %s", ip, path)
		}
	}

	if len(pathToContent) == 0 {
		return errx.New("no valid validation paths found")
	}

	// 創建 handler，根據請求路徑返回對應的驗證內容
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Infof("Received validation request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		content, ok := pathToContent[r.URL.Path]
		if !ok {
			logrus.Warningf("Unknown validation path: %s", r.URL.Path)
			// 嘗試返回任意一個驗證內容（兼容舊邏輯）
			for _, c := range pathToContent {
				content = c
				break
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
		logrus.Infof("Returned validation content for path: %s", r.URL.Path)
	})

	server := &http.Server{
		Addr:    ":80",
		Handler: handler,
	}

	// 在 goroutine 中啟動服務器
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Warningf("Temporary HTTP server error: %v", err)
		}
	}()

	// 監聽 context 取消事件，自動關閉服務器
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logrus.Warningf("Failed to shutdown HTTP server: %v", err)
		} else {
			logrus.Info("Temporary HTTP server closed")
		}
	}()

	logrus.Info("Temporary HTTP server started (listening on :80)")
	logrus.Infof("Serving %d validation paths", len(pathToContent))
	return nil
}

// saveCertificate 下載並保存證書文件
func (m *manager) saveCertificate(ctx context.Context, certID, certPath, chainPath, fullchainPath string) error {
	// 下載證書
	certFiles, err := downloadCertificate(ctx, certID, m.ZeroSSLApiKey, m.ZeroSSLBaseURL)
	if err != nil {
		return err
	}

	// 1. 保存證書本身 (cert.pem)
	if err := os.WriteFile(certPath, []byte(certFiles.CertificateCrt), 0644); err != nil {
		return errx.Wrap(err).AppendMsg("failed to save certificate").Err()
	}
	logrus.Infof("Certificate saved: %s", certPath)

	// 2. 保存 CA 鏈 (chain.pem)
	if err := os.WriteFile(chainPath, []byte(certFiles.CaBundleCrt), 0644); err != nil {
		return errx.Wrap(err).AppendMsg("failed to save CA chain").Err()
	}
	logrus.Infof("CA chain saved: %s", chainPath)

	// 3. 保存完整證書鏈 (fullchain.pem = cert.pem + chain.pem)
	fullchain := certFiles.CertificateCrt + "\n" + certFiles.CaBundleCrt
	if err := os.WriteFile(fullchainPath, []byte(fullchain), 0644); err != nil {
		return errx.Wrap(err).AppendMsg("failed to save full chain").Err()
	}
	logrus.Infof("Full chain saved: %s", fullchainPath)

	// 4. 私鑰 (privkey.pem) 已在 generateCSR() 中生成並保存
	keyPath := filepath.Join(m.CertDir, "privkey.pem")
	logrus.Infof("Private key location: %s", keyPath)

	logrus.Info("ZeroSSL IP certificate successfully obtained and installed!")
	logrus.Info("Certificate files (Let's Encrypt style):")
	logrus.Infof("  cert.pem       - certificate itself")
	logrus.Infof("  chain.pem      - CA certificate chain")
	logrus.Infof("  fullchain.pem  - full chain (recommended)")
	logrus.Infof("  privkey.pem    - private key")
	logrus.Info("Certificate validity: 90 days")
	logrus.Info("")
	logrus.Info("Nginx configuration example:")
	logrus.Infof("  ssl_certificate     %s;", fullchainPath)
	logrus.Infof("  ssl_certificate_key %s;", keyPath)

	return nil
}
