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
	PublicIP         string
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
		return nil, errx.Wrap(err).WithMsg("failed to create certificate directory").Err()
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

	logrus.Infof("Starting ZeroSSL certificate request for IP %s...", m.PublicIP)
	logrus.Info("ZeroSSL certificate validity: 90 days")
	return m.obtainCertificate(ctx)
}

// loadCertFromDisk 從磁盤加載證書
func (m *manager) loadCertFromDisk() (*x509.Certificate, error) {
	certPath := filepath.Join(m.CertDir, "cert.pem")
	keyPath := filepath.Join(m.CertDir, "privkey.pem")

	// 檢查文件是否存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, errx.NotFound.WithMsg("certificate file not found").Err()
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, errx.NotFound.WithMsg("private key file not found").Err()
	}

	// 讀取證書
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, errx.Wrap(err).WithMsg("failed to read certificate file").Err()
	}

	// 解析證書
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, errx.Validation.WithMsg("failed to decode certificate PEM").Err()
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errx.Wrap(err).WithMsg("failed to parse certificate").Err()
	}

	return cert, nil
}

// validateCert 校驗證書
func (m *manager) validateCert(cert *x509.Certificate) error {
	// 1. 驗證證書是否過期
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errx.Validation.WithMsg("certificate not yet valid").Err()
	}
	if now.After(cert.NotAfter) {
		return errx.Validation.WithMsg("certificate expired").Err()
	}

	// 2. 驗證 IP 地址是否匹配
	ipMatched := false

	// 檢查 Subject.CommonName
	if cert.Subject.CommonName == m.PublicIP {
		logrus.Infof("Certificate IP matched (CommonName): %s", m.PublicIP)
		ipMatched = true
	}

	// 檢查 IPAddresses 列表
	if !ipMatched {
		for _, ip := range cert.IPAddresses {
			if ip.String() == m.PublicIP {
				logrus.Infof("Certificate IP matched (IPAddresses): %s", m.PublicIP)
				ipMatched = true
				break
			}
		}
	}

	// 檢查 DNSNames 列表（有些證書可能把 IP 放在這裡）
	if !ipMatched {
		for _, dns := range cert.DNSNames {
			if dns == m.PublicIP {
				logrus.Infof("Certificate IP matched (DNSNames): %s", m.PublicIP)
				ipMatched = true
				break
			}
		}
	}

	if !ipMatched {
		logrus.Errorf("Certificate IP mismatch, expected: %s, CommonName: %s, IPAddresses: %v, DNSNames: %v",
			m.PublicIP, cert.Subject.CommonName, cert.IPAddresses, cert.DNSNames)
		return errx.Validation.WithMsgf("certificate IP mismatch, expected: %s", m.PublicIP).Err()
	}

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
		return errx.Wrap(err).WithMsg("failed to generate CSR").Err()
	}
	logrus.Info("CSR generated successfully")

	// 2. 創建證書
	createReq := CreateCertificateRequest{
		CertificateDomains:      m.PublicIP,
		CertificateCSR:          csr,
		CertificateValidityDays: m.CertValidityDays,
	}

	createResp, err := createCertificate(ctx, createReq, m.ZeroSSLApiKey, m.ZeroSSLBaseURL)
	if err != nil {
		return err
	}

	// 3. 獲取驗證詳情
	logrus.Info("Getting validation details...")
	validationDetails, ok := createResp.Validation.OtherMethods[m.PublicIP]
	if !ok {
		validationJSON, _ := json.MarshalIndent(createResp.Validation, "", "  ")
		logrus.Errorf("Validation data: %s", string(validationJSON))
		return errx.New("IP validation info not found")
	}

	if validationDetails.FileValidationURLHTTP == "" || len(validationDetails.FileValidationContent) == 0 {
		validationJSON, _ := json.MarshalIndent(validationDetails, "", "  ")
		logrus.Errorf("Validation data: %s", string(validationJSON))
		return errx.New("validation info incomplete")
	}

	// 4. 準備驗證內容
	logrus.Info("Preparing validation...")
	validationContent := strings.Join(validationDetails.FileValidationContent, "\n")
	logrus.Infof("Validation URL: %s", validationDetails.FileValidationURLHTTP)

	// 5. 啟動臨時 HTTP 服務器用於驗證
	if err := startValidationServer(ctx, validationContent); err != nil {
		return errx.Wrap(err).WithMsg("failed to start validation server").Err()
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
		return "", errx.Wrap(err).WithMsg("failed to generate private key").Err()
	}

	// 保存私鑰 (privkey.pem)
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return "", errx.Wrap(err).WithMsg("failed to create private key file").Err()
	}
	defer keyFile.Close()

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if _, err := keyFile.Write(keyPEM); err != nil {
		return "", errx.Wrap(err).WithMsg("failed to write private key").Err()
	}
	logrus.Infof("Private key saved: %s", keyPath)

	// 生成 CSR
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: m.PublicIP,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", errx.Wrap(err).WithMsg("failed to create CSR").Err()
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	logrus.Info("CSR generated successfully")
	return string(csrPEM), nil
}

// startValidationServer 啟動臨時 HTTP 服務器用於驗證
// 不管請求什麼路徑，都返回驗證內容
func startValidationServer(ctx context.Context, validationContent string) error {
	// 創建自定義 handler，對所有請求返回驗證內容
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Infof("Received validation request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(validationContent))
		logrus.Infof("Returned validation content to: %s", r.RemoteAddr)
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
		return errx.Wrap(err).WithMsg("failed to save certificate").Err()
	}
	logrus.Infof("Certificate saved: %s", certPath)

	// 2. 保存 CA 鏈 (chain.pem)
	if err := os.WriteFile(chainPath, []byte(certFiles.CaBundleCrt), 0644); err != nil {
		return errx.Wrap(err).WithMsg("failed to save CA chain").Err()
	}
	logrus.Infof("CA chain saved: %s", chainPath)

	// 3. 保存完整證書鏈 (fullchain.pem = cert.pem + chain.pem)
	fullchain := certFiles.CertificateCrt + "\n" + certFiles.CaBundleCrt
	if err := os.WriteFile(fullchainPath, []byte(fullchain), 0644); err != nil {
		return errx.Wrap(err).WithMsg("failed to save full chain").Err()
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
