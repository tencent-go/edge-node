package main

import (
	"context"
	"time"

	"bitbucket.org/tencent-international/go-pkg/env"
	"bitbucket.org/tencent-international/go-pkg/shutdown"
	"github.com/sirupsen/logrus"
	"github.com/tencent-go/edge-node/internal/cert"
	"github.com/tencent-go/edge-node/internal/publicip"
)

type Config struct {
	CertDir          string `env:"CERT_DIR" default:"/etc/cert"`
	CertValidityDays int    `env:"CERT_VALIDITY_DAYS" default:"90"`
	CertRenewDays    int    `env:"CERT_RENEW_DAYS" default:"2"`
	ZeroSSLApiKey    string `env:"ZEROSSL_API_KEY"`
	ZeroSSLBaseURL   string `env:"ZEROSSL_BASE_URL" default:"https://api.zerossl.com"`
	PublicIP         string `env:"PUBLIC_IP,omitempty"`
}

var configReader = env.NewReaderBuilder[Config]().Build()

func main() {
	env.PrintState()
	cfg := configReader.Read()
	if cfg.PublicIP == "" {
		ip, err := publicip.Get()
		if err != nil {
			logrus.Fatalf("Failed to get public IP: %v", err)
		}
		cfg.PublicIP = ip
	}
	// 創建證書管理器
	manager, err := cert.NewManager(cert.Config{
		CertDir:          cfg.CertDir,
		CertValidityDays: cfg.CertValidityDays,
		ZeroSSLApiKey:    cfg.ZeroSSLApiKey,
		ZeroSSLBaseURL:   cfg.ZeroSSLBaseURL,
		PublicIP:         cfg.PublicIP,
	})
	if err != nil {
		logrus.Fatalf("Failed to create certificate manager: %v", err)
	}

	go func() {
		for {
			certificate, err := manager.Load()
			if err != nil {
				// 證書不存在或無效，申請新證書
				logrus.Info("Certificate not found or invalid, requesting new certificate...")
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				if err := manager.Obtain(ctx); err != nil {
					logrus.Fatalf("Failed to obtain certificate: %v", err)
				}
				cancel()
				logrus.Info("Certificate obtained successfully")
				continue
			}

			// 計算剩餘天數
			daysUntilExpiry := int(time.Until(certificate.NotAfter).Hours() / 24)
			logrus.Infof("Certificate valid, %d days until expiry", daysUntilExpiry)

			if daysUntilExpiry <= cfg.CertRenewDays {
				// 小於等於 2 天，立即續期
				logrus.Infof("Certificate will expire in %d days, renewing...", daysUntilExpiry)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				if err := manager.Obtain(ctx); err != nil {
					cancel()
					logrus.Errorf("Failed to renew certificate: %v, retrying in 5 seconds", err)
					time.Sleep(5 * time.Second)
					continue
				}
				cancel()
				logrus.Info("Certificate renewed successfully")
				continue
			}

			// 計算精確的等待時間：過期時間 - 當前時間 - 續期提前時間
			renewTime := certificate.NotAfter.Add(-time.Duration(cfg.CertRenewDays) * 24 * time.Hour)
			waitDuration := time.Until(renewTime)
			logrus.Infof("Certificate has %d days remaining, will check renewal in %v", daysUntilExpiry, waitDuration)
			time.Sleep(waitDuration)
		}
	}()
	shutdown.Wait()
}
