package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"bitbucket.org/tencent-international/go-pkg/shutdown"
	"github.com/sirupsen/logrus"
	"github.com/tencent-go/edge-node/internal/cert"
	"github.com/tencent-go/edge-node/internal/compose"
	"github.com/tencent-go/edge-node/internal/publicip"
)

type StartCmd struct {
	Config `embed:""`
}

func (s *StartCmd) Run() error {
	// 自動獲取公網 IP
	if len(s.PublicIPs) == 0 {
		ip, err := publicip.Get()
		if err != nil {
			logrus.Fatalf("Failed to get public IP: %v", err)
		}
		s.PublicIPs = []string{ip}
	}

	// 設置證書目錄
	wd, err := os.Getwd()
	if err != nil {
		logrus.Fatalf("Failed to get working directory: %v", err)
	}
	if s.Cert.Dir == "" {
		s.Cert.Dir = filepath.Join(wd, "cert")
	}

	// 初始化應用
	apps := map[string]compose.App{}
	{
		workDir := filepath.Join(wd, "")
		s3Cfg := compose.S3Config{
			BaseEndpoint: s.S3.Endpoint,
			AccessKey:    s.S3.AccessKey,
			Secret:       s.S3.Secret,
			Region:       s.S3.Region,
			Bucket:       s.S3.Bucket,
		}
		for _, appName := range s.AppNames {
			apps[appName] = compose.NewApp(appName, workDir, s3Cfg)
		}
	}

	// 創建證書管理器
	manager, err := cert.NewManager(cert.Config{
		CertDir:          s.Cert.Dir,
		CertValidityDays: s.Cert.ValidityDays,
		ZeroSSLApiKey:    s.ZeroSSL.ApiKey,
		ZeroSSLBaseURL:   s.ZeroSSL.BaseURL,
		PublicIps:        s.PublicIPs,
	})
	if err != nil {
		logrus.Fatalf("Failed to create certificate manager: %v", err)
	}

	// TLS 證書自動續期
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

			if daysUntilExpiry <= s.Cert.RenewDays {
				// 小於等於續期天數，立即續期
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

			// 計算精確的等待時間
			renewTime := certificate.NotAfter.Add(-time.Duration(s.Cert.RenewDays) * 24 * time.Hour)
			waitDuration := time.Until(renewTime)
			logrus.Infof("Certificate has %d days remaining, will check renewal in %v", daysUntilExpiry, waitDuration)
			time.Sleep(waitDuration)
		}
	}()

	// Docker Compose 應用管理
	// TODO: 添加應用同步和管理邏輯

	shutdown.Wait()
	return nil
}
