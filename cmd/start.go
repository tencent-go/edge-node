package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tencent-go/edge-node/internal/cert"
	"github.com/tencent-go/edge-node/internal/compose"
	"github.com/tencent-go/edge-node/internal/publicip"
)

type StartCmd struct {
	Config        `embed:""`
	DockerConfDir string `help:"Docker Compose配置根目錄" type:"path" default:"./docker"`
	isFirstTime   bool
}

func (s *StartCmd) onTlsReady() {
	if s.isFirstTime {
		s.isFirstTime = false
		go s.runApps()
	} else {

	}
}

func (s *StartCmd) runApps() {
	if len(s.AppNames) == 0 {
		return
	}
	apps := map[string]compose.App{}
	{
		s3Cfg := s.S3.ToCompose()
		for _, appName := range s.AppNames {
			app := compose.NewApp(appName, s.DockerConfDir, s3Cfg)
			if err := app.Start(context.Background()); err != nil {
				logrus.Errorf("Failed to start app %s: %v", appName, err)
			}
			apps[appName] = app
		}
	}
	check := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		wg := sync.WaitGroup{}
		wg.Add(len(s.AppNames))
		for _, app := range apps {
			go func() {
				defer wg.Done()
				is, err := app.IsUpToDate(ctx)
				if err != nil || is {
					return
				}
				if err = app.Sync(ctx); err != nil {
					return
				}
				_ = app.Restart(ctx)
			}()
		}
	}
	for {
		check()
		time.Sleep(30 * time.Second)
	}
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
	closeSignal := make(chan os.Signal, 1)
	signal.Notify(closeSignal, syscall.SIGINT, syscall.SIGTERM)
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

		s.onTlsReady()

		// 計算精確的等待時間
		renewTime := certificate.NotAfter.Add(-time.Duration(s.Cert.RenewDays) * 24 * time.Hour)
		waitDuration := time.Until(renewTime)
		logrus.Infof("Certificate has %d days remaining, will check renewal in %v", daysUntilExpiry, waitDuration)
		select {
		case <-time.After(waitDuration):
		case <-closeSignal:
			return nil
		}
	}
}
