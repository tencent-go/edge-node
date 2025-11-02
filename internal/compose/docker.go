package compose

import (
	"context"
	"os/exec"
	"path/filepath"

	"bitbucket.org/tencent-international/go-pkg/errx"
	"github.com/sirupsen/logrus"
)

// Start 啟動 Docker Compose 服務
func (a *app) Start(ctx context.Context) error {
	appDir := filepath.Join(a.rootDir, a.appName)

	logrus.Infof("Starting Docker Compose services in %s", appDir)

	cmd := exec.CommandContext(ctx, "docker", "compose", "up", "-d")
	cmd.Dir = appDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("Docker compose up failed: %s", string(output))
		return errx.Wrap(err).AppendMsg("failed to start docker compose services").Err()
	}

	logrus.Infof("Docker Compose started successfully: %s", string(output))
	return nil
}

// Stop 停止 Docker Compose 服務
func (a *app) Stop(ctx context.Context) error {
	appDir := filepath.Join(a.rootDir, a.appName)

	logrus.Infof("Stopping Docker Compose services in %s", appDir)

	cmd := exec.CommandContext(ctx, "docker", "compose", "down")
	cmd.Dir = appDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("Docker compose down failed: %s", string(output))
		return errx.Wrap(err).AppendMsg("failed to stop docker compose services").Err()
	}

	logrus.Infof("Docker Compose stopped successfully: %s", string(output))
	return nil
}

// Restart 重啟 Docker Compose 服務
func (a *app) Restart(ctx context.Context) error {
	appDir := filepath.Join(a.rootDir, a.appName)

	logrus.Infof("Restarting Docker Compose services in %s", appDir)

	cmd := exec.CommandContext(ctx, "docker", "compose", "restart")
	cmd.Dir = appDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("Docker compose restart failed: %s", string(output))
		return errx.Wrap(err).AppendMsg("failed to restart docker compose services").Err()
	}

	logrus.Infof("Docker Compose restarted successfully: %s", string(output))
	return nil
}
