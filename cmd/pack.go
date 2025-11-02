package main

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/tencent-go/edge-node/internal/compose"
)

type PackCmd struct {
	App      string   `help:"指定AppName 若為空則打包全部"`
	WorkDir  string   `help:"工作目錄" type:"path"`
	S3       S3Config `embed:"" prefix:"s3." yaml:"s3"`
	AppNames []string `help:"應用名稱列表" env:"APP_NAMES" sep:"," name:"app-names" yaml:"app-names"`
}

func (c *PackCmd) Run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c.App != "" {
		return c.pack(ctx, c.App)
	}
	if len(c.AppNames) == 0 {
		fmt.Println("no app-names specified")
		return nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(c.AppNames))
	var (
		mu           sync.Mutex
		failedNames  []string
		successNames []string
	)
	for _, name := range c.AppNames {
		appName := name
		go func() {
			defer wg.Done()
			if err := c.pack(ctx, appName); err != nil {
				mu.Lock()
				failedNames = append(failedNames, fmt.Sprintf("%s (%v)", appName, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			successNames = append(successNames, appName)
			mu.Unlock()
		}()
	}
	wg.Wait()

	fmt.Printf("pack summary - success: %d, failed: %d\n", len(successNames), len(failedNames))
	if len(successNames) > 0 {
		fmt.Printf("  succeeded apps: %s\n", strings.Join(successNames, ", "))
	}
	if len(failedNames) > 0 {
		fmt.Printf("  failed apps: %s\n", strings.Join(failedNames, ", "))
		return fmt.Errorf("pack failed for apps: %s", strings.Join(failedNames, ", "))
	}

	return nil
}

func (c *PackCmd) pack(ctx context.Context, appName string) error {
	app := compose.NewApp(appName, path.Join(c.WorkDir, "compose"), c.S3.ToCompose())
	return app.Pack(ctx)
}
