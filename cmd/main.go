package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"
)

type CLI struct {
	ShowConfig ShowConfigCmd   `cmd:"" name:"config" help:"顯示當前配置"`
	Pack       PackCmd         `cmd:"" name:"pack" help:"打包並上傳compose配置"`
	Start      StartCmd        `cmd:"" name:"start" help:"運行服務器"`
	ConfigFile kong.ConfigFlag `help:"配置文件路徑（YAML，默認查找工作目錄 config.yaml）" short:"c" name:"config" type:"path"`
}

type ShowConfigCmd struct {
	Config `embed:""`
}

func (c *ShowConfigCmd) Run() error {
	// 輸出為 YAML（已合併配置文件、環境變量和命令行參數）
	data, err := yaml.Marshal(c.Config)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func main() {
	var cli CLI

	// 使用 kong 解析命令行和環境變量
	ctx := kong.Parse(&cli,
		kong.Name("edgenode"),
		kong.Description("Edge Node Server - 管理 SSL 證書和 Docker Compose 應用"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Configuration(yamlConfigurationLoader, "config.yaml"),
	)

	err := ctx.Run(&cli)
	ctx.FatalIfErrorf(err)
}

func yamlConfigurationLoader(r io.Reader) (kong.Resolver, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	normalized := normalizeYAML(raw)
	if normalized == nil {
		normalized = map[string]any{}
	}

	jsonData, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("encode JSON: %w", err)
	}

	return kong.JSON(bytes.NewReader(jsonData))
}

func normalizeYAML(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, val := range v {
			addKeyVariants(out, key, normalizeYAML(val))
		}
		return out
	case map[interface{}]any:
		out := make(map[string]any, len(v))
		for key, val := range v {
			addKeyVariants(out, fmt.Sprint(key), normalizeYAML(val))
		}
		return out
	case []interface{}:
		for i, val := range v {
			v[i] = normalizeYAML(val)
		}
		return v
	default:
		return v
	}
}

func addKeyVariants(target map[string]any, key string, val any) {
	target[key] = val
	if alt := strings.ReplaceAll(key, "-", "_"); alt != key {
		if _, exists := target[alt]; !exists {
			target[alt] = val
		}
	}
	if alt := strings.ReplaceAll(key, "_", "-"); alt != key {
		if _, exists := target[alt]; !exists {
			target[alt] = val
		}
	}
}
