package main

import "github.com/tencent-go/edge-node/internal/compose"

type CertConfig struct {
	Dir          string `help:"證書目錄" env:"CERT_DIR" type:"path" name:"dir" yaml:"dir" default:"./cert"`
	ValidityDays int    `help:"證書有效期（天）" env:"CERT_VALIDITY_DAYS" default:"90" name:"validity-days" yaml:"validity-days"`
	RenewDays    int    `help:"提前續期天數" env:"CERT_RENEW_DAYS" default:"2" name:"renew-days" yaml:"renew-days"`
}

type ZeroSSLConfig struct {
	ApiKey  string `help:"ZeroSSL API Key" env:"ZEROSSL_API_KEY" name:"api-key" yaml:"api-key"`
	BaseURL string `help:"ZeroSSL API 地址" env:"ZEROSSL_BASE_URL" default:"https://api.zerossl.com" name:"base-url" yaml:"base-url"`
}

type S3Config struct {
	Endpoint  string `help:"S3 端點（R2 使用）" env:"S3_ENDPOINT" name:"endpoint" yaml:"endpoint"`
	AccessKey string `help:"S3 Access Key" env:"S3_ACCESS_KEY" name:"access-key" yaml:"access-key"`
	Secret    string `help:"S3 Secret" env:"S3_SECRET" name:"secret" yaml:"secret"`
	Region    string `help:"S3 區域" env:"S3_REGION" default:"auto" name:"region" yaml:"region"`
	Bucket    string `help:"S3 桶名" env:"S3_BUCKET" name:"bucket" yaml:"bucket"`
}

func (cfg S3Config) ToCompose() compose.S3Config {
	return compose.S3Config{
		BaseEndpoint: cfg.Endpoint,
		AccessKey:    cfg.AccessKey,
		Secret:       cfg.Secret,
		Region:       cfg.Region,
		Bucket:       cfg.Bucket,
	}
}

type Config struct {
	// 證書配置
	Cert CertConfig `embed:"" prefix:"cert." yaml:"cert"`

	// ZeroSSL 配置
	ZeroSSL ZeroSSLConfig `embed:"" prefix:"zerossl." yaml:"zerossl"`

	// S3 配置
	S3 S3Config `embed:"" prefix:"s3." yaml:"s3"`

	// 公網 IP 地址
	PublicIPs []string `help:"公網 IP 地址列表" env:"PUBLIC_IPS" sep:"," name:"public-ips" yaml:"public_ips"`

	// 應用配置
	AppNames []string `help:"應用名稱列表" env:"APP_NAMES" sep:"," name:"app-names" yaml:"app_names"`

	WorkDir string `help:"工作目錄" type:"path"`
}
