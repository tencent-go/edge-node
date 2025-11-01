package publicip

import (
	"io"
	"net/http"
	"strings"
	"time"

	"bitbucket.org/tencent-international/go-pkg/errx"
	"github.com/sirupsen/logrus"
)

// Get 獲取公網 IP 地址
// 優先使用阿里雲 ECS 元數據服務，失敗則使用公共 IP 查詢服務
func Get() (string, error) {
	// 首先嘗試阿里雲元數據服務
	if ip, err := getIPFromAliyunMetadata(); err == nil {
		return ip, nil
	}

	// 如果失敗，嘗試公共服務
	if ip, err := getIPFromPublicService(); err == nil {
		return ip, nil
	}

	return "", errx.New("failed to get public IP address")
}

// getIPFromAliyunMetadata 從阿里雲 ECS 元數據服務獲取公網 IP
func getIPFromAliyunMetadata() (string, error) {
	// 嘗試獲取 EIP
	if ip, err := fetchMetadata("http://100.100.100.200/latest/meta-data/eipv4"); err == nil {
		logrus.Infof("Got EIP from Aliyun metadata service: %s", ip)
		return ip, nil
	}

	// 嘗試獲取公網 IP（非 EIP）
	if ip, err := fetchMetadata("http://100.100.100.200/latest/meta-data/public-ipv4"); err == nil {
		logrus.Infof("Got public IP from Aliyun metadata service: %s", ip)
		return ip, nil
	}

	return "", errx.New("failed to get IP from Aliyun metadata service")
}

// getIPFromPublicService 從公共 IP 查詢服務獲取公網 IP
func getIPFromPublicService() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://ident.me",
	}

	for _, service := range services {
		if ip, err := fetchIP(service); err == nil {
			logrus.Infof("Got public IP from %s: %s", service, ip)
			return ip, nil
		} else {
			logrus.Warningf("Failed to get IP from %s: %v", service, err)
		}
	}

	return "", errx.New("failed to get IP from all public services")
}

// fetchMetadata 從阿里雲元數據服務獲取數據
func fetchMetadata(url string) (string, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errx.Newf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", errx.New("empty response")
	}

	return ip, nil
}

// fetchIP 從公共服務獲取 IP
func fetchIP(url string) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errx.Newf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", errx.New("empty response")
	}

	return ip, nil
}
