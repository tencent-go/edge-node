package cert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tencent-go/pkg/errx"
	"github.com/sirupsen/logrus"
)

// CreateCertificateRequest 創建證書請求
type CreateCertificateRequest struct {
	CertificateDomains      string `json:"certificate_domains"`
	CertificateCSR          string `json:"certificate_csr"`
	CertificateValidityDays int    `json:"certificate_validity_days"`
}

// ValidationDetails 驗證詳情
type ValidationDetails struct {
	FileValidationURLHTTP string   `json:"file_validation_url_http"`
	FileValidationContent []string `json:"file_validation_content"`
}

// OtherMethods 其他驗證方法
type OtherMethods map[string]ValidationDetails

// Validation 驗證信息
type Validation struct {
	OtherMethods OtherMethods `json:"other_methods"`
}

// CreateCertificateResponse 創建證書響應
type CreateCertificateResponse struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	CommonName string     `json:"common_name"`
	Status     string     `json:"status"`
	Validation Validation `json:"validation"`
}

// VerifyChallengeRequest 觸發驗證請求
type VerifyChallengeRequest struct {
	ValidationMethod string `json:"validation_method"`
}

// CertificateStatusResponse 證書狀態響應
type CertificateStatusResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// CertificateDownloadResponse 證書下載響應
type CertificateDownloadResponse struct {
	CertificateCrt string `json:"certificate.crt"`
	CaBundleCrt    string `json:"ca_bundle.crt"`
}

// createCertificate 調用 ZeroSSL API 創建證書
func createCertificate(ctx context.Context, req CreateCertificateRequest, apiKey, baseURL string) (*CreateCertificateResponse, error) {
	logrus.Info("Creating certificate request...")

	// 使用 form-data 格式提交
	formData := url.Values{}
	formData.Set("certificate_domains", req.CertificateDomains)
	formData.Set("certificate_csr", req.CertificateCSR)
	formData.Set("certificate_validity_days", fmt.Sprintf("%d", req.CertificateValidityDays))

	createURL := fmt.Sprintf("%s/certificates?access_key=%s", baseURL, apiKey)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", createURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to create request").Err()
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("certificate creation request failed").Err()
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to read response body").Err()
	}

	if resp.StatusCode != 200 {
		logrus.Errorf("Failed to create certificate: %d", resp.StatusCode)
		logrus.Errorf("Response: %s", string(bodyBytes))
		return nil, errx.Newf("failed to create certificate: %d", resp.StatusCode)
	}

	var createResp CreateCertificateResponse
	if err := json.Unmarshal(bodyBytes, &createResp); err != nil {
		logrus.Errorf("Raw API response: %s", string(bodyBytes))
		return nil, errx.Wrap(err).AppendMsg("failed to parse response").Err()
	}

	if createResp.ID == "" {
		logrus.Errorf("ZeroSSL API returned unexpected payload: %s", string(bodyBytes))
		return nil, errx.New("certificate ID not found")
	}

	logrus.Infof("Certificate created successfully, ID: %s", createResp.ID)
	return &createResp, nil
}

// verifyChallenge 觸發證書驗證
func verifyChallenge(ctx context.Context, certID, apiKey string, req VerifyChallengeRequest, baseURL string) error {
	logrus.Info("Triggering validation...")

	verifyData := url.Values{}
	verifyData.Set("validation_method", req.ValidationMethod)

	verifyURL := fmt.Sprintf("%s/certificates/%s/challenges?access_key=%s", baseURL, certID, apiKey)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", verifyURL, strings.NewReader(verifyData.Encode()))
	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to create validation request").Err()
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	verifyResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to trigger validation").Err()
	}
	defer verifyResp.Body.Close()

	if verifyResp.StatusCode != 200 {
		body, _ := io.ReadAll(verifyResp.Body)
		logrus.Errorf("Failed to trigger validation: %d", verifyResp.StatusCode)
		logrus.Errorf("Response: %s", string(body))
		return errx.Newf("failed to trigger validation: %d", verifyResp.StatusCode)
	}

	logrus.Info("Validation triggered, waiting for completion...")
	return nil
}

// getCertificateStatus 獲取證書狀態
func getCertificateStatus(ctx context.Context, certID, apiKey, baseURL string) (*CertificateStatusResponse, error) {
	statusURL := fmt.Sprintf("%s/certificates/%s?access_key=%s", baseURL, certID, apiKey)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to create status request").Err()
	}

	statusResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to get status").Err()
	}
	defer statusResp.Body.Close()

	if statusResp.StatusCode != 200 {
		return nil, errx.Newf("failed to get status: %d", statusResp.StatusCode)
	}

	var statusData CertificateStatusResponse
	if err := json.NewDecoder(statusResp.Body).Decode(&statusData); err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to parse status").Err()
	}

	return &statusData, nil
}

// downloadCertificate 下載證書
func downloadCertificate(ctx context.Context, certID, apiKey, baseURL string) (*CertificateDownloadResponse, error) {
	logrus.Info("Downloading certificate...")

	downloadURL := fmt.Sprintf("%s/certificates/%s/download/return?access_key=%s", baseURL, certID, apiKey)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to create download request").Err()
	}

	downloadResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to download certificate").Err()
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != 200 {
		logrus.Errorf("Failed to download certificate: %d", downloadResp.StatusCode)
		return nil, errx.Newf("failed to download certificate: %d", downloadResp.StatusCode)
	}

	var certFiles CertificateDownloadResponse
	if err := json.NewDecoder(downloadResp.Body).Decode(&certFiles); err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to parse certificate files").Err()
	}

	return &certFiles, nil
}
