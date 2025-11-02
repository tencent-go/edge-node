package compose

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"bitbucket.org/tencent-international/go-pkg/errx"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
)

// App Docker Compose 應用管理器接口
type App interface {
	Pack(ctx context.Context) error
	IsUpToDate(ctx context.Context) (bool, error)
	Sync(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
}

type S3Config struct {
	BaseEndpoint string
	AccessKey    string
	Secret       string
	Region       string
	Bucket       string
}

func NewApp(appName string, rootDir string, s3Config S3Config) App {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(s3Config.Region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s3Config.AccessKey, s3Config.Secret, ""),
		),
	)
	if err != nil {
		logrus.Fatalf("Failed to load S3 config: %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if s3Config.BaseEndpoint != "" {
			o.BaseEndpoint = aws.String(s3Config.BaseEndpoint)
		}
	})

	return &app{
		appName:  appName,
		s3Client: client,
		bucket:   s3Config.Bucket,
		rootDir:  rootDir,
	}
}

type app struct {
	appName  string
	s3Client *s3.Client
	bucket   string
	rootDir  string
}

func (a *app) Pack(ctx context.Context) error {
	appDir := filepath.Join(a.rootDir, a.appName)
	if _, err := os.Stat(appDir); os.IsNotExist(err) {
		return errx.NotFound.AppendMsgf("app directory not found: %s", appDir).Err()
	}

	// 打包到內存
	logrus.Infof("Packing directory: %s", appDir)
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)
	fileCount, dirCount := 0, 0

	err := filepath.Walk(appDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(filepath.Dir(appDir), path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relPath)

		if info.IsDir() {
			header.Name += "/"
			dirCount++
		} else {
			header.Method = zip.Deflate
			fileCount++
		}

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(writer, file)
			file.Close()
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	})

	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to archive directory").Err()
	}

	if err := zipWriter.Close(); err != nil {
		return errx.Wrap(err).AppendMsg("failed to close zip writer").Err()
	}

	logrus.Infof("Archived %d files and %d directories", fileCount, dirCount)

	// 計算源文件的 hash（基於所有文件內容）
	hash, err := a.calculateDirectoryHash(appDir)
	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to calculate directory hash").Err()
	}
	logrus.Infof("Directory hash: %s", hash)

	// 獲取壓縮數據
	zipData := buf.Bytes()

	// 上傳 zip 文件（如果需要）
	zipKey := fmt.Sprintf("edge-configs/%s/%s.zip", a.appName, hash)
	if err := a.uploadZipIfNeeded(ctx, zipData, zipKey); err != nil {
		return err
	}

	// 保存並上傳 hash 文件
	hashFilePath := filepath.Join(a.rootDir, fmt.Sprintf("%s.sha256", a.appName))
	if err := os.WriteFile(hashFilePath, []byte(hash), 0644); err != nil {
		return errx.Wrap(err).AppendMsg("failed to save local hash file").Err()
	}

	hashKey := fmt.Sprintf("edge-configs/%s.sha256", a.appName)
	if err := a.uploadHashIfNeeded(ctx, hash, hashKey); err != nil {
		return err
	}

	logrus.Infof("Pack %s completed successfully", a.appName)
	return nil
}

func (a *app) IsUpToDate(ctx context.Context) (bool, error) {
	// 讀取本地 hash
	localHash, err := a.readLocalHash()
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Info("Local hash file not found, update needed")
			return false, nil
		}
		return false, err
	}

	// 讀取遠程 hash
	logrus.Info("Checking remote hash file")
	remoteHash, err := a.readRemoteHash(ctx)
	if err != nil {
		return false, err
	}

	// 比對 hash
	if localHash != remoteHash {
		logrus.Infof("Hash mismatch: local=%s, remote=%s", localHash, remoteHash)
		return false, nil
	}

	logrus.Info("Configuration is up to date")
	return true, nil
}

func (a *app) Sync(ctx context.Context) error {
	// 讀取遠程 hash
	logrus.Info("Loading hash file from S3")
	hash, err := a.readRemoteHash(ctx)
	if err != nil {
		return err
	}
	logrus.Infof("Remote hash: %s", hash)

	// 下載並驗證 zip
	zipKey := fmt.Sprintf("edge-configs/%s/%s.zip", a.appName, hash)
	zipData, err := a.downloadAndVerifyZip(ctx, zipKey)
	if err != nil {
		return err
	}

	// 清空並解壓
	if err := a.cleanAndExtract(zipData); err != nil {
		return err
	}

	// 保存本地 hash 文件
	hashFilePath := filepath.Join(a.rootDir, fmt.Sprintf("%s.sha256", a.appName))
	if err := os.WriteFile(hashFilePath, []byte(hash), 0644); err != nil {
		return errx.Wrap(err).AppendMsg("failed to save local hash file").Err()
	}

	logrus.Info("Sync completed successfully")
	return nil
}

// calculateSHA256 計算數據的 SHA256 hash
func (a *app) calculateSHA256(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// calculateDirectoryHash 計算目錄的 SHA256 hash（基於所有文件內容）
func (a *app) calculateDirectoryHash(dirPath string) (string, error) {
	var fileHashes []string

	// 遍歷目錄收集所有文件的 hash
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳過目錄
		if info.IsDir() {
			return nil
		}

		// 讀取文件內容
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// 計算文件 hash
		fileHash := a.calculateSHA256(data)

		// 獲取相對路徑
		relPath, err := filepath.Rel(filepath.Dir(dirPath), path)
		if err != nil {
			return err
		}

		// 組合：相對路徑 + hash（確保路徑變化也會影響總 hash）
		combined := fmt.Sprintf("%s:%s", filepath.ToSlash(relPath), fileHash)
		fileHashes = append(fileHashes, combined)

		return nil
	})

	if err != nil {
		return "", err
	}

	// 排序確保順序一致
	sort.Strings(fileHashes)

	// 合併所有 hash 並計算最終 hash
	allHashes := strings.Join(fileHashes, "\n")
	finalHash := a.calculateSHA256([]byte(allHashes))

	return finalHash, nil
}

// calculateMD5 計算數據的 MD5 hash 和 base64 編碼
func (a *app) calculateMD5(data []byte) (base64Encoded string, hexString string) {
	hasher := md5.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), fmt.Sprintf("%x", sum)
}

// uploadZipIfNeeded 檢查 zip 是否需要上傳，如果需要則上傳
func (a *app) uploadZipIfNeeded(ctx context.Context, zipData []byte, key string) error {
	md5Sum, expectedETag := a.calculateMD5(zipData)

	// 檢查文件是否已存在
	headOutput, err := a.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})

	if err == nil && headOutput.ETag != nil {
		// 文件存在，檢查 ETag
		etag := strings.Trim(*headOutput.ETag, "\"")
		if etag == expectedETag {
			logrus.Infof("Zip file already exists with matching hash: %s", key)
			return nil
		}
		logrus.Warningf("Zip file exists but ETag mismatch: expected=%s, got=%s", expectedETag, etag)
	}

	// 上傳文件
	logrus.Infof("Uploading to S3: %s", key)
	putOutput, err := a.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:     aws.String(a.bucket),
		Key:        aws.String(key),
		Body:       bytes.NewReader(zipData),
		ContentMD5: aws.String(md5Sum),
	})
	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to upload zip").Err()
	}

	// 驗證上傳的 ETag（只對簡單上傳有效）
	if putOutput.ETag != nil {
		etag := strings.Trim(*putOutput.ETag, "\"")
		// 如果包含 "-"，表示是分片上傳，ETag 不是 MD5
		if strings.Contains(etag, "-") {
			logrus.Info("Multipart upload detected, skipping ETag validation")
		} else if etag != expectedETag {
			logrus.Warningf("ETag mismatch: expected=%s, got=%s", expectedETag, etag)
		} else {
			logrus.Info("Zip upload verified successfully")
		}
	}

	return nil
}

// uploadHashIfNeeded 檢查 hash 文件是否需要上傳，如果需要則上傳
func (a *app) uploadHashIfNeeded(ctx context.Context, hash, key string) error {
	// 檢查文件是否已存在
	_, err := a.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})

	if err == nil {
		// 文件存在，下載並比對內容
		getOutput, err := a.s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(a.bucket),
			Key:    aws.String(key),
		})
		if err == nil {
			defer getOutput.Body.Close()
			existingHash, err := io.ReadAll(getOutput.Body)
			if err == nil && strings.TrimSpace(string(existingHash)) == hash {
				logrus.Infof("Hash file already exists with matching content: %s", key)
				return nil
			}
		}
	}

	// 上傳文件
	logrus.Infof("Uploading hash file to S3: %s", key)
	if _, err := a.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(hash)),
	}); err != nil {
		return errx.Wrap(err).AppendMsg("failed to upload hash file").Err()
	}

	return nil
}

// readLocalHash 讀取本地 hash 文件
func (a *app) readLocalHash() (string, error) {
	hashFilePath := filepath.Join(a.rootDir, fmt.Sprintf("%s.sha256", a.appName))
	data, err := os.ReadFile(hashFilePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// readRemoteHash 讀取遠程 hash 文件
func (a *app) readRemoteHash(ctx context.Context) (string, error) {
	hashKey := fmt.Sprintf("edge-configs/%s.sha256", a.appName)
	result, err := a.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(hashKey),
	})
	if err != nil {
		return "", errx.Wrap(err).AppendMsg("failed to get remote hash file").Err()
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return "", errx.Wrap(err).AppendMsg("failed to read remote hash file").Err()
	}
	return strings.TrimSpace(string(data)), nil
}

// downloadAndVerifyZip 下載並驗證 zip 文件
func (a *app) downloadAndVerifyZip(ctx context.Context, key string) ([]byte, error) {
	logrus.Infof("Downloading from S3: %s", key)
	result, err := a.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(a.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to get zip").Err()
	}
	defer result.Body.Close()

	zipData, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, errx.Wrap(err).AppendMsg("failed to read zip").Err()
	}

	// 驗證完整性（只對簡單上傳有效）
	if result.ETag != nil {
		etag := strings.Trim(*result.ETag, "\"")
		// 如果包含 "-"，表示是分片上傳，ETag 不是 MD5
		if strings.Contains(etag, "-") {
			logrus.Info("Multipart upload detected, skipping ETag validation")
		} else {
			_, expectedETag := a.calculateMD5(zipData)
			if etag != expectedETag {
				return nil, errx.New(fmt.Sprintf("zip integrity check failed: expected=%s, got=%s", expectedETag, etag))
			}
			logrus.Info("Zip download verified successfully")
		}
	}

	return zipData, nil
}

// cleanAndExtract 清空目標目錄並解壓 zip
func (a *app) cleanAndExtract(zipData []byte) error {
	// 清空目標目錄
	appDir := filepath.Join(a.rootDir, a.appName)
	logrus.Infof("Cleaning target directory: %s", appDir)
	if err := os.RemoveAll(appDir); err != nil {
		return errx.Wrap(err).AppendMsg("failed to remove target directory").Err()
	}

	// 解壓
	logrus.Info("Extracting files")
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return errx.Wrap(err).AppendMsg("failed to open zip").Err()
	}

	for _, file := range zipReader.File {
		destPath := filepath.Join(a.rootDir, file.Name)

		// 安全檢查
		if !strings.HasPrefix(destPath, filepath.Clean(a.rootDir)+string(os.PathSeparator)) {
			return errx.New("illegal file path in zip")
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, file.Mode()); err != nil {
				return errx.Wrap(err).AppendMsgf("failed to create directory: %s", destPath).Err()
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return errx.Wrap(err).AppendMsgf("failed to create parent directory: %s", filepath.Dir(destPath)).Err()
		}

		srcFile, err := file.Open()
		if err != nil {
			return errx.Wrap(err).AppendMsgf("failed to open file in zip: %s", file.Name).Err()
		}

		destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			srcFile.Close()
			return errx.Wrap(err).AppendMsgf("failed to create file: %s", destPath).Err()
		}

		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()

		if err != nil {
			return errx.Wrap(err).AppendMsgf("failed to extract file: %s", destPath).Err()
		}
	}

	return nil
}
