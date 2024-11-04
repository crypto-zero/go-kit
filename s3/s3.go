package s3

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 provides operations on s3 bucket
type S3 interface {
	// PresignGetURL returns a presigned url for get object operation
	PresignGetURL(ctx context.Context, bucket, key string, expire time.Duration,
	) (*url.URL, error)
	// PresignPutURL returns a presigned url for put object operation
	PresignPutURL(ctx context.Context, bucket, key, contentType, sha256 string,
		size int, expire time.Duration) (*url.URL, http.Header, error)
	// GetObject gets an object from bucket
	GetObject(ctx context.Context, bucket, key string, opt minio.GetObjectOptions) (
		*minio.Object, error)
	// PutObject uploads an object to bucket
	PutObject(ctx context.Context, bucket, key, contentType string, size int,
		body io.Reader, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	// CopyObject copies an object from srcKey to destKey
	CopyObject(ctx context.Context, bucket, srcKey, destKey string) (out minio.UploadInfo,
		err error)
	// DeleteObject deletes an object from bucket
	DeleteObject(ctx context.Context, bucket, key string) error
}

// MinioS3Impl provides operations on AWS/s3 and minio for implementing S3 interface
type MinioS3Impl struct {
	client *minio.Client
}

func (m *MinioS3Impl) PresignGetURL(ctx context.Context, bucket, key string, expire time.Duration,
) (out *url.URL, err error) {
	if out, err = m.client.PresignedGetObject(ctx, bucket, key, expire, nil); err != nil {
		return nil, fmt.Errorf("failed to presign get object: %w", err)
	}
	return
}

func (m *MinioS3Impl) PresignPutURL(ctx context.Context, bucket, key, contentType,
	sha256 string, size int, expire time.Duration,
) (out *url.URL, headers http.Header, err error) {
	headers = http.Header{
		"Content-Type":          []string{contentType},
		"Content-Length":        []string{fmt.Sprint(size)},
		"x-amz-checksum-sha256": []string{sha256},
	}
	out, err = m.client.PresignHeader(ctx, http.MethodPut, bucket, key, expire, nil, headers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to presign put object: %w", err)
	}
	return
}

func (m *MinioS3Impl) GetObject(ctx context.Context, bucket, key string, opts minio.GetObjectOptions,
) (out *minio.Object, err error) {
	if out, err = m.client.GetObject(ctx, bucket, key, opts); err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	return
}

func (m *MinioS3Impl) PutObject(ctx context.Context, bucket, key, contentType string,
	size int, body io.Reader, opts minio.PutObjectOptions,
) (out minio.UploadInfo, err error) {
	opts.ContentType = contentType
	if out, err = m.client.PutObject(ctx, bucket, key, body, int64(size), opts); err != nil {
		return out, fmt.Errorf("failed to put object: %w", err)
	}
	return
}

func (m *MinioS3Impl) CopyObject(ctx context.Context, bucket, srcKey, destKey string) (
	out minio.UploadInfo, err error,
) {
	copySourceOpts := minio.CopySrcOptions{
		Bucket: bucket,
		Object: srcKey,
	}
	copyDestOpts := minio.CopyDestOptions{
		Bucket: bucket,
		Object: destKey,
	}
	if out, err = m.client.CopyObject(ctx, copyDestOpts, copySourceOpts); err != nil {
		return out, fmt.Errorf("failed to copy object: %w", err)
	}
	return
}

func (m *MinioS3Impl) DeleteObject(ctx context.Context, bucket, key string) error {
	if err := m.client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}
	return nil
}

// NewMinioS3Impl creates a new MinioS3Impl
func NewMinioS3Impl(endpoint, accessKeyID, secretAccessKey, sessionToken string) (S3, error) {
	return NewMinioS3ImplWithSTS(endpoint, &credentials.Static{
		Value: credentials.Value{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			SessionToken:    sessionToken,
			SignerType:      credentials.SignatureV4,
		},
	})
}

// NewMinioS3ImplWithSTS creates a new MinioS3Impl with STSProvider
func NewMinioS3ImplWithSTS(endpoint string, sts STSProvider) (S3, error) {
	uri, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint: %w", err)
	}

	isHttps := uri.Scheme == "https"
	uri.Scheme = ""
	endpoint = uri.String()
	endpoint = strings.TrimLeft(endpoint, "//")

	opt := &minio.Options{
		Creds:  credentials.New(sts),
		Secure: isHttps,
	}
	c, err := minio.New(endpoint, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	return &MinioS3Impl{client: c}, nil
}

// DefaultSTSTokenExpirySeconds is the default expiry duration for STS token
const DefaultSTSTokenExpirySeconds = 3 * 24 * 60 * 60 // Three days

// STSProvider provides temporary credentials
type STSProvider = credentials.Provider

// WindowedSTSIdentityProvider provides temporary credentials with a windowed expiry
type WindowedSTSIdentityProvider struct {
	Window time.Duration
	*credentials.STSWebIdentity
}

// Retrieve returns the credential value
func (w *WindowedSTSIdentityProvider) Retrieve() (credentials.Value, error) {
	value, err := w.STSWebIdentity.Retrieve()
	if err != nil {
		return credentials.Value{}, err
	}
	w.SetExpiration(w.Expiration(), w.Window)
	return value, nil
}

// NewMinioSTSProviderImpl creates a new instance of the STSProvider.
func NewMinioSTSProviderImpl(endpoint string, expirySeconds int, expiryWindow time.Duration,
) (STSProvider, error) {
	// Read kubernetes service account ca certificate file
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read service account ca certificate: %w", err)
	}
	// Read kubernetes service account token file
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}

	// Create an HttpTransport with the service account token and ca certificate
	transport, err := minio.DefaultTransport(true)
	if err != nil {
		return nil, fmt.Errorf("failed to create minio transport: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %w", err)
	}
	if transport.TLSClientConfig.RootCAs == nil {
		transport.TLSClientConfig.RootCAs = pool
	}
	if ok := transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append kubernetes service account ca certificate")
	}

	// Create sts credentials
	credential := &credentials.STSWebIdentity{
		Client:      &http.Client{Transport: transport},
		STSEndpoint: endpoint,
		GetWebIDTokenExpiry: func() (*credentials.WebIdentityToken, error) {
			return &credentials.WebIdentityToken{
				Token:  string(token),
				Expiry: expirySeconds,
			}, nil
		},
		RoleARN: "",
	}
	return &WindowedSTSIdentityProvider{Window: expiryWindow, STSWebIdentity: credential}, nil
}

// IsNoSuchKeyErr checks if the error is a NoSuchKey error
func IsNoSuchKeyErr(err error) bool {
	if minioError := minio.ToErrorResponse(err); minioError.Code == "NoSuchKey" {
		return true
	}
	return false
}
