package s3

import (
	"context"
	"crypto/x509"
	"errors"
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

const (
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// S3 provides operations on an S3-compatible bucket.
//
// Deprecated: Consumers should prefer defining a narrow interface in the
// package that consumes S3 behavior. This broad interface remains for
// compatibility with existing go-kit users.
type S3 interface {
	// PresignGetURL returns a presigned URL for a get-object operation.
	PresignGetURL(ctx context.Context, bucket, key string, expire time.Duration) (*url.URL, error)
	// PresignPutURL returns a presigned URL and headers for a put-object operation.
	PresignPutURL(
		ctx context.Context,
		bucket string,
		key string,
		contentType string,
		sha256 string,
		size int,
		expire time.Duration,
	) (*url.URL, http.Header, error)
	// GetObject gets an object from bucket.
	GetObject(ctx context.Context, bucket, key string, opts minio.GetObjectOptions) (*minio.Object, error)
	// PutObject uploads an object to bucket.
	PutObject(
		ctx context.Context,
		bucket string,
		key string,
		contentType string,
		size int,
		body io.Reader,
		opts minio.PutObjectOptions,
	) (minio.UploadInfo, error)
	// CopyObject copies an object from srcKey to destKey in bucket.
	CopyObject(ctx context.Context, bucket, srcKey, destKey string) (minio.UploadInfo, error)
	// DeleteObject deletes an object from bucket.
	DeleteObject(ctx context.Context, bucket, key string) error
	// StatObject stats an object in bucket.
	StatObject(ctx context.Context, bucket, key string) (minio.ObjectInfo, error)
}

// MinioS3Impl provides operations on AWS S3 and MinIO.
type MinioS3Impl struct {
	client *minio.Client
}

var _ S3 = (*MinioS3Impl)(nil)

// PresignGetURL returns a presigned URL for a get-object operation.
func (m *MinioS3Impl) PresignGetURL(ctx context.Context, bucket, key string, expire time.Duration) (*url.URL, error) {
	out, err := m.client.PresignedGetObject(ctx, bucket, key, expire, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to presign get object: %w", err)
	}
	return out, nil
}

// PresignPutURL returns a presigned URL and headers for a put-object operation.
func (m *MinioS3Impl) PresignPutURL(
	ctx context.Context,
	bucket string,
	key string,
	contentType string,
	sha256 string,
	size int,
	expire time.Duration,
) (*url.URL, http.Header, error) {
	headers := http.Header{
		"Content-Type":          []string{contentType},
		"Content-Length":        []string{fmt.Sprint(size)},
		"x-amz-checksum-sha256": []string{sha256},
	}
	out, err := m.client.PresignHeader(ctx, http.MethodPut, bucket, key, expire, nil, headers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to presign put object: %w", err)
	}
	return out, headers, nil
}

// GetObject gets an object from bucket.
func (m *MinioS3Impl) GetObject(ctx context.Context, bucket, key string, opts minio.GetObjectOptions) (*minio.Object, error) {
	out, err := m.client.GetObject(ctx, bucket, key, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	return out, nil
}

// PutObject uploads an object to bucket.
func (m *MinioS3Impl) PutObject(
	ctx context.Context,
	bucket string,
	key string,
	contentType string,
	size int,
	body io.Reader,
	opts minio.PutObjectOptions,
) (minio.UploadInfo, error) {
	opts.ContentType = contentType
	out, err := m.client.PutObject(ctx, bucket, key, body, int64(size), opts)
	if err != nil {
		return out, fmt.Errorf("failed to put object: %w", err)
	}
	return out, nil
}

// CopyObject copies an object from srcKey to destKey in bucket.
func (m *MinioS3Impl) CopyObject(ctx context.Context, bucket, srcKey, destKey string) (minio.UploadInfo, error) {
	copySourceOpts := minio.CopySrcOptions{
		Bucket: bucket,
		Object: srcKey,
	}
	copyDestOpts := minio.CopyDestOptions{
		Bucket: bucket,
		Object: destKey,
	}
	out, err := m.client.CopyObject(ctx, copyDestOpts, copySourceOpts)
	if err != nil {
		return out, fmt.Errorf("failed to copy object: %w", err)
	}
	return out, nil
}

// DeleteObject deletes an object from bucket.
func (m *MinioS3Impl) DeleteObject(ctx context.Context, bucket, key string) error {
	if err := m.client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}
	return nil
}

// StatObject stats an object in bucket.
func (m *MinioS3Impl) StatObject(ctx context.Context, bucket, key string) (minio.ObjectInfo, error) {
	info, err := m.client.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if IsNoSuchKeyErr(err) {
		return minio.ObjectInfo{}, ErrNoSuchKey
	}
	if err != nil {
		return minio.ObjectInfo{}, fmt.Errorf("failed to stat object: %w", err)
	}
	return info, nil
}

// NewMinioS3Impl creates a new MinioS3Impl.
//
// It returns S3 for backward compatibility with earlier releases.
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

// NewMinioS3ImplWithSTS creates a new MinioS3Impl with STSProvider.
//
// It returns S3 for backward compatibility with earlier releases.
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

// DefaultSTSTokenExpirySeconds is the default expiry duration for an STS token.
const DefaultSTSTokenExpirySeconds = 3 * 24 * 60 * 60 // Three days

// STSProvider provides temporary credentials.
type STSProvider = credentials.Provider

// WindowedSTSIdentityProvider provides temporary credentials with a windowed expiry.
type WindowedSTSIdentityProvider struct {
	Window time.Duration
	*credentials.STSWebIdentity
}

// Retrieve returns the credential value.
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
	if expirySeconds <= 0 {
		return nil, fmt.Errorf("sts token expiry seconds must be positive")
	}
	caCert, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account ca certificate: %w", err)
	}
	token, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}

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

// IsNoSuchKeyErr checks if the error is a NoSuchKey error.
func IsNoSuchKeyErr(err error) bool {
	if minioError := minio.ToErrorResponse(err); minioError.Code == "NoSuchKey" {
		return true
	}
	return false
}

// ErrNoSuchKey reports a missing S3 object.
var ErrNoSuchKey = errors.New("no such key")
