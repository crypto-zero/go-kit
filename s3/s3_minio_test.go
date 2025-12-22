package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/suite"
)

func TestMinio(t *testing.T) {
	endpoint, bucket := os.Getenv("MINIO_ENDPOINT"), os.Getenv("MINIO_BUCKET")
	keyID, key := os.Getenv("MINIO_ACCESS_KEY_ID"), os.Getenv("MINIO_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("MINIO_SESSION_TOKEN")
	if endpoint == "" || bucket == "" || keyID == "" || key == "" {
		t.Skip("MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY_ID, MINIO_SECRET_ACCESS_KEY are required")
		return
	}
	suite.Run(t, &TestMinioSuite{
		endpoint:        endpoint,
		bucket:          bucket,
		accessKeyID:     keyID,
		secretAccessKey: key,
		sessionToken:    sessionToken,
	})
}

type TestMinioSuite struct {
	suite.Suite

	endpoint        string
	bucket          string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string

	ctx context.Context
	s3  S3
}

func (s *TestMinioSuite) SetupSuite() {
	s.ctx = context.Background()
	s3, err := NewMinioS3Impl(
		s.endpoint, s.accessKeyID, s.secretAccessKey, s.sessionToken,
	)
	if err != nil {
		s.T().Fatalf("failed to create service: %v", err)
		return
	}
	s.s3 = s3

	// Create test files
	r := s.Require()
	object, err := s.s3.PutObject(s.ctx, s.bucket, ObjectKey, "text/plain", len(ObjectBody),
		bytes.NewReader([]byte(ObjectBody)), minio.PutObjectOptions{})
	if err != nil {
		s.T().Fatalf("failed to create test object: %v", err)
		return
	}
	r.NotNil(object, "test object is nil")
}

func (s *TestMinioSuite) TearDownSuite() {
	r := s.Require()
	ctx := context.Background()
	err := s.s3.DeleteObject(ctx, s.bucket, ObjectKey)
	r.NoError(err, "failed to delete object")
	err = s.s3.DeleteObject(ctx, s.bucket, ObjectKey+"-copy")
	r.NoError(err, "failed to delete copied object")
}

const (
	ObjectKey  = "go-suite-test/test.txt"
	ObjectBody = "Hello, World!"
)

func (s *TestMinioSuite) TestGetObject() {
	r := s.Require()
	ctx := context.Background()
	object, err := s.s3.GetObject(ctx, s.bucket, ObjectKey, minio.GetObjectOptions{})
	r.NoError(err, "failed to get object")
	r.NotNil(object, "object is nil")
	r.NotEmpty(object, "object is empty")
	_, err = object.Stat()
	r.NoError(err, "failed to stat object")

}

func (s *TestMinioSuite) TestStatObject() {
	r := s.Require()
	ctx := context.Background()
	// Test get object with certainly not an existed key
	objectInfo, err := s.s3.StatObject(ctx, s.bucket, ObjectKey+"-not-exist")
	// When an object is not found, minio-go returns no error
	r.NotNil(objectInfo, "object should not be nil")
	r.EqualError(err, ErrNoSuchKey.Error(), "stat object with certainly not exist key should return not exists error")
}

func (s *TestMinioSuite) TestPresignedGetObject() {
	r := s.Require()
	ctx := context.Background()
	url, err := s.s3.PresignGetURL(ctx, s.bucket, ObjectKey, time.Minute)
	r.NoError(err, "failed to presign get object")
	r.NotNil(url, "url is nil")
	reply, err := http.Get(url.String())
	r.NoError(err, "failed to get object from presigned url")
	r.NotNil(reply, "reply is nil")
	defer reply.Body.Close()
	data, err := io.ReadAll(reply.Body)
	r.NoError(err, "failed to read object from presigned url")
	r.Equal(ObjectBody, string(data), "object body mismatch")
}

func (s *TestMinioSuite) TestPresignedPutObject() {
	r := s.Require()
	ctx := context.Background()
	contentType := "text/plain"
	digest := sha256.Sum256([]byte(ObjectBody))
	hash := base64.StdEncoding.EncodeToString(digest[:])
	size := len(ObjectBody)
	url, headers, err := s.s3.PresignPutURL(ctx, s.bucket, ObjectKey, contentType,
		hash, size, time.Minute)
	r.NoError(err, "failed to presign put object")
	r.NotNil(url, "url is nil")
	r.NotNil(headers, "headers is nil")
	urlString := url.String()
	urlString = strings.Replace(urlString, "staging-dowhat.oss-cn-shenzhen.aliyuncs.com", "staging-app-storage-bucket.dowhat.me", 1)

	s.T().Log("urlString: ", urlString)
	req, err := http.NewRequest(http.MethodPut, urlString, bytes.NewReader([]byte(ObjectBody)))
	r.NoError(err, "failed to create put request")
	req.Header = headers
	req.Body = io.NopCloser(bytes.NewReader([]byte(ObjectBody)))
	reply, err := http.DefaultClient.Do(req)
	r.NoError(err, "failed to put object to presigned url")
	r.NotNil(reply, "reply is nil")
	defer reply.Body.Close()
	data, err := io.ReadAll(reply.Body)
	r.NoError(err, "failed to read reply body")
	r.Empty(data, "reply body should be empty")
	r.Equal(http.StatusOK, reply.StatusCode, "put object failed")
}

func (s *TestMinioSuite) TestCopyObject() {
	r := s.Require()
	ctx := context.Background()
	object, err := s.s3.CopyObject(ctx, s.bucket, ObjectKey, ObjectKey+"-copy")
	r.NoError(err, "failed to copy object")
	r.NotNil(object, "object is nil")
	r.NotEmpty(object, "object is empty")
}

func (s *TestMinioSuite) TestCopyObjectWithSameETag() {
	r := s.Require()
	ctx := context.Background()
	original, err := s.s3.GetObject(ctx, s.bucket, ObjectKey, minio.GetObjectOptions{})
	r.NoError(err, "failed to get object")
	r.NotNil(original, "object is nil")
	r.NotEmpty(original, "object is empty")
	originStat, err := original.Stat()
	r.NoError(err, "failed to stat object")
	r.NotNil(originStat, "object stat is nil")
	object, err := s.s3.CopyObject(ctx, s.bucket, ObjectKey, ObjectKey+"-copy")
	r.NoError(err, "failed to copy object")
	r.NotNil(object, "object is nil")
	r.NotEmpty(object, "object is empty")
	newObject, err := s.s3.GetObject(ctx, s.bucket, ObjectKey+"-copy", minio.GetObjectOptions{})
	r.NoError(err, "failed to get copied object")
	r.NotNil(newObject, "copied object is nil")
	r.NotEmpty(newObject, "copied object is empty")
	newObjectStat, err := newObject.Stat()
	r.NoError(err, "failed to stat copied object")
	r.NotNil(newObjectStat, "copied object stat is nil")
	r.Equal(originStat.ETag, newObjectStat.ETag, "copied object ETag mismatch")
}
