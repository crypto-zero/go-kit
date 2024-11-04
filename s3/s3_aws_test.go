package s3

/*
import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TestAWSSuite struct {
	suite.Suite

	s3       S3
	bucket   string
	name     string
	sha256   string
	fileSize int
}

func (s *TestAWSSuite) SetupSuite() {
	region, keyID, key := os.Getenv("AWS_REGION"), os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY")
	bucket, name := os.Getenv("AWS_BUCKET"), os.Getenv("AWS_OBJECT_NAME")
	sha256 := os.Getenv("AWS_OBJECT_SHA256")
	fileSize := os.Getenv("AWS_OBJECT_SIZE")
	if region == "" || keyID == "" || key == "" || bucket == "" || name == "" ||
		sha256 == "" || fileSize == "" {
		s.T().Skip("AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_BUCKET, " +
			"AWS_OBJECT_NAME, AWS_OBJECT_SHA256, AWS_OBJECT_SIZE must be set")
		return
	}
	size, err := strconv.Atoi(fileSize)
	if err != nil {
		s.T().Fatalf("failed to convert file size: %v", err)
		return
	}
	ctx := context.Background()
	svc, err := NewS3(ctx, region, keyID, key)
	if err != nil {
		s.T().Fatalf("failed to create service: %v", err)
		return
	}
	s.s3, s.fileSize = svc, size
	s.bucket, s.name, s.sha256 = bucket, name, sha256
}

func (s *TestAWSSuite) TestPresignGetURL() {
	r := s.Require()
	ctx := context.Background()
	request, err := s.s3.PresignGetURL(ctx, s.bucket, s.name, 30*time.Second)
	r.NoError(err)
	r.NotNil(request)
	r.NotEmpty(request.URL)
	s.T().Log("presigned get object request: ", request)
}

func (s *TestAWSSuite) TestPresignPutURL() {
	r := s.Require()
	ctx := context.Background()
	request, err := s.s3.PresignPutURL(ctx, s.bucket, s.name, "text/html",
		s.sha256, s.fileSize, 30*time.Second)
	r.NoError(err)
	r.NotNil(request)
	r.NotEmpty(request.URL)
	s.T().Log("presigned put object request: ", request)
}

func (s *TestAWSSuite) TestMoveObject() {
	r := s.Require()
	ctx := context.Background()
	err := s.s3.MoveObject(ctx, s.bucket, "file-not-exists", "file-not-exists2")
	r.Error(err)
	r.True(IsNoSuchKeyErr(err))
	s.T().Log("move object error: ", err)
}

func (s *TestAWSSuite) TestDeleteObject() {
	r := s.Require()
	ctx := context.Background()
	err := s.s3.DeleteObject(ctx, s.bucket, "file-not-exists")
	r.Nil(err)
}

func TestAWS(t *testing.T) {
	suite.Run(t, new(TestAWSSuite))
}
*/
