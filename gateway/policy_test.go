package gateway

import (
	"net/http"
	"testing"

	authv1 "github.com/crypto-zero/go-kit/proto/kit/auth/v1"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestOperationPolicyRegistersPublicProtoHTTPRules(t *testing.T) {
	publicOpts := &descriptorpb.MethodOptions{}
	proto.SetExtension(publicOpts, authv1.E_Public, true)
	proto.SetExtension(publicOpts, annotations.E_Http, &annotations.HttpRule{
		Pattern: &annotations.HttpRule_Post{Post: "/v1/auth:verify"},
		AdditionalBindings: []*annotations.HttpRule{{
			Pattern: &annotations.HttpRule_Get{Get: "/v1/auth/verify"},
		}},
	})
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  proto.String("proto3"),
		Name:    proto.String("test/auth/v1/service.proto"),
		Package: proto.String("test.auth.v1"),
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("AuthService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       proto.String("Verify"),
					InputType:  proto.String(".test.auth.v1.VerifyRequest"),
					OutputType: proto.String(".test.auth.v1.VerifyResponse"),
					Options:    publicOpts,
				},
				{
					Name:       proto.String("Profile"),
					InputType:  proto.String(".test.auth.v1.ProfileRequest"),
					OutputType: proto.String(".test.auth.v1.ProfileResponse"),
				},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("VerifyRequest")},
			{Name: proto.String("VerifyResponse")},
			{Name: proto.String("ProfileRequest")},
			{Name: proto.String("ProfileResponse")},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}

	policy := NewOperationPolicy(WithPublicFromProtoFiles(fd))

	if policy.RequiresAuth("/test.auth.v1.AuthService/Verify") {
		t.Fatal("Verify should be public from proto option")
	}
	if policy.RequiresAuthHTTP(http.MethodPost, "/v1/auth:verify") {
		t.Fatal("POST /v1/auth:verify should be public from google.api.http")
	}
	if policy.RequiresAuthHTTP(http.MethodGet, "/v1/auth/verify") {
		t.Fatal("additional HTTP binding should be public")
	}
	if !policy.RequiresAuthHTTP(http.MethodGet, "/v1/private") {
		t.Fatal("untagged route should require auth")
	}
}

func TestOperationPolicyManualPublicHTTPRules(t *testing.T) {
	policy := NewOperationPolicy(WithPublicHTTPRules(HTTPRule{
		Method:  http.MethodGet,
		Pattern: "/v1/users/{user_id}/profile",
	}))

	if policy.RequiresAuthHTTP(http.MethodGet, "/v1/users/{user_id=*}/profile") {
		t.Fatal("GET profile route should be public with grpc-gateway canonical pattern")
	}
	if !policy.RequiresAuthHTTP(http.MethodPost, "/v1/users/{user_id=*}/profile") {
		t.Fatal("POST profile route should still require auth")
	}
}
