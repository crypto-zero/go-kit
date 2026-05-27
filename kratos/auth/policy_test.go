package auth

import (
	"testing"

	authv1 "github.com/crypto-zero/go-kit/proto/kit/auth/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestOperationPolicyRegistersPublicProtoMethods(t *testing.T) {
	publicOpts := &descriptorpb.MethodOptions{}
	proto.SetExtension(publicOpts, authv1.E_Public, true)
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  proto.String("proto3"),
		Name:    proto.String("test/auth/v1/service.proto"),
		Package: proto.String("test.auth.v1"),
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("AuthService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       proto.String("Login"),
					InputType:  proto.String(".test.auth.v1.LoginRequest"),
					OutputType: proto.String(".test.auth.v1.LoginResponse"),
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
			{Name: proto.String("LoginRequest")},
			{Name: proto.String("LoginResponse")},
			{Name: proto.String("ProfileRequest")},
			{Name: proto.String("ProfileResponse")},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}

	policy := NewOperationPolicy(WithPublicFromProtoFiles(fd))

	if policy.RequiresAuth("/test.auth.v1.AuthService/Login") {
		t.Fatal("Login should be public from proto option")
	}
	if !policy.RequiresAuth("/test.auth.v1.AuthService/Profile") {
		t.Fatal("Profile should require auth when untagged")
	}
}

func TestOperationPolicyManualPublicOperations(t *testing.T) {
	policy := NewOperationPolicy(WithPublicOperations("/healthz", "/readyz"))

	if policy.RequiresAuth("/healthz") {
		t.Fatal("/healthz should be public")
	}
	if !policy.RequiresAuth("/v1/private") {
		t.Fatal("/v1/private should require auth")
	}
}
