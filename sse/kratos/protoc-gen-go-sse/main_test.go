package main

import (
	"strings"
	"testing"

	ssev1 "github.com/crypto-zero/go-kit/proto/kit/sse/v1"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func TestGenerateFileUsesDefaultHTTPStreamBinding(t *testing.T) {
	req := testCodeGeneratorRequest(t)
	plugin, err := protogen.Options{}.New(req)
	if err != nil {
		t.Fatalf("protogen.New: %v", err)
	}

	for _, file := range plugin.Files {
		if file.Generate {
			generateFile(plugin, file)
		}
	}

	resp := plugin.Response()
	if len(resp.File) != 1 {
		t.Fatalf("generated files = %d, want 1", len(resp.File))
	}
	got := resp.File[0].GetContent()
	if strings.Contains(got, "RegisterHTTPStreamBound") {
		t.Fatalf("generated code uses bound registration:\n%s", got)
	}
	if count := strings.Count(got, "const OperationLiveServiceWatchSSE"); count != 1 {
		t.Fatalf("operation const count = %d, want 1:\n%s", count, got)
	}
	if count := strings.Count(got, "func _LiveService_Watch_SSE_Register"); count != 1 {
		t.Fatalf("register function count = %d, want 1:\n%s", count, got)
	}
	for _, want := range []string{
		`RegisterHTTPStream(s, "POST", "/v1/watch", OperationLiveServiceWatchSSE, srv.Watch, opts...)`,
		`RegisterHTTPStream(s, "GET", "/v1/watch:tail", OperationLiveServiceWatchSSE, srv.Watch, opts...)`,
		`type LiveServiceSSEClient interface`,
		`func NewLiveServiceSSEClient(client *kratos.HTTPClient) LiveServiceSSEClient`,
		`func (c *liveServiceSSEClient) Watch(ctx context.Context, in *WatchRequest, opts ...kratos.HTTPStreamCallOption) (*sse.Reader, error)`,
		`path := binding.EncodeURL(pattern, in, false)`,
		`return c.cc.Open(ctx, "POST", path, in, opts...)`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated code missing %q:\n%s", want, got)
		}
	}
}

func TestBodyExpr(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{body: "*", want: "in"},
		{body: "payload", want: "in.Payload"},
		{body: "filter_box.zoom_level", want: "in.FilterBox.ZoomLevel"},
	} {
		if got := bodyExpr(tc.body); got != tc.want {
			t.Fatalf("bodyExpr(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func testCodeGeneratorRequest(t *testing.T) *pluginpb.CodeGeneratorRequest {
	t.Helper()

	opts := &descriptorpb.MethodOptions{}
	proto.SetExtension(opts, ssev1.E_ServerSentEvent, true)
	proto.SetExtension(opts, annotations.E_Http, &annotations.HttpRule{
		Pattern: &annotations.HttpRule_Post{Post: "/v1/watch"},
		Body:    "*",
		AdditionalBindings: []*annotations.HttpRule{{
			Pattern: &annotations.HttpRule_Get{Get: "/v1/watch:tail"},
		}},
	})

	return &pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{"test/v1/live.proto"},
		ProtoFile: []*descriptorpb.FileDescriptorProto{{
			Syntax:  proto.String("proto3"),
			Name:    proto.String("test/v1/live.proto"),
			Package: proto.String("test.v1"),
			Options: &descriptorpb.FileOptions{
				GoPackage: proto.String("example.com/test/v1;testv1"),
			},
			MessageType: []*descriptorpb.DescriptorProto{{
				Name: proto.String("WatchRequest"),
			}, {
				Name: proto.String("WatchResponse"),
			}},
			Service: []*descriptorpb.ServiceDescriptorProto{{
				Name: proto.String("LiveService"),
				Method: []*descriptorpb.MethodDescriptorProto{{
					Name:       proto.String("Watch"),
					InputType:  proto.String(".test.v1.WatchRequest"),
					OutputType: proto.String(".test.v1.WatchResponse"),
					Options:    opts,
				}},
			}},
		}},
	}
}
