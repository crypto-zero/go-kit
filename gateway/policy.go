// Package gateway provides helpers for grpc-gateway based HTTP servers.
package gateway

import (
	"net/http"
	"strings"

	authv1 "github.com/crypto-zero/go-kit/proto/kit/auth/v1"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// HTTPRule identifies one grpc-gateway route.
type HTTPRule struct {
	Method  string
	Pattern string
}

// OperationPolicy reports whether an operation or HTTP route should run
// through authentication middleware.
type OperationPolicy struct {
	publicOperations map[string]struct{}
	publicHTTPRules  map[HTTPRule]struct{}
}

// OperationPolicyOption configures an OperationPolicy.
type OperationPolicyOption func(*OperationPolicy)

// NewOperationPolicy constructs an auth policy from proto descriptors and
// optional manually registered operations/routes.
func NewOperationPolicy(opts ...OperationPolicyOption) *OperationPolicy {
	p := &OperationPolicy{
		publicOperations: make(map[string]struct{}),
		publicHTTPRules:  make(map[HTTPRule]struct{}),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithPublicOperations marks explicit gRPC operation names as public.
func WithPublicOperations(ops ...string) OperationPolicyOption {
	return func(p *OperationPolicy) {
		for _, op := range ops {
			p.publicOperations[op] = struct{}{}
		}
	}
}

// WithPublicHTTPRules marks explicit HTTP method/path-pattern pairs as public.
func WithPublicHTTPRules(rules ...HTTPRule) OperationPolicyOption {
	return func(p *OperationPolicy) {
		for _, rule := range rules {
			p.publicHTTPRules[normalizeHTTPRule(rule)] = struct{}{}
		}
	}
}

// WithPublicFromProtoFiles scans file descriptors for methods tagged with
// `(kit.auth.v1.public) = true` and registers their gRPC operation name plus
// google.api.http routes, when present.
func WithPublicFromProtoFiles(files ...protoreflect.FileDescriptor) OperationPolicyOption {
	return func(p *OperationPolicy) {
		for _, fd := range files {
			registerPublicFromFile(p, fd)
		}
	}
}

// RequiresAuth reports whether operation should run through authentication.
func (p *OperationPolicy) RequiresAuth(operation string) bool {
	if p == nil {
		return true
	}
	_, ok := p.publicOperations[operation]
	return !ok
}

// RequiresAuthHTTP reports whether a grpc-gateway HTTP route should run
// through authentication.
func (p *OperationPolicy) RequiresAuthHTTP(method, pattern string) bool {
	if p == nil {
		return true
	}
	_, ok := p.publicHTTPRules[normalizeHTTPRule(HTTPRule{Method: method, Pattern: pattern})]
	return !ok
}

// OperationName returns the gRPC operation string for a proto method.
func OperationName(m protoreflect.MethodDescriptor) string {
	return "/" + string(m.Parent().FullName()) + "/" + string(m.Name())
}

func registerPublicFromFile(p *OperationPolicy, fd protoreflect.FileDescriptor) {
	services := fd.Services()
	for i := range services.Len() {
		methods := services.Get(i).Methods()
		for j := range methods.Len() {
			m := methods.Get(j)
			if !methodIsPublic(m) {
				continue
			}
			p.publicOperations[OperationName(m)] = struct{}{}
			for _, rule := range methodHTTPRules(m) {
				p.publicHTTPRules[normalizeHTTPRule(rule)] = struct{}{}
			}
		}
	}
}

func methodIsPublic(m protoreflect.MethodDescriptor) bool {
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil || !proto.HasExtension(opts, authv1.E_Public) {
		return false
	}
	v, ok := proto.GetExtension(opts, authv1.E_Public).(bool)
	return ok && v
}

func methodHTTPRules(m protoreflect.MethodDescriptor) []HTTPRule {
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil || !proto.HasExtension(opts, annotations.E_Http) {
		return nil
	}
	rule, ok := proto.GetExtension(opts, annotations.E_Http).(*annotations.HttpRule)
	if !ok || rule == nil {
		return nil
	}
	return appendHTTPRules(nil, rule)
}

func appendHTTPRules(out []HTTPRule, rule *annotations.HttpRule) []HTTPRule {
	if route, ok := httpRuleRoute(rule); ok {
		out = append(out, route)
	}
	for _, binding := range rule.AdditionalBindings {
		out = appendHTTPRules(out, binding)
	}
	return out
}

func httpRuleRoute(rule *annotations.HttpRule) (HTTPRule, bool) {
	switch pattern := rule.Pattern.(type) {
	case *annotations.HttpRule_Get:
		return HTTPRule{Method: http.MethodGet, Pattern: pattern.Get}, true
	case *annotations.HttpRule_Put:
		return HTTPRule{Method: http.MethodPut, Pattern: pattern.Put}, true
	case *annotations.HttpRule_Post:
		return HTTPRule{Method: http.MethodPost, Pattern: pattern.Post}, true
	case *annotations.HttpRule_Delete:
		return HTTPRule{Method: http.MethodDelete, Pattern: pattern.Delete}, true
	case *annotations.HttpRule_Patch:
		return HTTPRule{Method: http.MethodPatch, Pattern: pattern.Patch}, true
	case *annotations.HttpRule_Custom:
		if pattern.Custom == nil {
			return HTTPRule{}, false
		}
		return HTTPRule{Method: pattern.Custom.Kind, Pattern: pattern.Custom.Path}, true
	default:
		return HTTPRule{}, false
	}
}

func normalizeHTTPRule(rule HTTPRule) HTTPRule {
	return HTTPRule{
		Method:  strings.ToUpper(rule.Method),
		Pattern: normalizeHTTPPattern(rule.Pattern),
	}
}

func normalizeHTTPPattern(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '{' {
			b.WriteByte(pattern[i])
			continue
		}
		end := strings.IndexByte(pattern[i:], '}')
		if end == -1 {
			b.WriteString(pattern[i:])
			break
		}
		end += i
		capture := pattern[i+1 : end]
		b.WriteByte('{')
		b.WriteString(capture)
		if !strings.Contains(capture, "=") {
			b.WriteString("=*")
		}
		b.WriteByte('}')
		i = end
	}
	return b.String()
}
