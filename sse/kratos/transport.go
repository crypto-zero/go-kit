package kratos

import (
	"context"
	"net/http"

	ktransport "github.com/go-kratos/kratos/v2/transport"
)

var (
	_ Transporter         = (*Transport)(nil)
	_ ResponseTransporter = (*Transport)(nil)
)

// Transporter extends Kratos' transport.Transporter with the raw HTTP
// request, matching the shape that github.com/go-kratos/kratos/v2/transport/http
// exposes for its own transport.
type Transporter interface {
	ktransport.Transporter
	Request() *http.Request
	PathTemplate() string
}

// ResponseTransporter additionally exposes the response writer, for
// handlers that need to wrap or inspect it (e.g. SSE).
type ResponseTransporter interface {
	Transporter
	Response() http.ResponseWriter
}

// Transport is the SSE transport context attached to each request.
type Transport struct {
	endpoint     string
	operation    string
	pathTemplate string
	request      *http.Request
	response     http.ResponseWriter
	reqHeader    headerCarrier
	replyHeader  headerCarrier
}

// Kind reports the transport kind, KindSSE.
func (t *Transport) Kind() ktransport.Kind { return KindSSE }

// Endpoint reports the server's advertised endpoint.
func (t *Transport) Endpoint() string { return t.endpoint }

// Operation reports the matched route template (e.g. "/v1/chat:stream").
// Middleware that needs a more specific operation can override it via
// SetOperation.
func (t *Transport) Operation() string { return t.operation }

// PathTemplate reports the matched ServeMux pattern.
func (t *Transport) PathTemplate() string { return t.pathTemplate }

// Request returns the underlying *http.Request.
func (t *Transport) Request() *http.Request { return t.request }

// Response returns the underlying http.ResponseWriter.
func (t *Transport) Response() http.ResponseWriter { return t.response }

// RequestHeader returns the inbound HTTP headers.
func (t *Transport) RequestHeader() ktransport.Header { return t.reqHeader }

// ReplyHeader returns the writable response headers.
func (t *Transport) ReplyHeader() ktransport.Header { return t.replyHeader }

// SetOperation overrides the operation name on the SSE transport
// attached to ctx. It is a no-op when ctx does not carry an SSE
// transport.
func SetOperation(ctx context.Context, op string) {
	if tr, ok := ktransport.FromServerContext(ctx); ok {
		if t, ok := tr.(*Transport); ok {
			t.operation = op
		}
	}
}

// RequestFromServerContext returns the request stored in ctx by an SSE
// transport, or false if none is present.
func RequestFromServerContext(ctx context.Context) (*http.Request, bool) {
	if tr, ok := ktransport.FromServerContext(ctx); ok {
		if t, ok := tr.(Transporter); ok {
			return t.Request(), true
		}
	}
	return nil, false
}

// ResponseWriterFromServerContext returns the response writer stored in
// ctx, or false if none is present.
func ResponseWriterFromServerContext(ctx context.Context) (http.ResponseWriter, bool) {
	if tr, ok := ktransport.FromServerContext(ctx); ok {
		if t, ok := tr.(ResponseTransporter); ok {
			return t.Response(), true
		}
	}
	return nil, false
}

type headerCarrier http.Header

func (hc headerCarrier) Get(key string) string      { return http.Header(hc).Get(key) }
func (hc headerCarrier) Set(key, value string)      { http.Header(hc).Set(key, value) }
func (hc headerCarrier) Add(key, value string)      { http.Header(hc).Add(key, value) }
func (hc headerCarrier) Values(key string) []string { return http.Header(hc).Values(key) }
func (hc headerCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range http.Header(hc) {
		keys = append(keys, k)
	}
	return keys
}
