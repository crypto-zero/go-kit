package kratos

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kratos/kratos/v2/encoding"

	"github.com/crypto-zero/go-kit/sse"
)

// HTTPClient opens SSE streams over HTTP.
type HTTPClient struct {
	endpoint string
	client   *http.Client
}

// HTTPClientOption configures an HTTPClient.
type HTTPClientOption func(*HTTPClient)

// WithHTTPClient sets the underlying net/http client.
func WithHTTPClient(client *http.Client) HTTPClientOption {
	return func(c *HTTPClient) {
		if client == nil {
			panic("sse/kratos: nil HTTP client")
		}
		c.client = client
	}
}

// NewHTTPClient returns an SSE HTTP client for endpoint.
func NewHTTPClient(endpoint string, opts ...HTTPClientOption) *HTTPClient {
	c := &HTTPClient{endpoint: strings.TrimRight(endpoint, "/"), client: http.DefaultClient}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// HTTPStreamCallOption configures one SSE stream request.
type HTTPStreamCallOption func(*httpStreamCallConfig)

type httpStreamCallConfig struct {
	headers http.Header
}

// WithRequestHeader adds one request header value.
func WithRequestHeader(key, value string) HTTPStreamCallOption {
	return func(c *httpStreamCallConfig) {
		c.headers.Add(key, value)
	}
}

// WithLastEventID sets the Last-Event-ID header for stream resumption.
func WithLastEventID(id string) HTTPStreamCallOption {
	return WithRequestHeader(sse.LastEventIDHeader, id)
}

// Open opens an SSE stream and returns a reader for response events. Non-nil
// body values are JSON encoded unless body already implements io.Reader.
func (c *HTTPClient) Open(ctx context.Context, method, path string, body any, opts ...HTTPStreamCallOption) (*sse.Reader, error) {
	cfg := httpStreamCallConfig{headers: make(http.Header)}
	for _, opt := range opts {
		opt(&cfg)
	}
	u, err := joinEndpointPath(c.endpoint, path)
	if err != nil {
		return nil, err
	}
	bodyReader, contentType, err := encodeRequestBody(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, values := range cfg.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			return nil, fmt.Errorf("sse: unexpected status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("sse: unexpected status %d: %s", resp.StatusCode, msg)
	}
	return sse.NewReader(resp.Body), nil
}

func encodeRequestBody(body any) (io.Reader, string, error) {
	if body == nil {
		return nil, "", nil
	}
	if r, ok := body.(io.Reader); ok {
		return r, "", nil
	}
	b, err := encoding.GetCodec("json").Marshal(body)
	if err != nil {
		return nil, "", fmt.Errorf("sse: marshal request body: %w", err)
	}
	return bytes.NewReader(b), "application/json", nil
}

func joinEndpointPath(endpoint, path string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("sse: endpoint is empty")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	if ref.IsAbs() {
		return ref.String(), nil
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(ref.Path, "/")
	base.RawQuery = ref.RawQuery
	base.Fragment = ref.Fragment
	return base.String(), nil
}
