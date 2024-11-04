package errors

import (
	"context"
	"net/http"
)

// HttpServerErrorEncoder is a server error encoder.
func HttpServerErrorEncoder(
	encodeWithHeaderName func(header string, r *http.Request, content *Error) (
		contentType string, body []byte, err error),
	w http.ResponseWriter, r *http.Request, err error,
) {
	se := FromError(err)
	contentType, body, err := encodeWithHeaderName("Accept", r, se)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(int(se.Status))
	_, _ = w.Write(body)
}

// RPCHandler is a rpc handler for grpc/http client.
type RPCHandler func(ctx context.Context, req any) (any, error)

// RPCClientErrorParser is a rpc client error parser.
func RPCClientErrorParser(handler RPCHandler) RPCHandler {
	return func(ctx context.Context, req any) (any, error) {
		reply, err := handler(ctx, req)
		if err != nil {
			return nil, FromError(err)
		}
		return reply, nil
	}
}
