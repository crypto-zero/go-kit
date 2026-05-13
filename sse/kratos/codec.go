package kratos

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-kratos/kratos/v2/encoding"
	kerrors "github.com/go-kratos/kratos/v2/errors"
)

// DefaultRequestDecoder is the default body decoder: it picks a codec by
// the request's Content-Type and unmarshals the body into v. An empty
// body is a success. Unknown Content-Types fall back to JSON.
func DefaultRequestDecoder(r *http.Request, v any) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("sse: read body: %w", err)
	}
	if len(body) == 0 {
		return nil
	}
	c := codecForContentType(r.Header.Get("Content-Type"))
	if c == nil {
		c = encoding.GetCodec("json")
	}
	if c == nil {
		return errors.New("sse: no codec available")
	}
	if err := c.Unmarshal(body, v); err != nil {
		return fmt.Errorf("sse: decode %s: %w", c.Name(), err)
	}
	return nil
}

// DefaultErrorEncoder writes err as an HTTP error response, honoring
// the status code embedded in a Kratos *errors.Error if present. It is
// meant for the pre-stream phase — once SSE bytes have been flushed,
// errors should be reported via an SSE "error" event instead.
//
// The response body is the error's Message (or err.Error() when the
// underlying error is not a Kratos error). Content-Type is plain text;
// callers wanting JSON should install a custom EncodeErrorFunc via the
// ErrorEncoder option.
func DefaultErrorEncoder(w http.ResponseWriter, _ *http.Request, err error) {
	se := kerrors.FromError(err)
	code := int(se.Code)
	if code <= 0 {
		code = http.StatusInternalServerError
	}
	msg := se.Message
	if msg == "" {
		msg = err.Error()
	}
	http.Error(w, msg, code)
}

// codecForContentType picks a Kratos codec by Content-Type, returning
// nil when the type is unrecognized. Parameters (";charset=utf-8") are
// stripped and a vendor prefix on the subtype is removed.
func codecForContentType(ct string) encoding.Codec {
	if ct == "" {
		return nil
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	subtype := ct
	if _, after, ok := strings.Cut(ct, "/"); ok {
		subtype = after
	}
	if i := strings.LastIndexByte(subtype, '.'); i >= 0 {
		subtype = subtype[i+1:]
	}
	return encoding.GetCodec(subtype)
}
