package kratos_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ksse "github.com/crypto-zero/go-kit/sse"
	ssekratos "github.com/crypto-zero/go-kit/sse/kratos"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

type boundRequest struct {
	Name string
}

func TestRegisterHTTPStreamBoundUsesSuppliedBinder(t *testing.T) {
	srv := khttp.NewServer(khttp.Timeout(0))
	ssekratos.RegisterHTTPStreamBound(
		srv,
		http.MethodGet,
		"/v1/bound",
		"/test.Bound/Watch",
		func(ctx khttp.Context, req *boundRequest) error {
			req.Name = ctx.Query().Get("name")
			return nil
		},
		func(_ context.Context, req *boundRequest, st *ksse.Stream) error {
			if err := st.WriteJSON(map[string]string{"name": req.Name}); err != nil {
				return err
			}
			return st.Done()
		},
	)

	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/bound?name=generated")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), `data: {"name":"generated"}`) {
		t.Fatalf("bound response missing generated name:\n%s", string(body))
	}
}
