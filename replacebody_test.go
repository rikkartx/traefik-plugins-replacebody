package plugin_replace_body_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"plugin_replace_body"
	"strings"
	"testing"
)

func TestReplaceBody(t *testing.T) {
	cfg := plugin_replace_body.CreateConfig()
	cfg.Address = "http://localhost:8080"
	cfg.Method = http.MethodGet

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := plugin_replace_body.New(ctx, next, cfg, "replaceBody-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8080/foo", nil)
	if err != nil {
		t.Fatal(err)
	}

	reader := strings.NewReader("{\"type\": \"a\"}")
	req.Body = ioutil.NopCloser(reader)
	req.ContentLength = int64(reader.Len())
	handler.ServeHTTP(recorder, req)

	assertBody(t, req, "{\"type\": \"b\", \"lastModified\": \"time.Now()\"}")
}

func assertBody(t *testing.T, req *http.Request, body string) {
	t.Helper()

	var buf bytes.Buffer
	_, _ = io.Copy(bufio.NewWriter(&buf), req.Body)

	bodyString := buf.String()
	if !strings.EqualFold(bodyString, body) {
		t.Errorf("not equal: %s, %s", bodyString, body)
	}
}
