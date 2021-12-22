package plugin_replace_body_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"plugin_replace_body"
	"strings"
	"testing"
)

func TestReplaceBody(t *testing.T) {
	cfg := plugin_replace_body.CreateConfig()
	cfg.Address = "https://httpbin.org/robots.txt"
	cfg.Method = http.MethodGet

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := plugin_replace_body.New(ctx, next, cfg, "replaceBody-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	// this url doesn't matter
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	testReq, err := http.NewRequest(http.MethodGet, cfg.Address, nil)
	if err != nil {
		t.Fatal(err)
	}
	testClient := http.Client{}
	testResponse, err := testClient.Do(testReq)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(bufio.NewWriter(&buf), testResponse.Body)

	handler.ServeHTTP(recorder, req)

	assertBody(t, req, buf.String())
}

func assertBody(t *testing.T, req *http.Request, matchBody string) {
	t.Helper()

	var buf bytes.Buffer
	_, _ = io.Copy(bufio.NewWriter(&buf), req.Body)

	bodyString := buf.String()
	if !strings.EqualFold(bodyString, matchBody) {
		t.Errorf("not equal: %s, %s", bodyString, matchBody)
	}
}
