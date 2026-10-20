package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// On aidetector.com the API shares an origin with the web app, and the
// User-Agent prefix is what routes a CLI request to the API.
func TestEveryRequestCarriesTheCLIUserAgent(t *testing.T) {
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}))
	defer srv.Close()
	old := UserAgent
	UserAgent = "aidetector-cli/test"
	defer func() { UserAgent = old }()
	if err := New(srv.URL, "").Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "aidetector-cli/") {
		t.Fatalf("User-Agent = %q, want the aidetector-cli/ prefix", got)
	}
}
