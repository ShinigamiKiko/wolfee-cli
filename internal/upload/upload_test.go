package upload

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendBOM_PostsCorrectShape(t *testing.T) {
	var (
		gotPath        string
		gotContentType string
		gotApiKey      string
		gotBody        []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotApiKey = r.Header.Get("X-Api-Key")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"token":"abc-123"}`))
	}))
	defer srv.Close()

	bom := []byte(`{"bomFormat":"CycloneDX","components":[]}`)
	err := SendBOM(context.Background(), Params{
		ServerURL:   srv.URL,
		Token:       "secret-token",
		ProjectName: "my-app",
		BOMBytes:    bom,
	})
	if err != nil {
		t.Fatalf("SendBOM: %v", err)
	}

	if gotPath != "/api/v1/bom" {
		t.Errorf("path = %q; want /api/v1/bom", gotPath)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Errorf("Content-Type = %q; want application/json", gotContentType)
	}
	if gotApiKey != "secret-token" {
		t.Errorf("X-Api-Key = %q; want secret-token", gotApiKey)
	}

	var req uploadRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if req.ProjectName != "my-app" {
		t.Errorf("projectName = %q; want my-app", req.ProjectName)
	}
	if !req.AutoCreate {
		t.Error("autoCreate should be true (CLI always autoCreate)")
	}
	decoded, err := base64.StdEncoding.DecodeString(req.BOM)
	if err != nil {
		t.Fatalf("bom not base64: %v", err)
	}
	if string(decoded) != string(bom) {
		t.Error("decoded BOM != original; encoding round-trip broken")
	}
}

func TestSendBOM_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(413)
		_, _ = w.Write([]byte(`{"error":"bom too large"}`))
	}))
	defer srv.Close()

	err := SendBOM(context.Background(), Params{
		ServerURL:   srv.URL,
		ProjectName: "x",
		BOMBytes:    []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error on 413")
	}
	if !strings.Contains(err.Error(), "413") {
		t.Errorf("error should include status code: %v", err)
	}
	if !strings.Contains(err.Error(), "bom too large") {
		t.Errorf("error should include server response body: %v", err)
	}
}

func TestSendBOM_ValidatesInputs(t *testing.T) {
	cases := []struct {
		name string
		p    Params
	}{
		{"no-server", Params{ProjectName: "x", BOMBytes: []byte("{}")}},
		{"no-project", Params{ServerURL: "http://x", BOMBytes: []byte("{}")}},
		{"empty-bom", Params{ServerURL: "http://x", ProjectName: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := SendBOM(context.Background(), tc.p); err == nil {
				t.Error("expected error for invalid params")
			}
		})
	}
}

func TestSendBOM_UsesXApiKeyHeader(t *testing.T) {
	var seenAuth, seenApiKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenApiKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	_ = SendBOM(context.Background(), Params{
		ServerURL: srv.URL, ProjectName: "x", Token: "tok", BOMBytes: []byte("{}"),
	})
	if seenAuth != "" {
		t.Errorf("Authorization header should be empty, got %q", seenAuth)
	}
	if seenApiKey != "tok" {
		t.Errorf("X-Api-Key should carry the token, got %q", seenApiKey)
	}
}
