package onlinescan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestToxicReposLoad_TimesOutOnSlowUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()

	prev := toxicReposURL
	toxicReposURL = srv.URL
	defer func() { toxicReposURL = prev }()

	prevTimeout := toxicReposLoadTimeoutOverride
	toxicReposLoadTimeoutOverride = 200 * time.Millisecond
	defer func() { toxicReposLoadTimeoutOverride = prevTimeout }()

	idx := newToxicReposIndex()
	start := time.Now()
	err := idx.Load(context.Background(), &http.Client{Timeout: 5 * time.Second})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("load took %v; expected <1.5s due to per-feed timeout", elapsed)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "context") && !strings.Contains(strings.ToLower(err.Error()), "deadline") {
		t.Errorf("expected context/deadline error, got %v", err)
	}
}

func TestToxicReposLoad_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"problem_type":"ddos","name":"x","commit_link":"https://github.com/owner/repo","PURL":"pkg:npm/foo@1.0.0"}]`))
	}))
	defer srv.Close()

	prev := toxicReposURL
	toxicReposURL = srv.URL
	defer func() { toxicReposURL = prev }()

	idx := newToxicReposIndex()
	if err := idx.Load(context.Background(), &http.Client{}); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	hits := idx.Lookup("pkg:npm/foo@1.0.0", "foo")
	if len(hits) != 1 || hits[0].ProblemType != "ddos" {
		t.Fatalf("Lookup miss: %+v", hits)
	}
}
