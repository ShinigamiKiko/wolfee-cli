package feedcache

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestSource(t *testing.T) *DiskHTTP {
	t.Helper()
	dir := t.TempDir()
	return &DiskHTTP{
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		CacheDir:   dir,
		UserAgent:  "wolfee-cli/test",
	}
}

func TestDiskHTTP_FetchAndCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "test-feed", URL: srv.URL, TTL: 1 * time.Hour}

	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "hello world" {
		t.Errorf("body = %q; want %q", body, "hello world")
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 fetch, got %d", hits.Load())
	}

	rc, err = d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	rc.Close()
	if hits.Load() != 1 {
		t.Errorf("TTL-fresh cache should not refetch; got %d hits", hits.Load())
	}
}

func TestDiskHTTP_ConditionalGET304(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("first body"))
	}))
	defer srv.Close()

	d := newTestSource(t)

	feed := Feed{Name: "feed-304", URL: srv.URL, TTL: 50 * time.Millisecond}

	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "first body" {
		t.Fatalf("first body = %q", body)
	}

	time.Sleep(100 * time.Millisecond)

	rc, err = d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	body, _ = io.ReadAll(rc)
	rc.Close()
	if string(body) != "first body" {
		t.Errorf("304 path should return original body, got %q", body)
	}
	if hits.Load() != 2 {
		t.Errorf("expected 2 fetches (one 200, one 304), got %d", hits.Load())
	}
}

func TestDiskHTTP_FallbackToSecondaryOn404(t *testing.T) {
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer badSrv.Close()

	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from fallback"))
	}))
	defer goodSrv.Close()

	d := newTestSource(t)
	feed := Feed{
		Name:         "fallback-test",
		URL:          badSrv.URL,
		FallbackURLs: []string{goodSrv.URL},
		TTL:          1 * time.Hour,
	}
	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "from fallback" {
		t.Errorf("body = %q; want from fallback", body)
	}
}

func TestDiskHTTP_EnvOverridesPrimaryURL(t *testing.T) {
	overrideSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from override"))
	}))
	defer overrideSrv.Close()

	t.Setenv("WOLFEE_FEED_URL_DLA_LIST", overrideSrv.URL)

	d := newTestSource(t)

	feed := Feed{
		Name: "dla-list",
		URL:  "http://127.0.0.1:1/should-not-be-used",
		TTL:  1 * time.Hour,
	}
	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "from override" {
		t.Errorf("env override not honoured; body = %q", body)
	}
}

func TestDiskHTTP_OfflineModeServesStale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cached body"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "offline-feed", URL: srv.URL, TTL: 1 * time.Hour}

	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("warm: %v", err)
	}
	rc.Close()

	d.Offline = true
	srv.Close()
	feed.TTL = 1 * time.Nanosecond

	rc, err = d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("offline read: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "cached body" {
		t.Errorf("body = %q; want cached body", body)
	}
}

func TestDiskHTTP_OfflineWithoutCacheErrors(t *testing.T) {
	d := newTestSource(t)
	d.Offline = true
	_, err := d.Open(context.Background(), Feed{
		Name: "no-cache-yet",
		URL:  "http://example.invalid/whatever",
		TTL:  1 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error when offline + no cache")
	}
	if !strings.Contains(err.Error(), "offline") {
		t.Errorf("error should mention offline mode, got %v", err)
	}
}

func TestDiskHTTP_StaleCacheServedOnUpstreamFailure(t *testing.T) {
	served := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.Load() {
			http.Error(w, "now down", http.StatusServiceUnavailable)
			return
		}
		served.Store(true)
		_, _ = w.Write([]byte("warm body"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "flaky", URL: srv.URL, TTL: 1 * time.Nanosecond}

	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("warm: %v", err)
	}
	rc.Close()

	rc, err = d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("stale fallback: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "warm body" {
		t.Errorf("stale body lost; got %q", body)
	}
}

func TestDiskHTTP_AtomicWriteNoTempLeftovers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "atomic", URL: srv.URL, TTL: 1 * time.Hour}
	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rc.Close()

	entries, err := os.ReadDir(d.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("leftover tmp file after successful write: %s", e.Name())
		}
	}
}

func TestDiskHTTP_SchemaMismatchTreatedAsMiss(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("real body"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "schema-test", URL: srv.URL, TTL: 1 * time.Hour}
	binPath, metaPath := d.paths(feed.Name)

	if err := os.MkdirAll(d.CacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("stale body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"schemaVersion":999,"fetchedAt":"2099-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "real body" {
		t.Errorf("schema mismatch should force refetch; got %q", body)
	}
	if hits.Load() != 1 {
		t.Errorf("expected exactly one fetch on schema-mismatch miss, got %d", hits.Load())
	}
}

func TestDiskHTTP_MetaCarriesHashAndSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "hash-test", URL: srv.URL, TTL: 1 * time.Hour}
	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rc.Close()

	_, metaPath := d.paths(feed.Name)
	meta := loadMeta(metaPath)
	if meta == nil {
		t.Fatal("meta missing")
	}
	if meta.Size != int64(len("hello world")) {
		t.Errorf("size = %d; want %d", meta.Size, len("hello world"))
	}
	if len(meta.SHA256) != 64 {
		t.Errorf("sha256 should be 64 hex chars, got %q", meta.SHA256)
	}
}

func TestDiskHTTP_NoCacheDirIsPassthrough(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	d := &DiskHTTP{HTTPClient: &http.Client{}, UserAgent: "ua"}
	feed := Feed{Name: "passthrough", URL: srv.URL, TTL: 1 * time.Hour}

	for i := 0; i < 3; i++ {
		rc, err := d.Open(context.Background(), feed)
		if err != nil {
			t.Fatalf("Open[%d]: %v", i, err)
		}
		rc.Close()
	}
	if hits.Load() != 3 {
		t.Errorf("expected 3 fetches with no cache, got %d", hits.Load())
	}
}

func TestDiskHTTP_PathsAreFlat(t *testing.T) {
	d := &DiskHTTP{CacheDir: "/tmp/wolfee"}
	bin, meta := d.paths("foo-bar")
	if want := filepath.Join("/tmp/wolfee", "foo-bar.bin"); bin != want {
		t.Errorf("bin path = %q; want %q", bin, want)
	}
	if want := filepath.Join("/tmp/wolfee", "foo-bar.meta.json"); meta != want {
		t.Errorf("meta path = %q; want %q", meta, want)
	}
}

func TestDiskHTTP_SendsAcceptEncodingIdentity(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Accept-Encoding")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := newTestSource(t)
	feed := Feed{Name: "ae-test", URL: srv.URL, TTL: 1 * time.Hour}
	rc, err := d.Open(context.Background(), feed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rc.Close()
	if captured != "identity" {
		t.Errorf("Accept-Encoding sent to upstream = %q; want identity (anything else risks transparent gunzip)", captured)
	}
}

func TestResolveURL_EnvOverride(t *testing.T) {
	t.Setenv("WOLFEE_FEED_URL_DLA_LIST", "https://example.com/dla")
	got := resolveURL(Feed{Name: "dla-list", URL: "https://salsa.example/dla"})
	if got != "https://example.com/dla" {
		t.Errorf("env override missed; got %q", got)
	}

	t.Setenv("WOLFEE_FEED_URL_DLA_LIST", "")
	got = resolveURL(Feed{Name: "dla-list", URL: "https://salsa.example/dla"})
	if got != "https://salsa.example/dla" {
		t.Errorf("empty env should fall back to primary; got %q", got)
	}
}
