package onlinescan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoCPrefetch_RunsInParallel(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(100 * time.Millisecond)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	cves := make([]string, 200)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%04d", i+1000)
	}

	p := newPoCFetcher()
	start := time.Now()
	p.Prefetch(context.Background(), &http.Client{}, cves, nil)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("prefetch took %v; expected <5s with %d-wide pool", elapsed, pocPrefetchConcurrency)
	}
	if hits.Load() != int32(len(cves)) {
		t.Errorf("expected %d HTTP hits, got %d", len(cves), hits.Load())
	}

	p.mu.Lock()
	cached := len(p.cache)
	p.mu.Unlock()
	if cached != len(cves) {
		t.Errorf("cache size = %d; want %d", cached, len(cves))
	}
}

func TestPoCPrefetch_HonoursBudget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	t.Setenv("WOLFEE_POC_MAX_LOOKUPS", "10")

	cves := make([]string, 50)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%04d", i+1000)
	}

	p := newPoCFetcher()
	p.Prefetch(context.Background(), &http.Client{}, cves, nil)

	if got := hits.Load(); got != 10 {
		t.Errorf("expected 10 HTTP hits (budget cap), got %d", got)
	}
}

func TestPoCPrefetch_BudgetZeroSkipsAllWork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	t.Setenv("WOLFEE_POC_MAX_LOOKUPS", "0")

	p := newPoCFetcher()
	p.Prefetch(context.Background(), &http.Client{}, []string{"CVE-2024-1234"}, nil)

	if got := hits.Load(); got != 0 {
		t.Errorf("expected zero HTTP hits with WOLFEE_POC_MAX_LOOKUPS=0, got %d", got)
	}
}

func TestPocMaxLookups_BadEnvValueFallsBackToDefault(t *testing.T) {
	t.Setenv("WOLFEE_POC_MAX_LOOKUPS", "not-a-number")
	if got := pocMaxLookups(); got != pocDefaultMaxLookups {
		t.Errorf("bad env should fall back to %d, got %d", pocDefaultMaxLookups, got)
	}
	t.Setenv("WOLFEE_POC_MAX_LOOKUPS", "-5")
	if got := pocMaxLookups(); got != pocDefaultMaxLookups {
		t.Errorf("negative env should fall back to %d, got %d", pocDefaultMaxLookups, got)
	}
}

func TestPoCPrefetch_SkipsAlreadyCachedCVEs(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	p := newPoCFetcher()
	cves := []string{"CVE-2024-1", "CVE-2024-2", "CVE-2024-3"}
	p.Prefetch(context.Background(), &http.Client{}, cves, nil)
	first := hits.Load()

	p.Prefetch(context.Background(), &http.Client{}, cves, nil)
	second := hits.Load()
	if first != second {
		t.Errorf("second prefetch re-fetched: %d → %d (expected no change)", first, second)
	}
	if first != int32(len(cves)) {
		t.Errorf("first prefetch hits = %d; want %d", first, len(cves))
	}
}

func TestPoCPrefetch_DeterministicBudgetWindowRegardlessOfInputOrder(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	t.Setenv("WOLFEE_POC_MAX_LOOKUPS", "5")

	all := []string{
		"CVE-2020-1000", "CVE-2020-2000",
		"CVE-2021-1000", "CVE-2021-2000",
		"CVE-2022-1000", "CVE-2022-2000",
		"CVE-2023-1000", "CVE-2023-2000",
		"CVE-2024-1000", "CVE-2024-2000",
		"CVE-2024-3000", "CVE-2024-4000",
		"CVE-2024-5000", "CVE-2024-6000",
		"CVE-2024-7000", "CVE-2024-8000",
		"CVE-2024-9000", "CVE-2025-1000",
		"CVE-2025-2000", "CVE-2025-3000",
	}

	reversed := make([]string, len(all))
	for i, v := range all {
		reversed[len(all)-1-i] = v
	}

	p1 := newPoCFetcher()
	p1.Prefetch(context.Background(), &http.Client{}, all, nil)

	p2 := newPoCFetcher()
	p2.Prefetch(context.Background(), &http.Client{}, reversed, nil)

	p1.mu.Lock()
	keys1 := make(map[string]struct{}, len(p1.cache))
	for k := range p1.cache {
		keys1[k] = struct{}{}
	}
	p1.mu.Unlock()

	p2.mu.Lock()
	keys2 := make(map[string]struct{}, len(p2.cache))
	for k := range p2.cache {
		keys2[k] = struct{}{}
	}
	p2.mu.Unlock()

	if len(keys1) != len(keys2) {
		t.Errorf("cache sizes differ: %d vs %d", len(keys1), len(keys2))
	}
	for k := range keys1 {
		if _, ok := keys2[k]; !ok {
			t.Errorf("key %q in p1 cache but not p2 - budget window is not deterministic", k)
		}
	}
}

func TestPoCPrefetch_NonCVEIDsAreSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("non-CVE id should not trigger a request: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	p := newPoCFetcher()
	p.Prefetch(context.Background(), &http.Client{}, []string{"GHSA-xxxx", "MAL-2024-1"}, nil)
}

func TestPoCPrefetch_LoggerProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	prev := rawTemplateOverride
	rawTemplateOverride = srv.URL + "/%s/%s.json"
	defer func() { rawTemplateOverride = prev }()

	rec := &recordingLogger{}
	cves := make([]string, 120)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%04d", i)
	}

	p := newPoCFetcher()
	p.Prefetch(context.Background(), &http.Client{}, cves, rec)

	foundStep := false
	for _, s := range rec.steps {
		if strings.Contains(s, "Fetching PoC-in-GitHub links") {
			foundStep = true
			break
		}
	}
	if !foundStep {
		t.Errorf("expected step log containing 'Fetching PoC-in-GitHub links', got %v", rec.steps)
	}
	if len(rec.progress) == 0 {
		t.Errorf("expected at least one progress callback for 120 CVEs")
	}
}

type recordingLogger struct {
	steps    []string
	progress []string
}

func (r *recordingLogger) Step(s string) { r.steps = append(r.steps, s) }
func (r *recordingLogger) Progress(done, total int, label string) {
	r.progress = append(r.progress, fmt.Sprintf("%d/%d %s", done, total, label))
}
