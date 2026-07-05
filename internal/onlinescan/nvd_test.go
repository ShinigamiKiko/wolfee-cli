package onlinescan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func newNVDTestClient(t *testing.T, srvURL string) *http.Client {
	t.Helper()
	nvdEndpointForTest = srvURL
	t.Cleanup(func() { nvdEndpointForTest = "" })
	return &http.Client{Timeout: 5 * time.Second}
}

const nvdScoredBody = `{"vulnerabilities":[{"cve":{"id":"CVE-2023-4911",` +
	`"published":"2023-10-03T18:15:09.937","lastModified":"2024-01-01T00:00:00.000",` +
	`"metrics":{"cvssMetricV31":[{"cvssData":{"version":"3.1",` +
	`"vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",` +
	`"baseScore":7.8,"baseSeverity":"HIGH"}}]}}}]}`

func TestQueryNVD_RateLimitIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	hc := newNVDTestClient(t, srv.URL)

	if _, res := queryNVD(context.Background(), hc, "", "CVE-2023-4911"); res != nvdQueryError {
		t.Fatalf("429 must be nvdQueryError, got %v", res)
	}
}

func TestQueryNVD_EmptyArrayIsAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	hc := newNVDTestClient(t, srv.URL)

	if _, res := queryNVD(context.Background(), hc, "", "CVE-9999-0001"); res != nvdQueryAbsent {
		t.Fatalf("empty array must be nvdQueryAbsent, got %v", res)
	}
}

func TestQueryNVD_ScoredParsesSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nvdScoredBody))
	}))
	defer srv.Close()
	hc := newNVDTestClient(t, srv.URL)

	s, res := queryNVD(context.Background(), hc, "", "CVE-2023-4911")
	if res != nvdQueryScored {
		t.Fatalf("scored response must be nvdQueryScored, got %v", res)
	}
	if s.Severity != "HIGH" || s.Score != 7.8 {
		t.Errorf("unexpected score: %+v", s)
	}
}

func TestFetchNVDScores_TransientNotNegativeCached(t *testing.T) {
	t.Setenv("WOLFEE_NVD_CACHE_FILE", filepath.Join(t.TempDir(), "nvd.json"))
	t.Setenv("WOLFEE_NVD_CACHE", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	hc := newNVDTestClient(t, srv.URL)

	out := fetchNVDScores(context.Background(), hc, []string{"CVE-2023-4911"}, nil)
	if len(out) != 0 {
		t.Fatalf("transient failure must yield no scores, got %v", out)
	}
	if _, st := openNVDCache().lookup("CVE-2023-4911"); st != nvdCacheMiss {
		t.Fatalf("transient failure must not be negative-cached; got state %v", st)
	}
}

func TestFetchNVDScores_AbsentIsNegativeCached(t *testing.T) {
	t.Setenv("WOLFEE_NVD_CACHE_FILE", filepath.Join(t.TempDir(), "nvd.json"))
	t.Setenv("WOLFEE_NVD_CACHE", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	hc := newNVDTestClient(t, srv.URL)

	fetchNVDScores(context.Background(), hc, []string{"CVE-9999-0001"}, nil)
	if _, st := openNVDCache().lookup("CVE-9999-0001"); st != nvdCacheNegative {
		t.Fatalf("genuine absence must be negative-cached; got state %v", st)
	}
}

func TestApplyNVD_EmptyScoreDoesNotStampNVD(t *testing.T) {
	results := []*ComponentResult{{
		Vulnerabilities: []Vulnerability{{ID: "CVE-2018-18311", CVE: "CVE-2018-18311"}},
	}}
	applyNVD(results, map[string]nvdScore{"CVE-2018-18311": {}})

	v := results[0].Vulnerabilities[0]
	if v.Severity != "" {
		t.Errorf("severity must stay empty, got %q", v.Severity)
	}
	if v.SeveritySource != "" {
		t.Errorf("severitySource must NOT be stamped for an empty NVD score, got %q", v.SeveritySource)
	}
}

func TestApplyNVD_RealScoreApplies(t *testing.T) {
	results := []*ComponentResult{{
		Vulnerabilities: []Vulnerability{{ID: "CVE-2023-4911", CVE: "CVE-2023-4911"}},
	}}
	applyNVD(results, map[string]nvdScore{
		"CVE-2023-4911": {Severity: "HIGH", Score: 7.8, Vector: "CVSS:3.1/X"},
	})

	v := results[0].Vulnerabilities[0]
	if v.Severity != "HIGH" || v.CVSS != 7.8 || v.SeveritySource != "NVD" {
		t.Errorf("real NVD score must apply and attribute, got %+v", v)
	}
}
