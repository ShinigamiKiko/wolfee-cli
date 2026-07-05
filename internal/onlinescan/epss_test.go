package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newEPSSTestClient(t *testing.T, srvURL string) *http.Client {
	t.Helper()
	epssAPIURLForTest = srvURL
	t.Cleanup(func() { epssAPIURLForTest = "" })
	return &http.Client{Timeout: 5 * time.Second}
}

func epssJSONResp(data []struct{ CVE, EPSS, Percentile string }) []byte {
	type row struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	}
	type resp struct {
		Status string `json:"status"`
		Data   []row  `json:"data"`
	}
	rows := make([]row, len(data))
	for i, d := range data {
		rows[i] = row{CVE: d.CVE, EPSS: d.EPSS, Percentile: d.Percentile}
	}
	b, _ := json.Marshal(resp{Status: "OK", Data: rows})
	return b
}

func TestFetchEPSS_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(epssJSONResp([]struct{ CVE, EPSS, Percentile string }{
			{"CVE-2023-4911", "0.94310", "0.99821"},
			{"CVE-2024-0002", "1.0e-05", "0.10"},
		}))
	}))
	defer srv.Close()

	hc := newEPSSTestClient(t, srv.URL)
	got, err := fetchEPSS(context.Background(), hc, []string{"CVE-2023-4911", "CVE-2024-0002", "CVE-MISSING-9999"})
	if err != nil {
		t.Fatalf("fetchEPSS: %v", err)
	}
	if s := got["CVE-2023-4911"]; s.EPSS < 0.94 || s.EPSS > 0.95 {
		t.Errorf("CVE-2023-4911 EPSS = %v; want ~0.9431", s.EPSS)
	}
	if s := got["CVE-2024-0002"]; s.EPSS == 0 {
		t.Errorf("scientific-notation EPSS lost: %+v", s)
	}
}

func TestFetchEPSS_EmptyCVEsNoRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request should fire for empty CVE list, got %s", r.URL.Path)
	}))
	defer srv.Close()
	hc := newEPSSTestClient(t, srv.URL)

	out, err := fetchEPSS(context.Background(), hc, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty input should produce empty map, got %v", out)
	}
}

func TestFetchEPSS_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "epss feed offline", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	hc := newEPSSTestClient(t, srv.URL)

	_, err := fetchEPSS(context.Background(), hc, []string{"CVE-2023-4911"})
	if err == nil {
		t.Fatal("expected error on 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestFetchEPSS_BatchesLargeCVEList(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		cves := strings.Split(r.URL.Query().Get("cve"), ",")
		data := make([]struct{ CVE, EPSS, Percentile string }, len(cves))
		for i, c := range cves {
			data[i] = struct{ CVE, EPSS, Percentile string }{c, "0.5", "0.5"}
		}
		w.Write(epssJSONResp(data))
	}))
	defer srv.Close()
	hc := newEPSSTestClient(t, srv.URL)

	cves := make([]string, 250)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%04d", i+1)
	}
	got, err := fetchEPSS(context.Background(), hc, cves)
	if err != nil {
		t.Fatalf("fetchEPSS: %v", err)
	}
	if len(got) != 250 {
		t.Errorf("expected 250 hits, got %d", len(got))
	}
	if hits.Load() != 3 {
		t.Errorf("expected 3 batch requests, got %d", hits.Load())
	}
}

func TestFetchEPSS_CVEsPassedAsQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("cve")
		if !strings.Contains(got, "CVE-2024-1") {
			t.Errorf("?cve param missing CVE-2024-1, got %q", got)
		}
		w.Write(epssJSONResp(nil))
	}))
	defer srv.Close()
	hc := newEPSSTestClient(t, srv.URL)
	fetchEPSS(context.Background(), hc, []string{"CVE-2024-1"})
}
