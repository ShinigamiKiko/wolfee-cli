package onlinescan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestNVDCache(t *testing.T) *nvdCache {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("WOLFEE_NVD_CACHE_FILE", filepath.Join(dir, "nvd.json"))
	t.Setenv("WOLFEE_NVD_CACHE", "")
	return openNVDCache()
}

func TestNVDCache_RoundTripAcrossOpens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nvd.json")
	t.Setenv("WOLFEE_NVD_CACHE_FILE", path)

	c1 := openNVDCache()
	c1.store("CVE-2023-4911", nvdScore{Severity: "CRITICAL", Score: 9.8, Vector: "CVSS:3.1/X"})
	c1.flush()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}

	c2 := openNVDCache()
	got, st := c2.lookup("CVE-2023-4911")
	if st != nvdCacheHit {
		t.Fatalf("expected nvdCacheHit after reopen, got %v", st)
	}
	if got.Severity != "CRITICAL" || got.Score != 9.8 {
		t.Errorf("unexpected cached value: %+v", got)
	}
}

func TestNVDCache_NegativeEntryResolvesNegative(t *testing.T) {
	c := newTestNVDCache(t)
	c.storeNegative("CVE-2099-0001")

	got, st := c.lookup("CVE-2099-0001")
	if st != nvdCacheNegative {
		t.Fatalf("negative entry must resolve nvdCacheNegative, got %v", st)
	}
	if got.Severity != "" {
		t.Errorf("negative cache must carry no score, got %+v", got)
	}
}

func TestNVDCache_ExpiredEntryComesBackAsMiss(t *testing.T) {
	c := newTestNVDCache(t)
	c.entries["CVE-OLD"] = nvdCacheEntry{
		FetchedAt: time.Now().Add(-nvdPositiveCacheTTL - time.Hour),
		Severity:  "HIGH",
		Score:     7.5,
	}
	if _, st := c.lookup("CVE-OLD"); st != nvdCacheMiss {
		t.Errorf("expired positive entry must miss, got %v", st)
	}
	c.entries["CVE-OLD-NEG"] = nvdCacheEntry{
		FetchedAt: time.Now().Add(-nvdNegativeCacheTTL - time.Hour),
		Negative:  true,
	}
	if _, st := c.lookup("CVE-OLD-NEG"); st != nvdCacheMiss {
		t.Errorf("expired negative entry must miss, got %v", st)
	}
}

func TestNVDCache_DisabledIsNoop(t *testing.T) {
	t.Setenv("WOLFEE_NVD_CACHE", "off")
	t.Setenv("WOLFEE_NVD_CACHE_FILE", filepath.Join(t.TempDir(), "nvd.json"))
	c := openNVDCache()
	if c.enabled {
		t.Fatal("expected cache disabled when WOLFEE_NVD_CACHE=off")
	}
	c.store("CVE-2024-1", nvdScore{Severity: "HIGH"})
	if _, st := c.lookup("CVE-2024-1"); st != nvdCacheMiss {
		t.Errorf("disabled cache must always miss, got %v", st)
	}
}

func TestNVDCache_GarbageFileResetsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nvd.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WOLFEE_NVD_CACHE_FILE", path)

	c := openNVDCache()
	if len(c.entries) != 0 {
		t.Errorf("expected empty entries on garbage file, got %d", len(c.entries))
	}

	c.store("CVE-X", nvdScore{Severity: "HIGH"})
	if _, st := c.lookup("CVE-X"); st != nvdCacheHit {
		t.Errorf("post-reset writes must work, got %v", st)
	}
}
