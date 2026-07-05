package onlinescan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const nvdCacheTempPattern = nvdCacheDefaultName + ".tmp.*"

const (
	nvdCacheVersion       = 1
	nvdPositiveCacheTTL   = 90 * 24 * time.Hour
	nvdNegativeCacheTTL   = 7 * 24 * time.Hour
	nvdCacheDefaultSubdir = "wolfee"
	nvdCacheDefaultName   = "nvd-scores.json"
)

type nvdCacheEntry struct {
	FetchedAt time.Time `json:"fetchedAt"`
	Severity  string    `json:"severity,omitempty"`
	Score     float64   `json:"score,omitempty"`
	Vector    string    `json:"vector,omitempty"`
	Negative  bool      `json:"negative,omitempty"`
}

type nvdCacheFile struct {
	Version int                      `json:"version"`
	Entries map[string]nvdCacheEntry `json:"entries"`
}

type nvdCache struct {
	mu       sync.Mutex
	path     string
	enabled  bool
	entries  map[string]nvdCacheEntry
	dirty    bool
	loadOnce sync.Once
}

func openNVDCache() *nvdCache {
	c := &nvdCache{entries: map[string]nvdCacheEntry{}}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("WOLFEE_NVD_CACHE")), "off") {
		return c
	}
	path := strings.TrimSpace(os.Getenv("WOLFEE_NVD_CACHE_FILE"))
	if path == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return c
		}
		path = filepath.Join(base, nvdCacheDefaultSubdir, nvdCacheDefaultName)
	}
	c.path = path
	c.enabled = true
	c.load()
	return c
}

func (c *nvdCache) load() {
	c.loadOnce.Do(func() {
		if !c.enabled {
			return
		}
		b, err := os.ReadFile(c.path)
		if err != nil {
			return
		}
		var file nvdCacheFile
		if err := json.Unmarshal(b, &file); err != nil || file.Version != nvdCacheVersion {
			return
		}
		if file.Entries != nil {
			c.entries = file.Entries
		}
	})
}

type nvdCacheState int

const (
	nvdCacheMiss nvdCacheState = iota
	nvdCacheHit
	nvdCacheNegative
)

func (c *nvdCache) lookup(cve string) (nvdScore, nvdCacheState) {
	if c == nil || !c.enabled {
		return nvdScore{}, nvdCacheMiss
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[cve]
	if !ok {
		return nvdScore{}, nvdCacheMiss
	}
	ttl := nvdPositiveCacheTTL
	if e.Negative {
		ttl = nvdNegativeCacheTTL
	}
	if time.Since(e.FetchedAt) > ttl {
		return nvdScore{}, nvdCacheMiss
	}
	if e.Negative {
		return nvdScore{}, nvdCacheNegative
	}
	return nvdScore{Severity: e.Severity, Score: e.Score, Vector: e.Vector}, nvdCacheHit
}

func (c *nvdCache) store(cve string, s nvdScore) {
	if c == nil || !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cve] = nvdCacheEntry{
		FetchedAt: time.Now().UTC(),
		Severity:  s.Severity,
		Score:     s.Score,
		Vector:    s.Vector,
	}
	c.dirty = true
}

func (c *nvdCache) storeNegative(cve string) {
	if c == nil || !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cve] = nvdCacheEntry{
		FetchedAt: time.Now().UTC(),
		Negative:  true,
	}
	c.dirty = true
}

func (c *nvdCache) flush() {
	if c == nil || !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return
	}
	file := nvdCacheFile{Version: nvdCacheVersion, Entries: c.entries}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return
	}

	tmp, err := os.CreateTemp(filepath.Dir(c.path), nvdCacheTempPattern)
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, werr := tmp.Write(b); werr != nil {
		tmp.Close()
		return
	}
	if tmp.Close() != nil {
		return
	}

	if os.Rename(tmpName, c.path) == nil {
		c.dirty = false
	}
}
