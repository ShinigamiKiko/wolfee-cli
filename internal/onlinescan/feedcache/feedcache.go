package feedcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const cacheSchemaVersion = 2

type Feed struct {
	Name string

	URL string

	FallbackURLs []string

	TTL time.Duration
}

func resolveURL(f Feed) string {
	key := "WOLFEE_FEED_URL_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return f.URL
}

type Source interface {
	Open(ctx context.Context, f Feed) (io.ReadCloser, error)
}

type cacheMeta struct {
	SchemaVersion int       `json:"schemaVersion"`
	URL           string    `json:"url"`
	FetchedAt     time.Time `json:"fetchedAt"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"lastModified,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	Size          int64     `json:"size,omitempty"`
}

type DiskHTTP struct {
	HTTPClient *http.Client
	CacheDir   string
	Offline    bool
	UserAgent  string

	mu sync.Mutex
}

func NewDefault(hc *http.Client) *DiskHTTP {
	if hc == nil {
		hc = http.DefaultClient
	}
	d := &DiskHTTP{
		HTTPClient: hc,
		UserAgent:  "wolfee-cli/online",
		Offline:    strings.EqualFold(strings.TrimSpace(os.Getenv("WOLFEE_FEEDS_OFFLINE")), "1"),
	}
	if dir := strings.TrimSpace(os.Getenv("WOLFEE_FEEDS_CACHE_DIR")); dir != "" {
		d.CacheDir = dir
	} else if base, err := os.UserCacheDir(); err == nil {
		d.CacheDir = filepath.Join(base, "wolfee", "feeds")
	}
	return d
}

func (d *DiskHTTP) Open(ctx context.Context, f Feed) (io.ReadCloser, error) {
	if f.Name == "" || f.URL == "" {
		return nil, errors.New("feedcache: Feed.Name and Feed.URL are required")
	}

	if d.CacheDir == "" {
		return d.passthroughGET(ctx, resolveURL(f), f.FallbackURLs)
	}

	binPath, metaPath := d.paths(f.Name)
	meta := loadMeta(metaPath)

	if meta != nil && time.Since(meta.FetchedAt) < f.TTL {
		if rc, err := os.Open(binPath); err == nil {
			return rc, nil
		}
	}

	if d.Offline {
		if rc, err := os.Open(binPath); err == nil {
			return rc, nil
		}
		return nil, fmt.Errorf("feedcache: offline mode, no cache for %q", f.Name)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if meta2 := loadMeta(metaPath); meta2 != nil && time.Since(meta2.FetchedAt) < f.TTL {
		if rc, err := os.Open(binPath); err == nil {
			return rc, nil
		}
	}

	var lastErr error
	urls := append([]string{resolveURL(f)}, f.FallbackURLs...)
	for _, url := range urls {
		body, newMeta, err := d.conditionalGET(ctx, url, meta)
		if err != nil {
			lastErr = err
			continue
		}
		if body == nil {

			if meta != nil {
				meta.FetchedAt = time.Now().UTC()
				_ = saveMeta(metaPath, meta)
			}
			if rc, err := os.Open(binPath); err == nil {
				return rc, nil
			}
			lastErr = fmt.Errorf("304 received but cached body missing")
			continue
		}

		sha, size, werr := writeAtomic(binPath, body)
		body.Close()
		if werr != nil {
			lastErr = werr
			continue
		}
		newMeta.SchemaVersion = cacheSchemaVersion
		newMeta.FetchedAt = time.Now().UTC()
		newMeta.SHA256 = sha
		newMeta.Size = size
		_ = saveMeta(metaPath, newMeta)
		return os.Open(binPath)
	}

	if meta != nil {
		if rc, err := os.Open(binPath); err == nil {
			return rc, nil
		}
	}
	return nil, fmt.Errorf("feedcache: fetch %q: %w", f.Name, lastErr)
}

func (d *DiskHTTP) passthroughGET(ctx context.Context, primary string, fallbacks []string) (io.ReadCloser, error) {
	urls := append([]string{primary}, fallbacks...)
	var lastErr error
	for _, url := range urls {
		body, _, err := d.conditionalGET(ctx, url, nil)
		if err == nil && body != nil {
			return body, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("feedcache passthrough: %w", lastErr)
}

func (d *DiskHTTP) conditionalGET(ctx context.Context, url string, prior *cacheMeta) (io.ReadCloser, *cacheMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", d.UserAgent)

	req.Header.Set("Accept-Encoding", "identity")
	if prior != nil {
		if prior.ETag != "" {
			req.Header.Set("If-None-Match", prior.ETag)
		}
		if prior.LastModified != "" {
			req.Header.Set("If-Modified-Since", prior.LastModified)
		}
	}
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	switch resp.StatusCode {
	case http.StatusNotModified:
		resp.Body.Close()
		return nil, nil, nil
	case http.StatusOK:
		return resp.Body, &cacheMeta{
			URL:          url,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		}, nil
	default:

		_, _ = io.CopyN(io.Discard, resp.Body, 1<<10)
		resp.Body.Close()
		return nil, nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
}

func (d *DiskHTTP) paths(name string) (binPath, metaPath string) {
	binPath = filepath.Join(d.CacheDir, name+".bin")
	metaPath = filepath.Join(d.CacheDir, name+".meta.json")
	return
}

func loadMeta(path string) *cacheMeta {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m cacheMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	if m.SchemaVersion != cacheSchemaVersion {
		return nil
	}
	return &m
}

func saveMeta(path string, m *cacheMeta) error {
	if m.SchemaVersion == 0 {
		m.SchemaVersion = cacheSchemaVersion
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func writeAtomic(path string, body io.Reader) (string, int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), body)
	closeErr := tmp.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
