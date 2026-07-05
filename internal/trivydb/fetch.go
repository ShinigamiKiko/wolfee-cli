package trivydb

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultRegistry = "ghcr.io"
	trivyDBRepo     = "aquasecurity/trivy-db"
	trivyDBTag      = "2"
	dbCacheTTL      = 6 * time.Hour

	MirrorEnvKey = "WOLFEE_TRIVY_DB_MIRROR"
)

func EnsureDB(ctx context.Context, hc *http.Client, cacheDir, mirror string) (string, bool, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", false, fmt.Errorf("trivy-db: resolve cache dir: %w", err)
		}
		cacheDir = filepath.Join(base, "wolfee", "trivy-db")
	}
	if mirror == "" {
		mirror = strings.TrimSpace(os.Getenv(MirrorEnvKey))
	}
	registry := defaultRegistry
	if mirror != "" {
		registry = mirror
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", false, fmt.Errorf("trivy-db: mkdir %s: %w", cacheDir, err)
	}

	dbPath := filepath.Join(cacheDir, "trivy.db")
	metaPath := filepath.Join(cacheDir, "meta.json")

	if meta := loadMeta(metaPath); meta != nil && time.Since(meta.FetchedAt) < dbCacheTTL {
		if _, err := os.Stat(dbPath); err == nil {
			return dbPath, false, nil
		}
	}

	if err := downloadDB(ctx, hc, registry, dbPath); err != nil {

		if _, statErr := os.Stat(dbPath); statErr == nil {
			return dbPath, false, nil
		}
		return "", false, fmt.Errorf("trivy-db: %w", err)
	}
	saveMeta(metaPath, &dbMeta{FetchedAt: time.Now().UTC()})
	return dbPath, true, nil
}

func DBAge(cacheDir string) time.Time {
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return time.Time{}
		}
		cacheDir = filepath.Join(base, "wolfee", "trivy-db")
	}
	meta := loadMeta(filepath.Join(cacheDir, "meta.json"))
	if meta == nil {
		return time.Time{}
	}
	return meta.FetchedAt
}

type dbMeta struct {
	FetchedAt time.Time `json:"fetchedAt"`
}

func loadMeta(path string) *dbMeta {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m dbMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return &m
}

func saveMeta(path string, m *dbMeta) {
	b, _ := json.Marshal(m)
	_ = os.WriteFile(path, b, 0o644)
}

type ociToken struct {
	Token string `json:"token"`
}

type ociManifest struct {
	SchemaVersion int       `json:"schemaVersion"`
	MediaType     string    `json:"mediaType"`
	Config        ociDesc   `json:"config"`
	Layers        []ociDesc `json:"layers"`
	Manifests     []ociDesc `json:"manifests"`
}

type ociDesc struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

func downloadDB(ctx context.Context, hc *http.Client, registry, dbPath string) error {
	token, err := fetchToken(ctx, hc, registry)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	manifest, err := fetchManifest(ctx, hc, registry, token, trivyDBTag)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}

	if strings.Contains(manifest.MediaType, "index") || len(manifest.Manifests) > 0 {
		if len(manifest.Manifests) == 0 {
			return errors.New("OCI index has no manifests")
		}
		manifest, err = fetchManifest(ctx, hc, registry, token, manifest.Manifests[0].Digest)
		if err != nil {
			return fmt.Errorf("manifest (from index): %w", err)
		}
	}

	if len(manifest.Layers) == 0 {
		return errors.New("manifest has no layers")
	}

	layer := manifest.Layers[0]

	return fetchBlob(ctx, hc, registry, token, layer.Digest, dbPath)
}

func fetchToken(ctx context.Context, hc *http.Client, registry string) (string, error) {
	url := fmt.Sprintf("https://%s/token?service=%s&scope=repository:%s:pull",
		registry, registry, trivyDBRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "wolfee-cli/trivydb")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	var tok ociToken
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("token decode: %w", err)
	}
	return tok.Token, nil
}

func fetchManifest(ctx context.Context, hc *http.Client, registry, token, ref string) (*ociManifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, trivyDBRepo, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wolfee-cli/trivydb")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ","))
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest status %d", resp.StatusCode)
	}
	var m ociManifest
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	if m.MediaType == "" {
		ct := resp.Header.Get("Content-Type")
		m.MediaType = ct
	}
	return &m, nil
}

func fetchBlob(ctx context.Context, hc *http.Client, registry, token, digest, dbPath string) error {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, trivyDBRepo, digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wolfee-cli/trivydb")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("blob status %d", resp.StatusCode)
	}
	return extractTrivyDB(resp.Body, dbPath)
}

func extractTrivyDB(body io.Reader, dbPath string) error {
	gz, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var seen []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		seen = append(seen, name)
		if filepath.Base(name) == "trivy.db" {
			return atomicWrite(dbPath, tr)
		}
	}
	return fmt.Errorf("trivy.db not found in layer (saw: %s)", strings.Join(seen, ", "))
}

func atomicWrite(dst string, src io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "trivy.db.tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }

	if _, err := io.Copy(tmp, src); err != nil {
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dst)
}
