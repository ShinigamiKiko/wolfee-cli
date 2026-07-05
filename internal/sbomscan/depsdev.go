package sbomscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// deps.dev exposes resolved dependency graphs per package version across the
// language ecosystems (npm, Go, Maven, PyPI, Cargo, NuGet). We use it to answer
// "which version of the direct dependency stops pulling the vulnerable release"
// - information that is not present in a single SBOM snapshot. OSV.dev, by
// contrast, only knows which versions of a package are vulnerable.
const depsDevBase = "https://api.deps.dev/v3"

const depsDevBodyLimit = 16 << 20

type depsDevVersionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type depsDevVersion struct {
	VersionKey  depsDevVersionKey `json:"versionKey"`
	IsDefault   bool              `json:"isDefault"`
	PublishedAt string            `json:"publishedAt"`
}

type depsDevPackage struct {
	Versions []depsDevVersion `json:"versions"`
}

type depsDevDepNode struct {
	VersionKey depsDevVersionKey `json:"versionKey"`
	Relation   string            `json:"relation"`
	Errors     []string          `json:"errors,omitempty"`
}

type depsDevDependencies struct {
	Nodes []depsDevDepNode `json:"nodes"`
}

// depsDevClient is a small caching wrapper. A single scan re-queries the same
// package/version repeatedly (many components share a "father"), so results are
// memoised for the lifetime of the scan. It is safe for concurrent use.
type depsDevClient struct {
	hc *http.Client

	mu       sync.Mutex
	pkgCache map[string]*depsDevPackage
	depCache map[string]*depsDevDependencies
}

func newDepsDevClient(hc *http.Client) *depsDevClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &depsDevClient{
		hc:       hc,
		pkgCache: map[string]*depsDevPackage{},
		depCache: map[string]*depsDevDependencies{},
	}
}

func (d *depsDevClient) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wolfee-cli/remediate")
	req.Header.Set("Accept", "application/json")

	resp, err := d.hc.Do(req)
	if err != nil {
		return fmt.Errorf("deps.dev request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, depsDevBodyLimit))
	if err != nil {
		return fmt.Errorf("deps.dev read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deps.dev: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("deps.dev decode: %w", err)
	}
	return nil
}

// pathEscape percent-encodes a package name or version for use as a single path
// segment. deps.dev requires slashes in Go module paths and "@" in scoped npm
// names to be encoded, which url.PathEscape does.
func pathEscape(s string) string {
	return url.PathEscape(s)
}

// versions returns the published versions of a package, cached.
func (d *depsDevClient) versions(ctx context.Context, system, name string) (*depsDevPackage, error) {
	key := system + "\x00" + name
	d.mu.Lock()
	if v, ok := d.pkgCache[key]; ok {
		d.mu.Unlock()
		return v, nil
	}
	d.mu.Unlock()

	endpoint := fmt.Sprintf("%s/systems/%s/packages/%s", depsDevBase, system, pathEscape(name))
	var pkg depsDevPackage
	err := d.getJSON(ctx, endpoint, &pkg)

	d.mu.Lock()
	if err == nil {
		d.pkgCache[key] = &pkg
	} else {
		// Cache the miss as an empty package so a 404 (name mismatch) is not
		// retried for every component sharing this father.
		d.pkgCache[key] = nil
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &pkg, nil
}

// dependencies returns the resolved dependency graph of a specific version,
// cached.
func (d *depsDevClient) dependencies(ctx context.Context, system, name, version string) (*depsDevDependencies, error) {
	key := system + "\x00" + name + "\x00" + version
	d.mu.Lock()
	if v, ok := d.depCache[key]; ok {
		d.mu.Unlock()
		return v, nil
	}
	d.mu.Unlock()

	endpoint := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s:dependencies",
		depsDevBase, system, pathEscape(name), pathEscape(version))
	var deps depsDevDependencies
	err := d.getJSON(ctx, endpoint, &deps)

	d.mu.Lock()
	if err == nil {
		d.depCache[key] = &deps
	} else {
		d.depCache[key] = nil
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &deps, nil
}
