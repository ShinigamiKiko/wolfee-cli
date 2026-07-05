package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

const debianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"

type debianRelease struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories,omitempty"`
	FixedVersion string            `json:"fixed_version,omitempty"`
	Urgency      string            `json:"urgency,omitempty"`
	NoDSA        string            `json:"nodsa,omitempty"`
	NoDSAReason  string            `json:"nodsa_reason,omitempty"`
}

type debianCVE struct {
	Scope    string                   `json:"scope,omitempty"`
	Releases map[string]debianRelease `json:"releases"`
}

type debianIndex struct {
	mu       sync.RWMutex
	loadOnce sync.Once
	loaded   bool
	loadErr  error
	bySrc    map[string]map[string]debianCVE
}

func newDebianIndex() *debianIndex {
	return &debianIndex{bySrc: map[string]map[string]debianCVE{}}
}

func (d *debianIndex) IsLoaded() bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded && len(d.bySrc) > 0
}

func (d *debianIndex) Load(ctx context.Context, hc *http.Client) error {
	d.loadOnce.Do(func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, debianTrackerURL, nil)
		if err != nil {
			d.loadErr = err
			return
		}
		req.Header.Set("User-Agent", "wolfee-cli/online")
		resp, err := hc.Do(req)
		if err != nil {
			d.loadErr = fmt.Errorf("debian tracker: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			d.loadErr = fmt.Errorf("debian tracker: status %d", resp.StatusCode)
			return
		}

		const maxDebianTrackerSize = 256 << 20
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDebianTrackerSize+1))
		if err != nil {
			d.loadErr = fmt.Errorf("debian tracker: read: %w", err)
			return
		}
		if len(body) > maxDebianTrackerSize {
			d.loadErr = fmt.Errorf("debian tracker: dump exceeds %d MiB cap (got at least %d bytes); raise maxDebianTrackerSize", maxDebianTrackerSize>>20, len(body))
			return
		}
		idx := map[string]map[string]debianCVE{}
		if err := json.Unmarshal(body, &idx); err != nil {
			d.loadErr = fmt.Errorf("debian tracker: parse: %w", err)
			return
		}
		d.mu.Lock()
		d.bySrc = idx
		d.loaded = true
		d.mu.Unlock()
	})
	return d.loadErr
}

func (d *debianIndex) Lookup(sourcePkg, cve string) []DistroStatus {
	if d == nil || sourcePkg == "" || cve == "" {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.loaded {
		return nil
	}
	pkg, ok := d.bySrc[sourcePkg]
	if !ok {
		return nil
	}
	rec, ok := pkg[cve]
	if !ok {
		return nil
	}
	out := make([]DistroStatus, 0, len(rec.Releases))
	for rel, info := range rec.Releases {
		out = append(out, DistroStatus{
			Distro:     "debian",
			Release:    rel,
			Status:     normaliseDebianStatus(info),
			FixVersion: info.FixedVersion,
			Urgency:    info.Urgency,
		})
	}
	return out
}

func (d *debianIndex) LookupSource(sourcePkg string) map[string]debianCVE {
	if d == nil || sourcePkg == "" {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.loaded {
		return nil
	}
	pkg := d.bySrc[sourcePkg]
	if len(pkg) == 0 {
		return nil
	}
	out := make(map[string]debianCVE, len(pkg))
	for k, v := range pkg {
		out[k] = v
	}
	return out
}

func normaliseDebianStatus(r debianRelease) string {
	if r.NoDSA != "" {

		if strings.Contains(strings.ToLower(r.NoDSAReason), "postponed") {
			return "postponed"
		}
		return "no-dsa"
	}
	switch strings.ToLower(strings.TrimSpace(r.Status)) {
	case "resolved":
		return "resolved"
	case "open":
		return "open"
	case "undetermined":
		return "undetermined"
	case "end-of-life":
		return "end-of-life"
	case "not-affected":
		return "not-affected"
	case "ignored":
		return "ignored"
	case "postponed":
		return "postponed"
	default:
		return strings.ToLower(strings.TrimSpace(r.Status))
	}
}

func applyDebian(results []*ComponentResult, idx *debianIndex) {
	if idx == nil {
		return
	}
	for _, r := range results {
		if !isDebianEcosystem(r.System) {
			continue
		}
		src := r.Source
		if src == "" {
			src = r.Name
		}
		for vi := range r.Vulnerabilities {
			v := &r.Vulnerabilities[vi]
			if v.CVE == "" {
				continue
			}
			hits := idx.Lookup(src, v.CVE)
			if len(hits) == 0 {
				continue
			}
			v.DistroStatus = mergeDistroStatus(v.DistroStatus, hits)
		}
	}
}

func mergeDistroStatus(existing, incoming []DistroStatus) []DistroStatus {
	out := make([]DistroStatus, 0, len(existing)+len(incoming))
	keep := map[string]bool{}
	for _, in := range incoming {
		key := in.Distro + "/" + in.Release
		keep[key] = true
		out = append(out, in)
	}
	for _, ex := range existing {
		key := ex.Distro + "/" + ex.Release
		if keep[key] {
			continue
		}
		out = append(out, ex)
	}
	return out
}

func isDebianEcosystem(sys string) bool {
	switch strings.ToLower(sys) {
	case "debian", "ubuntu":
		return true
	}
	return false
}
