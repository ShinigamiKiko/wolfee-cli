package onlinescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	ossfRepoOwner = "ossf"
	ossfRepoName  = "malicious-packages"
	ossfBranch    = "main"

	ossfEcoConcurrency = 4
)

var ecoToOSSFDir = map[string]string{
	"NPM":       "npm",
	"PYPI":      "PyPI",
	"RUBYGEMS":  "RubyGems",
	"PACKAGIST": "Packagist",
	"CARGO":     "crates.io",
	"GO":        "Go",
	"NUGET":     "NuGet",
	"MAVEN":     "Maven",
}

type ossfHit struct {
	MalID string
	Path  string
}

type ossfIndex struct {
	once          sync.Once
	err           error
	partial       bool
	partialReason string
	byKey         map[string][]ossfHit
	loaded        bool
}

func newOSSFIndex() *ossfIndex { return &ossfIndex{} }

type ghTreeNode struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type ghTree struct {
	Tree      []ghTreeNode `json:"tree"`
	Truncated bool         `json:"truncated"`
}

func (o *ossfIndex) Load(ctx context.Context, hc *http.Client) error {
	o.once.Do(func() {

		root, err := o.fetchTree(ctx, hc, ossfBranch, false)
		if err != nil {
			o.err = fmt.Errorf("ossf root tree: %w", err)
			return
		}
		osvSHA := findChildSHA(root, "osv", "tree")
		if osvSHA == "" {
			o.err = errors.New("ossf: osv/ directory not present at repo root")
			return
		}

		osvTree, err := o.fetchTree(ctx, hc, osvSHA, false)
		if err != nil {
			o.err = fmt.Errorf("ossf osv tree: %w", err)
			return
		}

		o.byKey = make(map[string][]ossfHit, 8192)
		results := o.fetchEcosystems(ctx, hc, osvTree.Tree)

		var (
			partial         bool
			rateLimitedEcos []string
			truncatedEcos   []string
			otherFailedEcos []string
		)
		for _, r := range results {
			if r.err != nil {
				partial = true
				switch {
				case isRateLimitErr(r.err):
					rateLimitedEcos = append(rateLimitedEcos, r.eco)
				default:
					otherFailedEcos = append(otherFailedEcos, r.eco)
				}
				continue
			}
			if r.tree.Truncated {

				partial = true
				truncatedEcos = append(truncatedEcos, r.eco)
			}
			for _, node := range r.tree.Tree {
				if node.Type != "blob" || !strings.HasSuffix(node.Path, ".json") {
					continue
				}

				parts := strings.Split(node.Path, "/")
				if len(parts) < 2 {
					continue
				}
				pkg := parts[0]
				malID := strings.TrimSuffix(parts[len(parts)-1], ".json")
				if !strings.HasPrefix(malID, "MAL-") {
					continue
				}
				key := r.eco + "/" + pkg
				fullPath := "osv/" + r.eco + "/" + node.Path
				o.byKey[key] = append(o.byKey[key], ossfHit{MalID: malID, Path: fullPath})
			}
		}
		if partial {

			o.partial = true
			o.partialReason = formatOSSFPartialReason(rateLimitedEcos, truncatedEcos, otherFailedEcos)
		}
		o.loaded = true
	})
	if o.err != nil {
		return o.err
	}
	if o.partial {
		return fmt.Errorf("ossf: %s", o.partialReason)
	}
	return nil
}

func isRateLimitErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 429")
}

func formatOSSFPartialReason(rateLimited, truncated, other []string) string {
	var parts []string
	if len(rateLimited) > 0 {
		parts = append(parts, fmt.Sprintf("GitHub rate-limited %d eco tree(s) [%s] - set GITHUB_TOKEN to lift the 60/hr anon cap to 5000/hr",
			len(rateLimited), strings.Join(rateLimited, ",")))
	}
	if len(truncated) > 0 {
		parts = append(parts, fmt.Sprintf("%d eco tree(s) truncated by GitHub's 100k-entry cap [%s] - recent MAL records in those ecosystems may be missed",
			len(truncated), strings.Join(truncated, ",")))
	}
	if len(other) > 0 {
		parts = append(parts, fmt.Sprintf("%d eco tree(s) failed with network/decode errors [%s]",
			len(other), strings.Join(other, ",")))
	}
	if len(parts) == 0 {
		return "index partial (cause unknown)"
	}
	return "index partial - " + strings.Join(parts, "; ")
}

type ecoResult struct {
	eco  string
	tree *ghTree
	err  error
}

func (o *ossfIndex) fetchEcosystems(ctx context.Context, hc *http.Client, ecos []ghTreeNode) []ecoResult {
	out := make([]ecoResult, 0, len(ecos))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, ossfEcoConcurrency)

	for _, eco := range ecos {
		if eco.Type != "tree" {
			continue
		}
		eco := eco
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t, err := o.fetchTree(ctx, hc, eco.SHA, true)
			mu.Lock()
			out = append(out, ecoResult{eco: eco.Path, tree: t, err: err})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func (o *ossfIndex) fetchTree(ctx context.Context, hc *http.Client, sha string, recursive bool) (*ghTree, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s",
		ossfRepoOwner, ossfRepoName, sha)
	if recursive {
		url += "?recursive=1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wolfee-cli/online")

	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github tree %s: status %d", sha, resp.StatusCode)
	}

	var t ghTree
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&t); err != nil {
		return nil, fmt.Errorf("decode tree %s: %w", sha, err)
	}
	return &t, nil
}

func findChildSHA(t *ghTree, name, kind string) string {
	if t == nil {
		return ""
	}
	for _, e := range t.Tree {
		if e.Path == name && e.Type == kind {
			return e.SHA
		}
	}
	return ""
}

func (o *ossfIndex) Lookup(system, name string) []ossfHit {
	if o == nil || !o.loaded {
		return nil
	}
	dir, ok := ecoToOSSFDir[strings.ToUpper(system)]
	if !ok {
		return nil
	}
	return o.byKey[dir+"/"+name]
}

func (o *ossfIndex) rawURL(path string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
		ossfRepoOwner, ossfRepoName, ossfBranch, path)
}
