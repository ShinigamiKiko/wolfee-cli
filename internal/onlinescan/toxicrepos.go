package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var toxicReposURL = "https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/json/toxic-repos.json"

const toxicReposLoadTimeout = 15 * time.Second

var toxicReposLoadTimeoutOverride time.Duration

const toxicReposMaxBodySize = 32 << 20

type toxicReposEntry struct {
	ID          int    `json:"id"`
	ProblemType string `json:"problem_type"`
	Name        string `json:"name"`
	CommitLink  string `json:"commit_link"`
	Description string `json:"description"`
	PURLLink    string `json:"PURL-link"`
	PURL        string `json:"PURL"`
}

type toxicReposIndex struct {
	once sync.Once

	byPURL map[string][]toxicReposEntry

	byBaseName map[string][]toxicReposEntry

	loaded bool
}

func newToxicReposIndex() *toxicReposIndex { return &toxicReposIndex{} }

func (t *toxicReposIndex) Load(ctx context.Context, hc *http.Client) error {
	var loadErr error
	t.once.Do(func() {
		timeout := toxicReposLoadTimeout
		if toxicReposLoadTimeoutOverride > 0 {
			timeout = toxicReposLoadTimeoutOverride
		}
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, toxicReposURL, nil)
		if err != nil {
			loadErr = err
			return
		}
		req.Header.Set("User-Agent", "wolfee-cli/online")
		resp, err := hc.Do(req)
		if err != nil {
			loadErr = fmt.Errorf("toxic-repos fetch: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			loadErr = fmt.Errorf("toxic-repos: status %d", resp.StatusCode)
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, toxicReposMaxBodySize+1))
		if err != nil {
			loadErr = fmt.Errorf("toxic-repos read: %w", err)
			return
		}
		if len(body) > toxicReposMaxBodySize {
			loadErr = fmt.Errorf("toxic-repos: body exceeds %d MiB cap", toxicReposMaxBodySize>>20)
			return
		}
		var entries []toxicReposEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			loadErr = fmt.Errorf("toxic-repos decode: %w", err)
			return
		}

		t.byPURL = make(map[string][]toxicReposEntry, 64)
		t.byBaseName = make(map[string][]toxicReposEntry, 1024)
		for _, e := range entries {
			t.indexEntry(e)
		}
		t.loaded = true
	})
	return loadErr
}

func (t *toxicReposIndex) indexEntry(e toxicReposEntry) {
	if p := strings.TrimSpace(e.PURL); p != "" {
		t.byPURL[p] = append(t.byPURL[p], e)

		if at := strings.LastIndex(p, "@"); at >= 0 {
			base := p[:at]
			t.byPURL[base] = append(t.byPURL[base], e)
		}
	}

	if base := repoBaseFromURL(e.CommitLink); base != "" && len(base) >= 4 {
		key := strings.ToLower(base)
		t.byBaseName[key] = append(t.byBaseName[key], e)
	}
}

func (t *toxicReposIndex) Lookup(purl, name string) []toxicReposEntry {
	if t == nil || !t.loaded {
		return nil
	}
	if hits, ok := t.byPURL[purl]; ok && len(hits) > 0 {
		return hits
	}
	if at := strings.LastIndex(purl, "@"); at >= 0 {
		if hits, ok := t.byPURL[purl[:at]]; ok && len(hits) > 0 {
			return hits
		}
	}

	if len(name) < 4 {
		return nil
	}
	return t.byBaseName[strings.ToLower(name)]
}

func repoBaseFromURL(u string) string {
	if u == "" {
		return ""
	}

	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}

	if !strings.HasPrefix(strings.ToLower(s), "github.com/") {
		return ""
	}
	s = s[len("github.com/"):]
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	repo := parts[1]

	repo = strings.TrimSuffix(repo, ".git")
	return repo
}

func toxicReposToToxic(hits []toxicReposEntry) Toxic {
	if len(hits) == 0 {
		return Toxic{}
	}
	t := Toxic{Found: true}
	seenCat := map[string]struct{}{}
	for _, e := range hits {
		if e.ProblemType != "" {
			if _, dup := seenCat[e.ProblemType]; !dup {
				t.Categories = append(t.Categories, e.ProblemType)
				seenCat[e.ProblemType] = struct{}{}
			}
		}
		note := strings.TrimSpace(e.Description)
		if note == "" {
			note = e.Name
		}
		if e.CommitLink != "" {
			note = note + " (" + e.CommitLink + ")"
		}
		t.Notes = append(t.Notes, note)
	}
	return t
}
