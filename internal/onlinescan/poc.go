package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const rawTemplate = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/%s/%s.json"

var rawTemplateOverride string

func pocRawURL(year, cve string) string {
	tpl := rawTemplate
	if rawTemplateOverride != "" {
		tpl = rawTemplateOverride
	}
	return fmt.Sprintf(tpl, year, cve)
}

const pocPrefetchConcurrency = 16

const pocDefaultMaxLookups = 400

func pocMaxLookups() int {
	v := strings.TrimSpace(os.Getenv("WOLFEE_POC_MAX_LOOKUPS"))
	if v == "" {
		return pocDefaultMaxLookups
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return pocDefaultMaxLookups
	}
	if n < 0 {
		return pocDefaultMaxLookups
	}
	return n
}

type pocEntry struct {
	HTMLURL         string `json:"html_url"`
	StargazersCount int    `json:"stargazers_count"`
}

type pocFetcher struct {
	mu    sync.Mutex
	cache map[string][]string
}

func newPoCFetcher() *pocFetcher {
	return &pocFetcher{cache: map[string][]string{}}
}

func (p *pocFetcher) Prefetch(ctx context.Context, hc *http.Client, cves []string, log ProgressLogger) {
	if len(cves) == 0 {
		return
	}
	budget := pocMaxLookups()
	if budget == 0 {
		if log != nil {
			log.Step("PoC stage disabled (WOLFEE_POC_MAX_LOOKUPS=0)")
		}
		return
	}

	sort.Slice(cves, func(i, j int) bool { return cves[i] > cves[j] })
	if len(cves) > budget {
		if log != nil {
			log.Step(fmt.Sprintf("PoC budget: looking up %d/%d CVEs (raise via WOLFEE_POC_MAX_LOOKUPS)", budget, len(cves)))
		}
		cves = cves[:budget]
	} else if log != nil {
		log.Step(fmt.Sprintf("Fetching PoC-in-GitHub links for %d CVEs", len(cves)))
	}

	sem := make(chan struct{}, pocPrefetchConcurrency)
	var wg sync.WaitGroup
	var doneMu sync.Mutex
	done := 0

	var toFetch []string
	for _, cve := range cves {
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		p.mu.Lock()
		_, cached := p.cache[cve]
		p.mu.Unlock()
		if !cached {
			toFetch = append(toFetch, cve)
		}
	}
	total := len(toFetch)

	for _, cve := range toFetch {
		if ctx.Err() != nil {
			break
		}
		cve := cve
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var links []string
			const maxAttempts = 3
			for attempt := 0; attempt < maxAttempts; attempt++ {
				var definitive bool
				links, definitive = p.fetch(ctx, hc, cve, 3)
				if definitive {
					p.mu.Lock()
					p.cache[cve] = links
					p.mu.Unlock()
					break
				}

				if attempt < maxAttempts-1 {
					wait := time.Duration(1<<uint(attempt)) * time.Second
					select {
					case <-ctx.Done():
						return
					case <-time.After(wait):
					}
				}
			}

			doneMu.Lock()
			done++
			cur := done
			doneMu.Unlock()
			if log != nil && cur%50 == 0 {
				log.Progress(cur, total, "poc "+cve)
			}
		}()
	}
	wg.Wait()
	if log != nil && done > 0 {
		log.Progress(done, total, "poc done")
	}
}

func (p *pocFetcher) Lookup(_ context.Context, _ *http.Client, cve string, _ int) []string {
	if cve == "" || !strings.HasPrefix(cve, "CVE-") {
		return nil
	}
	p.mu.Lock()
	v := p.cache[cve]
	p.mu.Unlock()
	return v
}

func (p *pocFetcher) fetch(ctx context.Context, hc *http.Client, cve string, maxLinks int) ([]string, bool) {

	parts := strings.SplitN(cve, "-", 3)
	if len(parts) < 3 {
		return nil, true
	}
	year := parts[1]
	urlStr := pocRawURL(year, cve)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, true
	}
	req.Header.Set("User-Agent", "wolfee-cli/online")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:

	case http.StatusNotFound:

		return nil, true
	case http.StatusTooManyRequests:

		return nil, false
	default:
		if resp.StatusCode >= 500 {
			return nil, false
		}
		return nil, true
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	var entries []pocEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, true
	}

	links := make([]string, 0, maxLinks)
	for i := 0; i < maxLinks && i < len(entries); i++ {
		bestIdx := -1
		for j := range entries {
			if entries[j].HTMLURL == "" {
				continue
			}
			if bestIdx == -1 || entries[j].StargazersCount > entries[bestIdx].StargazersCount {
				bestIdx = j
			}
		}
		if bestIdx == -1 {
			break
		}
		links = append(links, entries[bestIdx].HTMLURL)
		entries[bestIdx].HTMLURL = ""
	}
	return links, true
}
