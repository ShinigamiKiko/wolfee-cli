package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	epssAPIBase     = "https://api.first.org/data/v1/epss"
	epssBatchSize   = 100
	epssConcurrency = 4
)

var epssAPIURLForTest = ""

func epssAPIURL() string {
	if epssAPIURLForTest != "" {
		return epssAPIURLForTest
	}
	return epssAPIBase
}

type epssScore struct {
	EPSS, Percentile float64
}

type epssAPIResp struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

func fetchEPSS(ctx context.Context, hc *http.Client, cves []string) (map[string]epssScore, error) {
	out := make(map[string]epssScore, len(cves))
	if len(cves) == 0 {
		return out, nil
	}

	batches := make([][]string, 0, (len(cves)+epssBatchSize-1)/epssBatchSize)
	for i := 0; i < len(cves); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(cves) {
			end = len(cves)
		}
		batches = append(batches, cves[i:end])
	}

	var (
		mu        sync.Mutex
		firstErr  error
		failCount int
		wg        sync.WaitGroup
		sem       = make(chan struct{}, epssConcurrency)
	)

	for _, batch := range batches {
		batch := batch
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			scores, err := fetchEPSSBatch(ctx, hc, batch)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				failCount++
				return
			}
			for cve, s := range scores {
				out[cve] = s
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		if len(out) == 0 {
			return nil, fmt.Errorf("epss fetch: %w", firstErr)
		}

		return out, fmt.Errorf("epss fetch: %d/%d batches failed (first error: %w); EPSS scores may be incomplete",
			failCount, len(batches), firstErr)
	}
	return out, nil
}

func fetchEPSSBatch(ctx context.Context, hc *http.Client, cves []string) (map[string]epssScore, error) {
	u, _ := url.Parse(epssAPIURL())
	q := u.Query()
	q.Set("cve", strings.Join(cves, ","))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wolfee-cli/online")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, u.Host)
	}

	var apiResp epssAPIResp
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	out := make(map[string]epssScore, len(apiResp.Data))
	for _, d := range apiResp.Data {
		e, _ := strconv.ParseFloat(d.EPSS, 64)
		p, _ := strconv.ParseFloat(d.Percentile, 64)
		out[d.CVE] = epssScore{EPSS: e, Percentile: p}
	}
	return out, nil
}
