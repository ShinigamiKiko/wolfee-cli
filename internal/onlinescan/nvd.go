package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	nvdDefaultMaxLookups = 60
)

var nvdEndpointForTest = ""

func nvdEndpointURL() string {
	if nvdEndpointForTest != "" {
		return nvdEndpointForTest
	}
	return nvdEndpoint
}

type nvdQueryResult int

const (
	nvdQueryError nvdQueryResult = iota
	nvdQueryScored
	nvdQueryAbsent
)

func nvdMaxLookups() int {
	if v := strings.TrimSpace(os.Getenv("WOLFEE_NVD_MAX_LOOKUPS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return nvdDefaultMaxLookups
}

type nvdResp struct {
	Vulnerabilities []nvdVulnEntry `json:"vulnerabilities"`
}

type nvdVulnEntry struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string        `json:"id"`
	Published    string        `json:"published,omitempty"`
	LastModified string        `json:"lastModified,omitempty"`
	Weaknesses   []nvdWeakness `json:"weaknesses,omitempty"`
	Metrics      nvdMetrics    `json:"metrics"`
}

type nvdWeakness struct {
	Description []nvdLangValue `json:"description"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSv31 []nvdCvssEntry `json:"cvssMetricV31"`
	CVSSv30 []nvdCvssEntry `json:"cvssMetricV30"`
	CVSSv2  []nvdCvssEntry `json:"cvssMetricV2"`
}

type nvdCvssEntry struct {
	CVSSData nvdCvssData `json:"cvssData"`
	BaseSev  string      `json:"baseSeverity,omitempty"`
}

type nvdCvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity,omitempty"`
}

type nvdScore struct {
	Severity     string
	Score        float64
	Vector       string
	CWEs         []string
	Published    string
	LastModified string
}

func fetchNVDScores(ctx context.Context, hc *http.Client, cves []string, log ProgressLogger) map[string]nvdScore {
	if len(cves) == 0 {
		return nil
	}
	cache := openNVDCache()
	out := map[string]nvdScore{}

	var miss []string
	var negSkipped int
	for _, cve := range cves {
		switch s, st := cache.lookup(cve); st {
		case nvdCacheHit:
			out[cve] = s
		case nvdCacheNegative:
			negSkipped++
		default:
			miss = append(miss, cve)
		}
	}
	if log != nil && (len(out) > 0 || negSkipped > 0) {
		log.Step(fmt.Sprintf("NVD cache: %d scored, %d known-absent (skipped); querying NVD for %d new CVEs",
			len(out), negSkipped, len(miss)))
	}
	cves = miss

	if len(cves) == 0 {
		return out
	}
	cap := nvdMaxLookups()
	if len(cves) > cap {
		cves = cves[:cap]
	}

	apiKey := strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	delay := 6500 * time.Millisecond
	if apiKey != "" {
		delay = 700 * time.Millisecond
	}

	for i, cve := range cves {
		if ctx.Err() != nil {
			cache.flush()
			return out
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				cache.flush()
				return out
			case <-time.After(delay):
			}
		}
		switch s, res := queryNVD(ctx, hc, apiKey, cve); res {
		case nvdQueryScored:
			out[cve] = s
			cache.store(cve, s)
		case nvdQueryAbsent:

			cache.storeNegative(cve)
		case nvdQueryError:

		}
		if log != nil && (i+1)%10 == 0 {
			log.Progress(i+1, len(cves), "nvd "+cve)
		}
	}
	cache.flush()
	return out
}

func queryNVD(ctx context.Context, hc *http.Client, apiKey, cve string) (nvdScore, nvdQueryResult) {
	u, _ := url.Parse(nvdEndpointURL())
	q := u.Query()
	q.Set("cveId", cve)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nvdScore{}, nvdQueryError
	}
	req.Header.Set("User-Agent", "wolfee-cli/online")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nvdScore{}, nvdQueryError
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {

		return nvdScore{}, nvdQueryError
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nvdScore{}, nvdQueryError
	}
	var doc nvdResp
	if err := json.Unmarshal(body, &doc); err != nil {
		return nvdScore{}, nvdQueryError
	}
	if len(doc.Vulnerabilities) == 0 {
		return nvdScore{}, nvdQueryAbsent
	}
	nvdEntry := doc.Vulnerabilities[0].CVE
	m := nvdEntry.Metrics

	var s nvdScore
	var found bool
	if e := pickNVDEntry(m.CVSSv31); e != nil {
		s = entryToScore(*e)
		found = true
	} else if e := pickNVDEntry(m.CVSSv30); e != nil {
		s = entryToScore(*e)
		found = true
	} else if e := pickNVDEntry(m.CVSSv2); e != nil {
		s = entryToScore(*e)
		found = true
	}
	if !found {

		return nvdScore{}, nvdQueryAbsent
	}
	s.CWEs = extractNVDCWEs(nvdEntry.Weaknesses)
	s.Published = nvdEntry.Published
	s.LastModified = nvdEntry.LastModified
	return s, nvdQueryScored
}

func pickNVDEntry(es []nvdCvssEntry) *nvdCvssEntry {
	for i := range es {
		if es[i].CVSSData.BaseScore > 0 || es[i].CVSSData.VectorString != "" {
			return &es[i]
		}
	}
	return nil
}

func entryToScore(e nvdCvssEntry) nvdScore {
	sev := strings.ToUpper(strings.TrimSpace(e.CVSSData.BaseSeverity))
	if sev == "" {
		sev = strings.ToUpper(strings.TrimSpace(e.BaseSev))
	}
	if sev == "" && e.CVSSData.BaseScore > 0 {
		sev = severityFromCVSS(e.CVSSData.BaseScore)
	}
	if sev == "MODERATE" {
		sev = SevMedium
	}
	return nvdScore{
		Severity: sev,
		Score:    e.CVSSData.BaseScore,
		Vector:   e.CVSSData.VectorString,
	}
}

func applyNVD(results []*ComponentResult, scores map[string]nvdScore) {
	if len(scores) == 0 {
		return
	}
	for _, r := range results {
		for vi := range r.Vulnerabilities {
			v := &r.Vulnerabilities[vi]
			if v.CVE == "" {
				continue
			}
			s, ok := scores[v.CVE]
			if !ok {
				continue
			}
			if v.Severity == "" && s.Severity != "" {
				v.Severity = s.Severity
				if s.Score > 0 {
					v.CVSS = s.Score
				}
				if s.Vector != "" {
					v.CVSSVector = s.Vector
				}
				v.SeveritySource = "NVD"
			}
			if len(v.CWEs) == 0 && len(s.CWEs) > 0 {
				v.CWEs = s.CWEs
			}
			if v.Published == "" && s.Published != "" {
				v.Published = s.Published
			}
			if v.Modified == "" && s.LastModified != "" {
				v.Modified = s.LastModified
			}
		}
	}
}

func extractNVDCWEs(weaknesses []nvdWeakness) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, w := range weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				if _, dup := seen[d.Value]; !dup {
					seen[d.Value] = struct{}{}
					out = append(out, d.Value)
				}
			}
		}
	}
	return out
}

func cvesNeedingNVD(results []*ComponentResult) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			if v.Severity != "" || v.CVE == "" {
				continue
			}
			if _, dup := seen[v.CVE]; dup {
				continue
			}
			seen[v.CVE] = struct{}{}
			out = append(out, v.CVE)
		}
	}
	sort.Strings(out)
	return out
}

func FetchCVESeverities(ctx context.Context, cves []string, o Options) map[string]string {
	if len(cves) == 0 {
		return nil
	}
	hc := o.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	scores := fetchNVDScores(ctx, hc, cves, o.Logger)
	out := make(map[string]string, len(scores))
	for cve, sc := range scores {
		if sc.Severity != "" {
			out[cve] = sc.Severity
		} else if sc.Score > 0 {
			out[cve] = SeverityFromScore(sc.Score)
		}
	}
	return out
}
