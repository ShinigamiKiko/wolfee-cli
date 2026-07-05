package onlinescan

import (
	"net"
	"net/http"
	"strings"
	"time"
)

func deduplicateBySourcePackage(results []*ComponentResult) {
	type srcKey struct{ sys, src string }
	seen := make(map[srcKey]map[string]struct{})
	for _, r := range results {
		if !isDebianEcosystem(r.System) {
			continue
		}
		src := r.Source
		if src == "" {
			src = r.Name
		}
		k := srcKey{r.System, src}
		if seen[k] == nil {
			seen[k] = make(map[string]struct{})
		}
		filtered := make([]Vulnerability, 0, len(r.Vulnerabilities))
		for _, v := range r.Vulnerabilities {
			id := v.CVE
			if id == "" {
				id = v.ID
			}
			if id == "" {

				filtered = append(filtered, v)
				continue
			}
			if _, dup := seen[k][id]; dup {
				continue
			}
			seen[k][id] = struct{}{}
			filtered = append(filtered, v)
		}
		r.Vulnerabilities = filtered
	}
}

func normaliseSeverities(results []*ComponentResult) {
	for _, r := range results {
		for i := range r.Vulnerabilities {
			if r.Vulnerabilities[i].Severity == "" {
				r.Vulnerabilities[i].Severity = SevUnknownLabel
			}
		}
	}
}

func anyDebianComponent(results []*ComponentResult) bool {
	for _, r := range results {
		if isDebianEcosystem(r.System) {
			return true
		}
	}
	return false
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func uniqueCVEs(results []*ComponentResult) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			cve := canonicalCVE(v.CVE)
			if cve == "" {
				continue
			}
			if _, dup := seen[cve]; dup {
				continue
			}
			seen[cve] = struct{}{}
			out = append(out, cve)
		}
	}
	return out
}

func canonicalCVE(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if isCVEID(s) {
		return s
	}
	return extractEmbeddedCVE(s)
}

func normaliseCVEFields(results []*ComponentResult) {
	for _, r := range results {
		for vi := range r.Vulnerabilities {
			if c := canonicalCVE(r.Vulnerabilities[vi].CVE); c != r.Vulnerabilities[vi].CVE {
				r.Vulnerabilities[vi].CVE = c
			}
		}
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
