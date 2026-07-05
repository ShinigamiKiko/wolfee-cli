package onlinescan

import (
	"context"
	"net/http"
)

// QueryPURLVulns runs a single OSV.dev query for the given PURL (which should
// include a concrete @version) and returns the vulnerabilities affecting it.
// Malware entries (MAL-*) are filtered out by the underlying query. It is used
// by the remediation stage to confirm whether a resolved package version is
// still affected by a specific advisory.
func QueryPURLVulns(ctx context.Context, hc *http.Client, purl string) ([]Vulnerability, error) {
	vulns, _, err := queryOSV(ctx, hc, purl)
	return vulns, err
}

// DefaultHTTPClient returns the same HTTP client configuration the online scan
// uses, so callers outside this package can reuse consistent timeouts.
func DefaultHTTPClient() *http.Client {
	return defaultHTTPClient()
}
