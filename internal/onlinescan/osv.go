package onlinescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const osvEndpoint = "https://api.osv.dev/v1/query"

type osvQueryReq struct {
	Package   osvPackage `json:"package"`
	PageToken string     `json:"page_token,omitempty"`
}
type osvPackage struct {
	PURL string `json:"purl"`
}

type osvQueryResp struct {
	Vulns         []osvVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token,omitempty"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Published        string         `json:"published,omitempty"`
	Modified         string         `json:"modified,omitempty"`
	Severity         []osvSeverity  `json:"severity,omitempty"`
	Affected         []osvAffected  `json:"affected,omitempty"`
	References       []osvReference `json:"references,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package           osvAffectedPkg `json:"package,omitempty"`
	Ranges            []osvRange     `json:"ranges,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
}

type osvAffectedPkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}
type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

const osvMaxPages = 5

func queryOSV(ctx context.Context, hc *http.Client, purl string) (vulns []Vulnerability, mal Malware, err error) {
	normalized := normalizePURLForOSV(purl)
	pageToken := ""
	for page := 0; page < osvMaxPages; page++ {
		body, _ := json.Marshal(osvQueryReq{
			Package:   osvPackage{PURL: normalized},
			PageToken: pageToken,
		})
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, osvEndpoint, bytes.NewReader(body))
		if reqErr != nil {
			return nil, Malware{}, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "wolfee-cli/online")

		resp, doErr := hc.Do(req)
		if doErr != nil {
			return nil, Malware{}, fmt.Errorf("osv request: %w", doErr)
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, Malware{}, fmt.Errorf("osv read: %w", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, Malware{}, fmt.Errorf("osv: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		var out osvQueryResp
		if jsonErr := json.Unmarshal(respBody, &out); jsonErr != nil {
			return nil, Malware{}, fmt.Errorf("osv decode: %w", jsonErr)
		}

		for _, v := range out.Vulns {
			if strings.HasPrefix(v.ID, "MAL-") {

				if !mal.Found {
					mal = Malware{
						Found:     true,
						ID:        v.ID,
						Summary:   firstNonEmpty(v.Summary, v.Details),
						Reference: firstReference(v.References),
						Sources:   []string{"OSV"},
					}
				}
				mal.MalIDs = appendUnique(mal.MalIDs, v.ID)
				continue
			}
			vulns = append(vulns, mapOSV(v))
		}

		if out.NextPageToken == "" {
			break
		}
		pageToken = out.NextPageToken
	}
	return vulns, mal, nil
}

func mapOSV(v osvVuln) Vulnerability {
	out := Vulnerability{
		ID:          v.ID,
		Aliases:     v.Aliases,
		Title:       v.Summary,
		Description: v.Details,
		Summary:     firstNonEmpty(v.Summary, v.Details),
		Published:   v.Published,
		Modified:    v.Modified,
		Reference:   firstReference(v.References),
	}
	out.CVE = pickCVE(v.ID, v.Aliases)
	out.Severity, out.CVSS, out.CVSSVector = deriveSeverity(v)
	if out.Severity != "" {
		out.SeveritySource = "OSV"
	}
	out.CWEs = extractOSVCWEs(v)
	out.VulnerableSymbols = extractVulnSymbols(v)
	out.Fixed = collectFixedVersions(v.Affected)
	out.DistroStatus = collectOSVDistroStatus(v)
	return out
}

func extractOSVCWEs(v osvVuln) []string {
	if v.DatabaseSpecific == nil {
		return nil
	}
	raw, ok := v.DatabaseSpecific["cwe_ids"]
	if !ok {
		return nil
	}
	switch val := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

func extractVulnSymbols(v osvVuln) []VulnImport {
	var out []VulnImport
	seen := map[string]int{}
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, "Go") || a.EcosystemSpecific == nil {
			continue
		}
		rawImports, ok := a.EcosystemSpecific["imports"].([]any)
		if !ok {
			continue
		}
		for _, ri := range rawImports {
			im, ok := ri.(map[string]any)
			if !ok {
				continue
			}
			path, _ := im["path"].(string)
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			var syms []string
			if rawSyms, ok := im["symbols"].([]any); ok {
				for _, rs := range rawSyms {
					if s, ok := rs.(string); ok && strings.TrimSpace(s) != "" {
						syms = append(syms, s)
					}
				}
			}
			if idx, dup := seen[path]; dup {
				out[idx].Symbols = mergeUnique(out[idx].Symbols, syms)
				continue
			}
			seen[path] = len(out)
			out = append(out, VulnImport{Path: path, Symbols: syms})
		}
	}
	return out
}

func mergeUnique(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	have := make(map[string]struct{}, len(a))
	for _, s := range a {
		have[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := have[s]; !ok {
			have[s] = struct{}{}
			a = append(a, s)
		}
	}
	return a
}

func deriveSeverity(v osvVuln) (sev string, score float64, vector string) {
	if v.DatabaseSpecific != nil {
		if s, ok := v.DatabaseSpecific["severity"].(string); ok {
			switch strings.ToUpper(strings.TrimSpace(s)) {
			case "CRITICAL":
				sev = SevCritical
			case "HIGH":
				sev = SevHigh
			case "MODERATE", "MEDIUM":
				sev = SevMedium
			case "LOW":
				sev = SevLow
			}
		}

		if f, ok := v.DatabaseSpecific["cvss_score"].(float64); ok && score == 0 {
			score = f
		}
	}

	for _, s := range v.Severity {
		raw := strings.TrimSpace(s.Score)
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "CVSS:") || isV2Vector(raw) {
			if vector == "" {
				vector = raw
			}
			if score == 0 {
				if f, _ := scoreCVSSVector(raw); f > 0 {
					score = f
				}
			}
			continue
		}
		if score == 0 {
			if f, err := strconv.ParseFloat(raw, 64); err == nil {
				score = f
			}
		}
	}
	if sev == "" && score > 0 {
		sev = severityFromCVSS(score)
	}
	return sev, score, vector
}

func isV2Vector(s string) bool {
	return strings.Contains(s, "Au:") && strings.Contains(s, "AV:")
}

func parseCVSSScore(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasPrefix(s, "CVSS:") || isV2Vector(s) {
		f, _ := scoreCVSSVector(s)
		return f
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}

func severityFromCVSS(f float64) string {
	switch {
	case f >= 9.0:
		return SevCritical
	case f >= 7.0:
		return SevHigh
	case f >= 4.0:
		return SevMedium
	case f > 0:
		return SevLow
	}
	return SevUnknown
}

func collectFixedVersions(aff []osvAffected) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, a := range aff {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				if _, dup := seen[e.Fixed]; dup {
					continue
				}
				seen[e.Fixed] = struct{}{}
				out = append(out, e.Fixed)
			}
		}
	}
	return out
}

func pickCVE(id string, aliases []string) string {
	if isCVEID(id) {
		return id
	}
	for _, a := range aliases {
		if isCVEID(a) {
			return a
		}
	}
	if cve := extractEmbeddedCVE(id); cve != "" {
		return cve
	}
	for _, a := range aliases {
		if cve := extractEmbeddedCVE(a); cve != "" {
			return cve
		}
	}
	return ""
}

var embeddedCVEPattern = regexp.MustCompile(`(?:^|[^0-9A-Za-z])(CVE-[0-9]{4}-[0-9]{4,})(?:$|[^0-9])`)

func extractEmbeddedCVE(s string) string {
	m := embeddedCVEPattern.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func isCVEID(s string) bool {
	if !strings.HasPrefix(s, "CVE-") {
		return false
	}
	rest := s[4:]
	dash := strings.Index(rest, "-")
	if dash < 4 {
		return false
	}
	year, num := rest[:dash], rest[dash+1:]
	if len(year) != 4 || !allDigits(year) {
		return false
	}
	if len(num) < 4 || !allDigits(num) {
		return false
	}
	return true
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func collectOSVDistroStatus(v osvVuln) []DistroStatus {
	var out []DistroStatus
	for _, a := range v.Affected {
		distro, release := parseDistroEcosystem(a.Package.Ecosystem)
		if distro == "" {
			continue
		}
		st := DistroStatus{Distro: distro, Release: release}

		if a.EcosystemSpecific != nil {
			if u, ok := a.EcosystemSpecific["urgency"].(string); ok {
				st.Urgency = u
			}
		}

		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					st.FixVersion = e.Fixed
					break
				}
			}
			if st.FixVersion != "" {
				break
			}
		}
		if st.FixVersion != "" {
			st.Status = "resolved"
		} else {
			st.Status = "open"
		}
		out = append(out, st)
	}
	return out
}

func parseDistroEcosystem(eco string) (distro, release string) {
	if eco == "" {
		return "", ""
	}
	parts := strings.SplitN(eco, ":", 2)
	head := strings.ToLower(parts[0])
	switch head {
	case "debian", "ubuntu", "alpine", "rocky", "almalinux", "redhat", "rhel", "suse", "opensuse", "amazon", "amazonlinux", "photon", "wolfi", "chainguard", "mariner":
		distro = head
	default:
		return "", ""
	}
	if len(parts) == 2 {
		release = parts[1]
	}
	return distro, release
}

func firstReference(refs []osvReference) string {
	for _, r := range refs {

		if r.Type == "ADVISORY" {
			return r.URL
		}
	}
	for _, r := range refs {
		if r.URL != "" {
			return r.URL
		}
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func appendUnique(xs []string, s string) []string {
	if s == "" {
		return xs
	}
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func normalizePURLForOSV(p string) string {
	const oldPrefix = "pkg:github/"
	const newPrefix = "pkg:githubactions/"
	if strings.HasPrefix(p, oldPrefix) {
		return newPrefix + p[len(oldPrefix):]
	}
	return p
}
