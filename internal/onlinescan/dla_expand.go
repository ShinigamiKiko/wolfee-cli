package onlinescan

import (
	"regexp"
	"strings"
)

var advisoryIDPattern = regexp.MustCompile(`^(?:DLA|DSA|USN)-[0-9]+(?:-[0-9]+)?$`)

var severityRank = map[string]int{
	"":              0,
	SevUnknownLabel: 0,
	SevLow:          1,
	SevMedium:       2,
	SevHigh:         3,
	SevCritical:     4,
}

func expandAdvisoryRows(results []*ComponentResult, idx *dlaIndex) {
	if idx == nil || !idx.IsLoaded() {
		return
	}
	sevByCVE := buildSeverityIndex(results)
	if len(sevByCVE) == 0 {

		return
	}
	for _, r := range results {
		for vi := range r.Vulnerabilities {
			v := &r.Vulnerabilities[vi]
			if !isAdvisoryRow(v) {
				continue
			}
			cves := idx.LookupAdvisory(v.ID)
			if len(cves) == 0 {
				continue
			}
			worstSev, worstCVE := pickWorstSeverity(cves, sevByCVE)
			if worstSev == "" {
				continue
			}
			v.Severity = worstSev
			v.SeveritySource = "dla-expand:" + worstCVE

			v.RelatedAdvisories = mergeStringSet(v.RelatedAdvisories, []string{v.ID})
			v.Aliases = mergeStringSet(v.Aliases, cves)
		}
	}
}

func isAdvisoryRow(v *Vulnerability) bool {
	if v.CVE != "" {
		return false
	}
	return advisoryIDPattern.MatchString(strings.TrimSpace(v.ID))
}

func buildSeverityIndex(results []*ComponentResult) map[string]string {
	out := map[string]string{}
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			cve := v.CVE
			if cve == "" {
				continue
			}
			s := strings.ToUpper(strings.TrimSpace(v.Severity))
			if s == "" || s == SevUnknownLabel {
				continue
			}
			if severityRank[s] > severityRank[out[cve]] {
				out[cve] = s
			}
		}
	}
	return out
}

func pickWorstSeverity(cves []string, sev map[string]string) (string, string) {
	bestSev, bestCVE := "", ""
	for _, c := range cves {
		s := sev[c]
		if s == "" {
			continue
		}
		if severityRank[s] > severityRank[bestSev] {
			bestSev = s
			bestCVE = c
		}
	}
	return bestSev, bestCVE
}

func (d *dlaIndex) IsLoaded() bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded
}
