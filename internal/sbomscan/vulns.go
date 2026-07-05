package sbomscan

import (
	"fmt"
	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/reachability"
	"strings"
)

func bestVulnID(goID string, aliases []string) (primary string, rest []string) {
	cve, ghsa := "", ""
	var others []string
	for _, a := range aliases {
		up := strings.ToUpper(a)
		switch {
		case strings.HasPrefix(up, "CVE-"):
			if cve == "" {
				cve = a
			} else {
				others = append(others, a)
			}
		case strings.HasPrefix(up, "GHSA-"):
			if ghsa == "" {
				ghsa = a
			} else {
				others = append(others, a)
			}
		default:
			others = append(others, a)
		}
	}
	switch {
	case cve != "":
		primary = cve
		rest = append(append([]string{goID}, ghsa), others...)
	case ghsa != "":
		primary = ghsa
		rest = append([]string{goID}, others...)
	default:
		primary = goID
		rest = aliases
	}

	out := rest[:0]
	for _, s := range rest {
		if s != "" {
			out = append(out, s)
		}
	}
	return primary, out
}

func dedupeVulns(vulns []onlinescan.Vulnerability) []onlinescan.Vulnerability {
	if len(vulns) <= 1 {
		return vulns
	}
	type entry struct {
		idx int
		v   onlinescan.Vulnerability
	}

	key := func(v onlinescan.Vulnerability) string {
		if v.CVE != "" {
			return strings.ToUpper(v.CVE)
		}
		return strings.ToUpper(v.ID)
	}

	idRank := func(id string) int {
		up := strings.ToUpper(id)
		switch {
		case strings.HasPrefix(up, "GHSA-"):
			return 0
		case strings.HasPrefix(up, "GO-"):
			return 1
		default:
			return 2
		}
	}

	reachRank := func(r string) int {
		switch r {
		case string(reachability.StateReachable):
			return 0
		case string(reachability.StateUnreachable):
			return 1
		default:
			return 2
		}
	}

	order := []string{}
	best := map[string]onlinescan.Vulnerability{}
	noKeyIdx := 0
	for _, v := range vulns {
		k := key(v)
		if k == "" {

			k = fmt.Sprintf("__nokey_%d", noKeyIdx)
			noKeyIdx++
			order = append(order, k)
			best[k] = v
			continue
		}
		prev, exists := best[k]
		if !exists {
			order = append(order, k)
			best[k] = v
			continue
		}

		if idRank(v.ID) < idRank(prev.ID) {

			if v.Severity == "" {
				v.Severity = prev.Severity
			}
			if v.CVSS == 0 {
				v.CVSS = prev.CVSS
			}
			if v.CVSSVector == "" {
				v.CVSSVector = prev.CVSSVector
			}
			if v.Description == "" {
				v.Description = prev.Description
			}
			if v.Title == "" {
				v.Title = prev.Title
			}
			if v.Summary == "" {
				v.Summary = prev.Summary
			}
			if len(v.PoCs) == 0 {
				v.PoCs = prev.PoCs
			}
			if len(v.Fixed) == 0 {
				v.Fixed = prev.Fixed
			}
			if len(v.DistroStatus) == 0 {
				v.DistroStatus = prev.DistroStatus
			}
			if len(v.CWEs) == 0 {
				v.CWEs = prev.CWEs
			}
			if !v.InKEV {
				v.InKEV = prev.InKEV
			}
			if v.EPSS == 0 {
				v.EPSS = prev.EPSS
			}
			if v.EPSSPercentile == 0 {
				v.EPSSPercentile = prev.EPSSPercentile
			}
			if v.Published == "" {
				v.Published = prev.Published
			}
			if v.Reachable == "" {
				v.Reachable = prev.Reachable
			}
			if v.CallSite == "" {
				v.CallSite = prev.CallSite
			}
			if v.CallLine == "" {
				v.CallLine = prev.CallLine
			}
			prev = v
		}
		if reachRank(v.Reachable) < reachRank(prev.Reachable) {
			prev.Reachable = v.Reachable
		}
		if prev.CallSite == "" {
			prev.CallSite = v.CallSite
			prev.CallLine = v.CallLine
		}

		seen := map[string]bool{strings.ToUpper(prev.ID): true}
		for _, a := range prev.Aliases {
			seen[strings.ToUpper(a)] = true
		}
		for _, a := range v.Aliases {
			if !seen[strings.ToUpper(a)] {
				prev.Aliases = append(prev.Aliases, a)
				seen[strings.ToUpper(a)] = true
			}
		}
		if !seen[strings.ToUpper(v.ID)] {
			prev.Aliases = append(prev.Aliases, v.ID)
		}
		best[k] = prev
	}

	out := make([]onlinescan.Vulnerability, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

func vulnHasID(vulns []onlinescan.Vulnerability, target string) bool {
	upper := strings.ToUpper(target)
	for _, v := range vulns {
		if strings.ToUpper(v.ID) == upper {
			return true
		}
		for _, a := range v.Aliases {
			if strings.ToUpper(a) == upper {
				return true
			}
		}
	}
	return false
}

func topAndCount(vs []onlinescan.Vulnerability) (string, int) {
	best := 0
	for _, v := range vs {
		switch strings.ToUpper(v.Severity) {
		case onlinescan.SevCritical:
			if best < 4 {
				best = 4
			}
		case onlinescan.SevHigh:
			if best < 3 {
				best = 3
			}
		case onlinescan.SevMedium:
			if best < 2 {
				best = 2
			}
		case onlinescan.SevLow:
			if best < 1 {
				best = 1
			}
		}
	}
	switch best {
	case 4:
		return onlinescan.SevCritical, len(vs)
	case 3:
		return onlinescan.SevHigh, len(vs)
	case 2:
		return onlinescan.SevMedium, len(vs)
	case 1:
		return onlinescan.SevLow, len(vs)
	}
	return "", len(vs)
}
