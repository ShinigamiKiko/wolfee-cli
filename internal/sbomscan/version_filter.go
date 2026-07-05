package sbomscan

import (
	"strconv"
	"strings"
)

// filterVulnsByVersion drops findings that cannot apply to a component's actual
// version. For OS packages distro_filter already does version matching, and OSV
// filters language packages server-side - this is a safety net for any other
// path (trivy, cross-source merges) that might attach a CVE already fixed at or
// below the installed version.
//
// The rule is deliberately conservative: a finding is dropped only when the
// component version and every listed fix parse as plain releases AND the version
// is >= all of them. Call-graph-confirmed (reachable) findings are never
// dropped, and anything that does not parse cleanly is kept.
func filterVulnsByVersion(components []ComponentReport) {
	for i := range components {
		c := &components[i]
		if c.Language == "os" || componentLanguage(c.System, c.PURL) == "os" {
			continue
		}
		cur, ok := parseRelease(c.Version)
		if !ok {
			continue
		}
		filtered := c.Vulnerabilities[:0]
		changed := false
		for _, v := range c.Vulnerabilities {
			if v.Reachable != "reachable" && versionPastAllFixes(cur, v.Fixed) {
				changed = true
				continue
			}
			filtered = append(filtered, v)
		}
		if changed {
			c.Vulnerabilities = filtered
			c.TopSeverity, c.VulnCount = topAndCount(c.Vulnerabilities)
		}
	}
}

// versionPastAllFixes reports whether cur is at or above every fix in fixes.
// Returns false when there are no fixes or any fix is unparseable, so unknown
// data is always treated as "still affected".
func versionPastAllFixes(cur []int, fixes []string) bool {
	if len(fixes) == 0 {
		return false
	}
	for _, f := range fixes {
		fv, ok := parseRelease(f)
		if !ok {
			return false
		}
		if compareRelease(cur, fv) < 0 {
			return false
		}
	}
	return true
}

// parseRelease parses a plain dotted release like "v0.49.0" or "1.25.10" into
// its numeric segments. Pre-release and build metadata (anything with '-' or
// '+') are rejected so ambiguous versions are left untouched.
func parseRelease(v string) ([]int, bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "v")
	if v == "" || strings.ContainsAny(v, "-+ ") {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// compareRelease compares two release segment slices, treating missing trailing
// segments as zero (so 1.2 == 1.2.0).
func compareRelease(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
