package onlinescan

import (
	"strconv"
	"strings"
)

// orderFixesForVersion puts the first fix from the installed version's branch
// first. Unknown version formats retain OSV's original order.
func orderFixesForVersion(fixes []string, installed string) []string {
	if len(fixes) < 2 {
		return fixes
	}
	cur, ok := parseFixRelease(installed)
	if !ok {
		return fixes
	}

	best := -1
	for i, raw := range fixes {
		fix, ok := parseFixRelease(raw)
		if !ok || compareFixRelease(fix, cur) <= 0 {
			continue
		}
		if best == -1 || compareFixRelease(fix, mustParseFixRelease(fixes[best])) < 0 {
			best = i
		}
	}
	if best <= 0 {
		return fixes
	}

	out := make([]string, 0, len(fixes))
	out = append(out, fixes[best])
	out = append(out, fixes[:best]...)
	out = append(out, fixes[best+1:]...)
	return out
}

func purlVersion(purl string) string {
	purl = strings.TrimSpace(purl)
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	if i := strings.LastIndexByte(purl, '@'); i >= 0 {
		return purl[i+1:]
	}
	return ""
}

type fixRelease struct {
	parts    []int
	wildcard bool
}

func parseFixRelease(raw string) (fixRelease, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(raw), "v"))
	if raw == "" || strings.ContainsAny(raw, "-+ ") {
		return fixRelease{}, false
	}
	parts := strings.Split(raw, ".")
	parsed := make([]int, 0, len(parts))
	wildcard := false
	for i, part := range parts {
		if part == "x" || part == "*" {
			if i != len(parts)-1 {
				return fixRelease{}, false
			}
			wildcard = true
			break
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return fixRelease{}, false
		}
		parsed = append(parsed, n)
	}
	if len(parsed) == 0 {
		return fixRelease{}, false
	}
	return fixRelease{parts: parsed, wildcard: wildcard}, true
}

func mustParseFixRelease(raw string) fixRelease {
	parsed, _ := parseFixRelease(raw)
	return parsed
}

// compareFixRelease compares release prefixes and treats a wildcard as the
// beginning of that branch. Thus 3.14.x is greater than 3.5.1 and less than
// 4.0.0, while 3.14.1 is greater than 3.14.x only when its prefix is longer.
func compareFixRelease(a, b fixRelease) int {
	n := len(a.parts)
	if len(b.parts) > n {
		n = len(b.parts)
	}
	for i := 0; i < n; i++ {
		if i >= len(a.parts) || i >= len(b.parts) {
			break
		}
		if a.parts[i] < b.parts[i] {
			return -1
		}
		if a.parts[i] > b.parts[i] {
			return 1
		}
	}
	if len(a.parts) != len(b.parts) {
		if len(a.parts) < len(b.parts) {
			return -1
		}
		return 1
	}
	if a.wildcard != b.wildcard {
		if a.wildcard {
			return -1
		}
		return 1
	}
	return 0
}
