package sbomscan

import (
	"regexp"
	"strings"
)

// License risk levels for running a component in production / shipping it.
const (
	// LicenseRiskHigh: strong or network copyleft, source-available or
	// non-commercial terms (GPL, AGPL, SSPL, BUSL, CC-BY-NC, ...).
	LicenseRiskHigh = "high"
	// LicenseRiskMedium: weak / file-level copyleft (LGPL, MPL, EPL, CDDL, ...).
	LicenseRiskMedium = "medium"
	// LicenseRiskLow: permissive (MIT, Apache-2.0, BSD, ISC, ...).
	LicenseRiskLow = "low"
	// LicenseRiskUnknown: a license is declared but not recognised.
	LicenseRiskUnknown = "unknown"
)

func licenseRiskRank(r string) int {
	switch r {
	case LicenseRiskHigh:
		return 3
	case LicenseRiskMedium:
		return 2
	case LicenseRiskUnknown:
		return 1
	case LicenseRiskLow:
		return 0
	}
	return -1
}

// annotateLicenses fills the flat License / LicenseRisk fields from the
// structured cdxgen (or trivy) license list on every component.
func annotateLicenses(components []ComponentReport) {
	for i := range components {
		components[i].License, components[i].LicenseRisk = summarizeLicenses(components[i].Licenses)
	}
}

func countLicenseTotals(r *Report) {
	r.Totals.LicenseHigh, r.Totals.LicenseMedium = 0, 0
	for _, c := range r.Components {
		switch c.LicenseRisk {
		case LicenseRiskHigh:
			r.Totals.LicenseHigh++
		case LicenseRiskMedium:
			r.Totals.LicenseMedium++
		}
	}
}

// summarizeLicenses returns a display string ("MIT, GPL-2.0-only") and the
// worst risk across the declared entries. Several entries in a CycloneDX
// licenses array are treated conservatively (all apply); an explicit SPDX
// "A OR B" expression picks the least risky alternative.
func summarizeLicenses(ls []LicenseChoice) (display, risk string) {
	var parts []string
	seen := map[string]bool{}
	for _, l := range ls {
		label := licenseChoiceLabel(l)
		if label == "" || seen[strings.ToLower(label)] {
			continue
		}
		seen[strings.ToLower(label)] = true
		parts = append(parts, label)
		if r := classifyLicenseExpression(label); licenseRiskRank(r) > licenseRiskRank(risk) {
			risk = r
		}
	}
	return strings.Join(parts, ", "), risk
}

func licenseChoiceLabel(l LicenseChoice) string {
	if e := strings.TrimSpace(l.Expression); e != "" {
		return e
	}
	if l.License == nil {
		return ""
	}
	if id := strings.TrimSpace(l.License.ID); id != "" {
		return id
	}
	return strings.TrimSpace(l.License.Name)
}

var (
	reOr   = regexp.MustCompile(`(?i)\s+or\s+|\s*/\s*`)
	reAnd  = regexp.MustCompile(`(?i)\s+and\s+`)
	reWith = regexp.MustCompile(`(?i)\s+with\s+`)
)

// classifyLicenseExpression handles SPDX expressions: OR takes the least risky
// alternative, AND the most risky term.
func classifyLicenseExpression(expr string) string {
	expr = strings.NewReplacer("(", " ", ")", " ").Replace(expr)
	best := ""
	for _, alt := range reOr.Split(expr, -1) {
		worst := ""
		for _, term := range reAnd.Split(alt, -1) {
			term = strings.TrimSpace(term)
			if term == "" {
				continue
			}
			if r := classifyLicenseTerm(term); licenseRiskRank(r) > licenseRiskRank(worst) {
				worst = r
			}
		}
		if worst == "" {
			continue
		}
		if best == "" || licenseRiskRank(worst) < licenseRiskRank(best) {
			best = worst
		}
	}
	return best
}

func classifyLicenseTerm(term string) string {
	base, exception := term, ""
	if parts := reWith.Split(term, 2); len(parts) == 2 {
		base, exception = parts[0], parts[1]
	}
	risk := classifyLicenseID(base)
	// GPL + linking exception (Classpath, GCC runtime, ...) behaves like weak copyleft.
	if risk == LicenseRiskHigh && exception != "" {
		return LicenseRiskMedium
	}
	return risk
}

func classifyLicenseID(raw string) string {
	id := strings.ToUpper(strings.TrimSpace(raw))
	if id == "" {
		return ""
	}
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(id, s) {
				return true
			}
		}
		return false
	}
	pfx := func(prefixes ...string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(id, p) {
				return true
			}
		}
		return false
	}

	switch {
	// Weak copyleft first: "LGPL" contains "GPL", "LESSER GENERAL PUBLIC" contains "GENERAL PUBLIC".
	case pfx("LGPL", "MPL", "EPL", "CDDL", "CPL-", "EUPL", "CC-BY-SA", "MS-RL", "APSL", "ERPL", "NPL-"),
		has("LESSER GENERAL PUBLIC", "LIBRARY GENERAL PUBLIC", "MOZILLA PUBLIC", "ECLIPSE PUBLIC",
			"COMMON DEVELOPMENT AND DISTRIBUTION", "EUROPEAN UNION PUBLIC"):
		return LicenseRiskMedium

	case pfx("AGPL", "GPL", "SSPL", "OSL-", "RPL-", "CPAL", "SISSL", "BUSL", "ELASTIC-", "CC-BY-NC",
		"SLEEPYCAT", "QPL", "WATCOM", "PARITY", "POLYFORM", "CONFLUENT-COMMUNITY"),
		has("AFFERO", "GENERAL PUBLIC LICENSE", "SERVER SIDE PUBLIC", "BUSINESS SOURCE", "COMMONS CLAUSE",
			"COMMONS-CLAUSE", "NON-COMMERCIAL", "NONCOMMERCIAL", "PROPRIETARY", "COMMERCIAL"),
		id == "GPL" || id == "AGPL":
		return LicenseRiskHigh

	case pfx("MIT", "APACHE", "BSD", "0BSD", "ISC", "UNLICENSE", "CC0", "ZLIB", "PYTHON", "PSF",
		"ARTISTIC-2", "BLUEOAK", "WTFPL", "X11", "CURL", "OPENSSL", "BSL-1.0", "UPL", "HPND", "PUBLIC-DOMAIN",
		"PUBLIC DOMAIN", "CC-BY-", "BOOST", "UNICODE", "W3C", "OFL", "POSTGRESQL", "VIM", "RUBY", "PHP-", "NCSA",
		"ICU", "JSON", "MIT-0", "BZIP2", "LIBPNG", "IJG", "SSLEAY", "FTL", "TCL", "ZPL", "AFL", "EFL", "ECL", "NTP"),
		has("APACHE LICENSE", "BSD LICENSE", "MIT LICENSE"):
		return LicenseRiskLow
	}
	return LicenseRiskUnknown
}

// trivyLicenses converts trivy's flat license strings into CycloneDX choices.
func trivyLicenses(names []string) []LicenseChoice {
	var out []LicenseChoice
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		l := &License{Name: n}
		if !strings.ContainsAny(n, " \t") {
			l = &License{ID: n}
		}
		out = append(out, LicenseChoice{License: l})
	}
	return out
}
