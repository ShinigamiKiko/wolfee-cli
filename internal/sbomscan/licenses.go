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

var reLicenseToken = regexp.MustCompile(`[()/]|[^\s()/]+`)

// classifyLicenseExpression evaluates an SPDX expression with its grouping
// intact: OR takes the least risky alternative, AND the most risky term, AND
// binds tighter than OR, and parentheses override both. "/" is accepted as OR
// (common in non-SPDX metadata such as "MIT/GPL-2.0").
func classifyLicenseExpression(expr string) string {
	p := &licenseExprParser{tokens: reLicenseToken.FindAllString(expr, -1)}
	risk := p.parseOr()
	// Unbalanced ")" or other leftovers: evaluate the rest conservatively.
	for p.pos < len(p.tokens) {
		p.pos++
		if r := p.parseOr(); licenseRiskRank(r) > licenseRiskRank(risk) {
			risk = r
		}
	}
	return risk
}

type licenseExprParser struct {
	tokens []string
	pos    int
}

func (p *licenseExprParser) peekOp(op string) bool {
	if p.pos >= len(p.tokens) {
		return false
	}
	t := p.tokens[p.pos]
	if op == "OR" && t == "/" {
		return true
	}
	return strings.EqualFold(t, op)
}

func (p *licenseExprParser) parseOr() string {
	best := p.parseAnd()
	for p.peekOp("OR") {
		p.pos++
		r := p.parseAnd()
		if r == "" {
			continue
		}
		if best == "" || licenseRiskRank(r) < licenseRiskRank(best) {
			best = r
		}
	}
	return best
}

func (p *licenseExprParser) parseAnd() string {
	worst := p.parseAtom()
	for p.peekOp("AND") {
		p.pos++
		if r := p.parseAtom(); licenseRiskRank(r) > licenseRiskRank(worst) {
			worst = r
		}
	}
	return worst
}

func (p *licenseExprParser) parseAtom() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	if p.tokens[p.pos] == "(" {
		p.pos++
		r := p.parseOr()
		if p.pos < len(p.tokens) && p.tokens[p.pos] == ")" {
			p.pos++
		}
		return r
	}
	// A term is every word up to the next operator or parenthesis, so
	// free-form names like "GNU General Public License v3" stay together.
	base := p.words()
	exception := ""
	if p.peekOp("WITH") {
		p.pos++
		exception = p.words()
	}
	if base == "" {
		return ""
	}
	return classifyLicenseTerm(base, exception)
}

func (p *licenseExprParser) words() string {
	var parts []string
	for p.pos < len(p.tokens) {
		t := p.tokens[p.pos]
		if t == "(" || t == ")" || p.peekOp("OR") || p.peekOp("AND") || p.peekOp("WITH") {
			break
		}
		parts = append(parts, t)
		p.pos++
	}
	return strings.Join(parts, " ")
}

func classifyLicenseTerm(base, exception string) string {
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
