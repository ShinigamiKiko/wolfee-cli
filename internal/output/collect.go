package output

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

func rankComponent(c reflect.Value) int {
	score := 0
	if boolNested(c, "Malware", "Found") {
		score += 1000
	}
	switch strings.ToUpper(stringField(c, "TopSeverity")) {
	case "CRITICAL":
		score += 4
	case "HIGH":
		score += 3
	case "MEDIUM":
		score += 2
	case "LOW":
		score += 1
	}
	if score == 0 && boolNested(c, "Toxic", "Found") {
		score = 1
	}
	return score
}

func hasKEV(c reflect.Value) bool {
	vulns := c.FieldByName("Vulnerabilities")
	if !vulns.IsValid() {
		return false
	}
	for i := 0; i < vulns.Len(); i++ {
		f := vulns.Index(i).FieldByName("InKEV")
		if f.IsValid() && f.Kind() == reflect.Bool && f.Bool() {
			return true
		}
	}
	return false
}

func hasPoC(c reflect.Value) bool {
	vulns := c.FieldByName("Vulnerabilities")
	if !vulns.IsValid() {
		return false
	}
	for i := 0; i < vulns.Len(); i++ {
		f := vulns.Index(i).FieldByName("PoCs")
		if f.IsValid() && f.Kind() == reflect.Slice && f.Len() > 0 {
			return true
		}
	}
	return false
}

type topVulnRow struct {
	sev      string
	id       string
	cve      string
	pkg      string
	fix      string
	reach    string
	callSite string
	callLine string
	system   string
	scope    string
	origin   string
	epss     float64
	kev      bool
	poc      bool
	rank     int
}

func collectTopVulns(components reflect.Value) []topVulnRow {
	rows := []topVulnRow{}
	for i := 0; i < components.Len(); i++ {
		c := components.Index(i)
		pkg := fmt.Sprintf("%s@%s", stringField(c, "Name"), stringField(c, "Version"))
		vulns := c.FieldByName("Vulnerabilities")
		if !vulns.IsValid() {
			continue
		}
		for vi := 0; vi < vulns.Len(); vi++ {
			vv := vulns.Index(vi)
			row := topVulnRow{
				sev:      stringField(vv, "Severity"),
				id:       stringField(vv, "ID"),
				cve:      stringField(vv, "CVE"),
				pkg:      pkg,
				fix:      firstFix(vv),
				reach:    stringField(vv, "Reachable"),
				callSite: stringField(vv, "CallSite"),
				callLine: stringField(vv, "CallLine"),
				system:   stringField(c, "System"),
				origin:   stringField(c, "Origin"),
				scope:    stringField(c, "Scope"),
			}
			if k := vv.FieldByName("InKEV"); k.IsValid() && k.Kind() == reflect.Bool {
				row.kev = k.Bool()
			}
			if e := vv.FieldByName("EPSS"); e.IsValid() && e.Kind() == reflect.Float64 {
				row.epss = e.Float()
			}
			if p := vv.FieldByName("PoCs"); p.IsValid() && p.Kind() == reflect.Slice && p.Len() > 0 {
				row.poc = true
			}
			row.rank = rankVuln(row)
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].rank > rows[j].rank })
	return rows
}

func rankVuln(r topVulnRow) int {
	score := 0
	if r.kev {
		score += 1000
	}
	if r.poc {
		score += 100
	}
	switch strings.ToUpper(r.sev) {
	case "CRITICAL":
		score += 400
	case "HIGH":
		score += 300
	case "MEDIUM":
		score += 200
	case "LOW":
		score += 100
	}
	score += int(r.epss * 100)

	if r.reach == "reachable" && score == 0 {
		score = 1
	}
	return score
}

func malwareSources(comp reflect.Value) string {
	mal := comp.FieldByName("Malware")
	if !mal.IsValid() {
		return ""
	}
	srcs := mal.FieldByName("Sources")
	if !srcs.IsValid() || srcs.Kind() != reflect.Slice || srcs.Len() == 0 {
		return ""
	}
	parts := make([]string, 0, srcs.Len())
	for i := 0; i < srcs.Len(); i++ {
		parts = append(parts, srcs.Index(i).String())
	}
	return strings.Join(parts, "+")
}

func firstToxicCategory(comp reflect.Value) string {
	tox := comp.FieldByName("Toxic")
	if !tox.IsValid() {
		return ""
	}
	cats := tox.FieldByName("Categories")
	if !cats.IsValid() || cats.Kind() != reflect.Slice || cats.Len() == 0 {
		return ""
	}
	return cats.Index(0).String()
}

func collectReachableVulns(components reflect.Value) []topVulnRow {
	var rows []topVulnRow
	for i := 0; i < components.Len(); i++ {
		c := components.Index(i)
		pkg := fmt.Sprintf("%s@%s", stringField(c, "Name"), stringField(c, "Version"))
		vulns := c.FieldByName("Vulnerabilities")
		if !vulns.IsValid() {
			continue
		}
		for vi := 0; vi < vulns.Len(); vi++ {
			vv := vulns.Index(vi)
			if stringField(vv, "Reachable") != "reachable" {
				continue
			}
			row := topVulnRow{
				sev:      stringField(vv, "Severity"),
				id:       stringField(vv, "ID"),
				cve:      stringField(vv, "CVE"),
				pkg:      pkg,
				reach:    "reachable",
				callSite: stringField(vv, "CallSite"),
				callLine: stringField(vv, "CallLine"),
			}
			row.rank = rankVuln(row)
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].rank > rows[j].rank })
	return rows
}

func firstFix(v reflect.Value) string {
	// Prefer the computed remediation: it points at the dependency you actually
	// control (the direct "father"), not the deeply transitive vulnerable lib.
	if bump := remediationBump(v); bump != "" {
		return bump
	}
	f := v.FieldByName("Fixed")
	if f.IsValid() && f.Kind() == reflect.Slice && f.Len() > 0 {
		return f.Index(0).String()
	}
	return ""
}

// remediationBump returns "direct@fixVersion" when a remediation was computed,
// so the fix column tells the reader which manifest entry to change.
func remediationBump(v reflect.Value) string {
	rem := v.FieldByName("Remediation")
	if !rem.IsValid() || rem.Kind() != reflect.Ptr || rem.IsNil() {
		return ""
	}
	r := rem.Elem()
	direct := stringField(r, "Direct")
	fixVer := stringField(r, "FixVersion")
	if direct == "" || fixVer == "" {
		return ""
	}
	return direct + "@" + fixVer
}
