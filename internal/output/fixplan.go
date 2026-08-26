package output

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// FixPlan renders the remediation groups attached to an sbomscan.Report.
// Reflection keeps the output package independent from the scanner package.
type FixPlan struct {
	NoColor bool
}

func (f FixPlan) Render(w io.Writer, report any) error {
	v := reflect.Indirect(reflect.ValueOf(report))
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("fix-plan: unexpected report type %T", report)
	}
	plan := indirectField(v, "FixPlan")
	if !plan.IsValid() {
		_, err := fmt.Fprintln(w, "No remediation plan available.")
		return err
	}

	c := newColors(!f.NoColor && os.Getenv("NO_COLOR") == "")
	fmt.Fprintln(w, c.bold("FIX PLAN"))
	if source := stringField(v, "Source"); source != "" {
		fmt.Fprintf(w, "%s %s\n", c.bold("Source:"), source)
	}
	fmt.Fprintln(w)

	renderFixPlanFindings(w, c, v)

	fmt.Fprintln(w, c.bold("REMEDIATION PLAN"))
	fmt.Fprintln(w)

	groups := fieldSlice(plan, "Groups")
	for i := 0; i < groups.Len(); i++ {
		group := groups.Index(i)
		verb := "Upgrade"
		if stringField(group, "Via") == "osv-fixed" {
			verb = "Update"
		}
		fmt.Fprintf(w, "%d. %s %s", i+1, verb, c.high(stringField(group, "Direct")))
		if current := stringField(group, "CurrentVersion"); current != "" {
			fmt.Fprintf(w, " %s -> %s", c.high(current), c.green(stringField(group, "FixVersion")))
		}
		fmt.Fprintln(w)

		packages := fieldSlice(group, "Packages")
		fixCount := 0
		for j := 0; j < packages.Len(); j++ {
			fixCount += fieldSlice(packages.Index(j), "Vulnerabilities").Len()
		}
		label := "vulnerabilities"
		if fixCount == 1 {
			label = "vulnerability"
		}
		fmt.Fprintf(w, "  %s %d %s\n", c.bold("Fixes:"), fixCount, label)
		fg := &grid{}
		fg.add("PACKAGE", "CVE", "SEV", "EPSS", "FIX", "FLAGS")
		for j := 0; j < packages.Len(); j++ {
			pkg := packages.Index(j)
			name := stringField(pkg, "Package")
			vulns := fieldSlice(pkg, "Vulnerabilities")
			for k := 0; k < vulns.Len(); k++ {
				vuln := vulns.Index(k)
				fg.add(c.high(name), coloredAdvisory(c, vuln), c.sev(stringField(vuln, "Severity")),
					stringFieldValue(vuln, "EPSS"), c.green(stringField(vuln, "FixVersion")), vulnFlags(c, vuln))
			}
		}
		fg.render(w)
		fmt.Fprintln(w)
		if hasAnyPaths(packages) {
			fmt.Fprintln(w, c.bold("Dependency paths"))
			seenPaths := map[string]bool{}
			shownPaths := 0
			totalPaths := 0
			for j := 0; j < packages.Len(); j++ {
				pkg := packages.Index(j)
				for _, path := range stringMatrixField(pkg, "DependencyPaths") {
					totalPaths++
					key := strings.Join(path, "\x00")
					if seenPaths[key] || shownPaths >= maxTerminalFixPlanPaths {
						continue
					}
					seenPaths[key] = true
					shownPaths++
					fmt.Fprintf(w, "  path: %s\n", c.low(strings.Join(path, " -> ")))
				}
			}
			if totalPaths > shownPaths || anyPathTruncated(packages) {
				fmt.Fprintf(w, "  %s\n", c.low(fmt.Sprintf("... %d more paths; use --format json for full list", totalPaths-shownPaths)))
			}
		}
		if note := stringField(group, "Note"); note != "" {
			fmt.Fprintf(w, "  Note: %s\n", note)
		}
		fmt.Fprintln(w)
	}

	unresolved := fieldSlice(plan, "Unresolved")
	if unresolved.Len() > 0 {
		fmt.Fprintln(w, c.bold("UNRESOLVED REMEDIATIONS"))
		fg := &grid{}
		fg.add("PACKAGE", "CVE", "SEV", "EPSS", "FIX", "FLAGS")
		for i := 0; i < unresolved.Len(); i++ {
			pkg := unresolved.Index(i)
			vulns := fieldSlice(pkg, "Vulnerabilities")
			for j := 0; j < vulns.Len(); j++ {
				vuln := vulns.Index(j)
				fg.add(c.high(stringField(pkg, "Package")), coloredAdvisory(c, vuln), c.sev(stringField(vuln, "Severity")),
					stringFieldValue(vuln, "EPSS"), "", vulnFlags(c, vuln))
			}
		}
		fg.render(w)
		fmt.Fprintln(w)
		if hasAnyPaths(unresolved) {
			fmt.Fprintln(w, c.bold("Dependency paths"))
			seenPaths := map[string]bool{}
			shownPaths := 0
			totalPaths := 0
			for i := 0; i < unresolved.Len(); i++ {
				pkg := unresolved.Index(i)
				for _, path := range stringMatrixField(pkg, "DependencyPaths") {
					totalPaths++
					key := strings.Join(path, "\x00")
					if seenPaths[key] || shownPaths >= maxTerminalFixPlanPaths {
						continue
					}
					seenPaths[key] = true
					shownPaths++
					fmt.Fprintf(w, "  path: %s\n", c.low(strings.Join(path, " -> ")))
				}
			}
			if totalPaths > shownPaths || anyPathTruncated(unresolved) {
				fmt.Fprintf(w, "  %s\n", c.low(fmt.Sprintf("... %d more paths; use --format json for full list", totalPaths-shownPaths)))
			}
		}
		return nil
	}
	return nil
}

const maxTerminalFixPlanPaths = 10

type fixPlanFindingRow struct {
	pkg      string
	id       string
	severity string
	epss     string
	fix      string
	flags    string
	rank     int
}

func renderFixPlanFindings(w io.Writer, c colors, report reflect.Value) {
	components := fieldSlice(report, "Components")
	rows := make([]fixPlanFindingRow, 0)
	for i := 0; i < components.Len(); i++ {
		component := components.Index(i)
		pkg := fmt.Sprintf("%s@%s", stringField(component, "Name"), stringField(component, "Version"))
		vulns := fieldSlice(component, "Vulnerabilities")
		for j := 0; j < vulns.Len(); j++ {
			vuln := vulns.Index(j)
			severity := strings.ToUpper(stringField(vuln, "Severity"))
			id := stringField(vuln, "CVE")
			if id == "" {
				id = stringField(vuln, "ID")
			}
			rows = append(rows, fixPlanFindingRow{
				pkg: pkg, id: id, severity: severity,
				epss: stringFieldValue(vuln, "EPSS"),
				fix:  firstStringField(vuln, "Fixed"), flags: vulnFlags(c, vuln),
				rank: severityRank(severity),
			})
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank > rows[j].rank
		}
		if rows[i].pkg != rows[j].pkg {
			return rows[i].pkg < rows[j].pkg
		}
		return rows[i].id < rows[j].id
	})

	fmt.Fprintf(w, "%s (%d)\n", c.bold("VULNERABILITIES"), len(rows))
	grid := &grid{}
	grid.add("PACKAGE", "CVE", "SEV", "EPSS", "FIX", "FLAGS")
	for _, row := range rows {
		grid.add(c.high(row.pkg), colorAdvisory(c, row.id, row.severity), c.sev(row.severity), row.epss, c.green(row.fix), row.flags)
	}
	grid.render(w)
	fmt.Fprintln(w)
}

func severityRank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func colorAdvisory(c colors, id, severity string) string {
	switch severity {
	case "CRITICAL":
		return c.crit(id)
	case "HIGH":
		return c.high(id)
	case "MEDIUM":
		return c.med(id)
	case "LOW":
		return c.low(id)
	default:
		return id
	}
}

func firstStringField(v reflect.Value, name string) string {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Slice || f.Len() == 0 {
		return ""
	}
	if first := f.Index(0); first.Kind() == reflect.String {
		return first.String()
	}
	return ""
}

func anyPathTruncated(values reflect.Value) bool {
	for i := 0; i < values.Len(); i++ {
		if boolField(values.Index(i), "DependencyPathsTruncated") {
			return true
		}
	}
	return false
}

func hasAnyPaths(values reflect.Value) bool {
	for i := 0; i < values.Len(); i++ {
		if len(stringMatrixField(values.Index(i), "DependencyPaths")) > 0 || boolField(values.Index(i), "DependencyPathsTruncated") {
			return true
		}
	}
	return false
}

func indirectField(v reflect.Value, name string) reflect.Value {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return reflect.Value{}
	}
	for f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return reflect.Value{}
		}
		f = f.Elem()
	}
	return f
}

func fieldSlice(v reflect.Value, name string) reflect.Value {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Slice {
		return reflect.ValueOf([]struct{}{})
	}
	return f
}

func boolField(v reflect.Value, name string) bool {
	f := v.FieldByName(name)
	return f.IsValid() && f.Kind() == reflect.Bool && f.Bool()
}

func stringFieldValue(v reflect.Value, name string) string {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return ""
	}
	if f.Kind() == reflect.Float32 || f.Kind() == reflect.Float64 {
		if f.Float() == 0 {
			return ""
		}
		return fmt.Sprintf("%.2f", f.Float())
	}
	return stringField(v, name)
}

func coloredAdvisory(c colors, v reflect.Value) string {
	id := stringField(v, "CVE")
	if id == "" {
		id = stringField(v, "ID")
	}
	switch strings.ToUpper(stringField(v, "Severity")) {
	case "CRITICAL":
		return c.crit(id)
	case "HIGH":
		return c.high(id)
	case "MEDIUM":
		return c.med(id)
	case "LOW":
		return c.low(id)
	default:
		return id
	}
}

func vulnFlags(c colors, v reflect.Value) string {
	var flags []string
	if boolField(v, "InKEV") {
		flags = append(flags, c.high("KEV"))
	}
	if f := v.FieldByName("PoCs"); f.IsValid() && f.Kind() == reflect.Slice && f.Len() > 0 {
		flags = append(flags, c.med("PoC"))
	}
	return strings.Join(flags, " ")
}
