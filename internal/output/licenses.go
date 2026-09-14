package output

import (
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

const maxLicenseCellLen = 40

// licenseCell renders a component's license, coloured by production risk.
func licenseCell(c colors, comp reflect.Value) string {
	label := stringField(comp, "License")
	if len(label) > maxLicenseCellLen {
		label = label[:maxLicenseCellLen-3] + "..."
	}
	return c.license(label, stringField(comp, "LicenseRisk"))
}

func licenseRiskLabel(c colors, risk string) string {
	switch risk {
	case "high":
		return c.crit("HIGH")
	case "medium":
		return c.med("MEDIUM")
	}
	return risk
}

// renderLicenseRisks lists every component whose license is risky in
// production (strong/network copyleft, non-commercial = red; weak copyleft =
// yellow). Image scans hide clean components from Findings, so this section is
// the only place such packages are guaranteed to show up.
func renderLicenseRisks(w io.Writer, c colors, components reflect.Value) {
	if !components.IsValid() || components.Kind() != reflect.Slice {
		return
	}
	type row struct {
		pkg, eco, license, risk string
		rank                    int
	}
	var rows []row
	seen := map[string]bool{}
	for i := 0; i < components.Len(); i++ {
		comp := components.Index(i)
		risk := stringField(comp, "LicenseRisk")
		rank := 0
		switch risk {
		case "high":
			rank = 2
		case "medium":
			rank = 1
		default:
			continue
		}
		pkg := fmt.Sprintf("%s@%s", stringField(comp, "Name"), stringField(comp, "Version"))
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		rows = append(rows, row{pkg: pkg, eco: strings.ToLower(stringField(comp, "System")),
			license: stringField(comp, "License"), risk: risk, rank: rank})
	}
	if len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank > rows[j].rank
		}
		return rows[i].pkg < rows[j].pkg
	})

	fmt.Fprintln(w, c.bold("License risks")+c.low("  (red = copyleft / non-commercial, yellow = weak copyleft)"))
	g := &grid{}
	g.add("RISK", "PACKAGE", "ECO", "LICENSE")
	const maxRows = 200
	for i, r := range rows {
		if i >= maxRows {
			g.add(fmt.Sprintf("... (%d more - use --format json for the full list)", len(rows)-i))
			break
		}
		g.add(licenseRiskLabel(c, r.risk), r.pkg, r.eco, c.license(r.license, r.risk))
	}
	g.render(w)
	fmt.Fprintln(w)
}
