package output

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
)

type Table struct {
	NoColor bool
}

func (t Table) Render(w io.Writer, report any) error {
	v := reflect.Indirect(reflect.ValueOf(report))
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("table: unexpected report type %T", report)
	}
	totals := v.FieldByName("Totals")
	source := stringField(v, "Source")
	components := v.FieldByName("Components")
	if !components.IsValid() {
		return nil
	}

	useColor := !t.NoColor && os.Getenv("NO_COLOR") == ""
	c := newColors(useColor)

	fmt.Fprintln(w)
	fmt.Fprintln(w, c.bold("┌─ wolfee ─ vulnerability scan ─────────────────────────────"))
	if source != "" {
		fmt.Fprintln(w, c.bold("│ ")+"source: "+source)
	}
	if ts := stringField(v, "GeneratedAt"); ts != "" {
		fmt.Fprintln(w, c.bold("│ ")+"scanned: "+ts)
	}
	fmt.Fprintln(w, c.bold("└────────────────────────────────────────────────────────────"))
	fmt.Fprintln(w)

	fmt.Fprintln(w, c.bold("Summary"))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  Components scanned\t%d\n", intField(totals, "Scanned"))

	if direct, transitive := intField(totals, "Direct"), intField(totals, "Transitive"); direct+transitive > 0 {
		fmt.Fprintf(tw, "  Direct dependencies\t%d\n", direct)
		fmt.Fprintf(tw, "  Transitive dependencies\t%d\n", transitive)
	}
	if skipped := intField(totals, "Skipped"); skipped > 0 {
		fmt.Fprintf(tw, "  Components skipped (no purl)\t%d\n", skipped)
	}
	fmt.Fprintf(tw, "  With vulnerabilities\t%d\n", intField(totals, "WithVulns"))

	reach := intField(totals, "Reachable")
	unreach := intField(totals, "Unreachable")
	reachUnk := intField(totals, "ReachUnknown")
	pkgUsed := intField(totals, "PackageUsed")
	pkgUnused := intField(totals, "PackageUnused")
	if reach+unreach+reachUnk > 0 {
		line := func(label string, n int, col func(string) string) {
			if n > 0 {
				fmt.Fprintf(tw, "  %s\t%s\n", label, col(fmt.Sprintf("%d", n)))
			}
		}
		line("CVEs called (reachable)", reach, c.crit)
		line("CVEs not called (unreachable)", unreach, c.green)
		line("CVEs undecided (no data)", reachUnk, c.low)
	}
	if pkgUsed+pkgUnused > 0 {
		line := func(label string, n int, col func(string) string) {
			if n > 0 {
				fmt.Fprintf(tw, "  %s\t%s\n", label, col(fmt.Sprintf("%d", n)))
			}
		}
		line("Packages imported (in use)", pkgUsed, c.med)
		line("Packages not imported (unused)", pkgUnused, c.low)
	}
	if mal := intField(totals, "Malware"); mal > 0 {
		fmt.Fprintf(tw, "  Malware\t%s\n", c.crit(fmt.Sprintf("%d", mal)))
	}
	if tox := intField(totals, "Toxic"); tox > 0 {
		fmt.Fprintf(tw, "  Toxic packages\t%d\n", tox)
	}
	if kev := intField(totals, "KEV"); kev > 0 {
		fmt.Fprintf(tw, "  In CISA KEV\t%s\n", c.high(fmt.Sprintf("%d", kev)))
	}
	if poc := intField(totals, "PoC"); poc > 0 {
		fmt.Fprintf(tw, "  Public PoC\t%s\n", c.med(fmt.Sprintf("%d", poc)))
	}
	if errCount := countComponentErrors(components); errCount > 0 {
		fmt.Fprintf(tw, "  Components with errors\t%s\n",
			c.high(fmt.Sprintf("%d (use --format json for details)", errCount)))
	}
	fmt.Fprintf(tw, "  Severity\t%s %d\t%s %d\t%s %d\t%s %d\n",
		c.crit("CRIT"), intField(totals, "CRITICAL"),
		c.high("HIGH"), intField(totals, "HIGH"),
		c.med("MED "), intField(totals, "MEDIUM"),
		c.low("LOW "), intField(totals, "LOW"),
	)
	tw.Flush()
	fmt.Fprintln(w)

	type row struct {
		idx  int
		rank int
		val  reflect.Value
	}
	rows := make([]row, 0, components.Len())
	for i := 0; i < components.Len(); i++ {
		comp := components.Index(i)
		rows = append(rows, row{idx: i, rank: rankComponent(comp), val: comp})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].rank > rows[j].rank })

	const maxRows = 200
	affected := 0
	for _, r := range rows {
		if r.rank > 0 {
			affected++
		}
	}
	if affected == 0 {
		fmt.Fprintln(w, c.green("✓ No vulnerabilities or malware detected"))
		fmt.Fprintln(w)
		return nil
	}

	fmt.Fprintln(w, c.bold("Findings"))
	showLayer := anyLayerDigest(components)
	showLang := anyLanguageRelevance(components)
	fg := &grid{}
	if showLayer {
		header := []string{"PACKAGE", "VERSION", "ECO", "LAYER", "VULNS", "FLAGS", "TOXIC", "ORIGIN"}
		if showLang {
			header = append(header, "LANG")
		}
		fg.add(header...)
	} else {
		// Non-image scans (SBOM / reachable): ORIGIN tells direct vs transitive,
		// LANG the ecosystem language. Both are always shown here.
		fg.add("PACKAGE", "VERSION", "ECO", "VULNS", "FLAGS", "TOXIC", "ORIGIN", "LANG")
	}
	shown := 0
	for _, r := range rows {
		if r.rank == 0 {
			break
		}
		if shown >= maxRows {
			fg.add(fmt.Sprintf("... (%d more rows omitted; use --format json for full list)", affected-shown))
			break
		}
		comp := r.val

		toxic := ""
		if boolNested(comp, "Toxic", "Found") {
			toxic = "TOXIC"
			if cat := firstToxicCategory(comp); cat != "" {
				toxic = "TOXIC[" + cat + "]"
			}
			toxic = c.high(toxic)
		}
		flags := []string{}
		if boolNested(comp, "Malware", "Found") {
			label := "MALWARE"
			if srcs := malwareSources(comp); srcs != "" {
				label = "MALWARE[" + srcs + "]"
			}
			flags = append(flags, c.crit(label))
		}
		if hasKEV(comp) {
			flags = append(flags, c.high("KEV"))
		}
		if hasPoC(comp) {
			flags = append(flags, c.med("PoC"))
		}
		usage := stringField(comp, "PackageUsage")
		switch usage {
		case "used", "used-transitive":
			usedStr := c.med("used")
			if site := stringField(comp, "ImportSite"); site != "" {
				usedStr += " " + site
			}
			flags = append(flags, usedStr)
		case "unused":
			flags = append(flags, c.green("not-used"))
		}

		transitive := strings.EqualFold(stringField(comp, "Scope"), "optional") || usage == "used-transitive"
		lang := ""
		if showLang {
			relevant, known := relevantField(comp, "Relevant")
			lang = c.lang(
				langLabel(stringField(comp, "System"), stringField(comp, "PURL"), stringField(comp, "Language")),
				relevant, known,
			)
		}
		if showLayer {
			cells := []string{
				stringField(comp, "Name"),
				stringField(comp, "Version"),
				strings.ToLower(stringField(comp, "System")),
				shortDigest(stringField(comp, "LayerDigest")),
				fmt.Sprintf("%d", intField(comp, "VulnCount")),
				strings.Join(flags, " "),
				toxic,
				c.origin(originLabel(stringField(comp, "System"), stringField(comp, "Origin"), transitive)),
			}
			if showLang {
				cells = append(cells, lang)
			}
			fg.add(cells...)
		} else {
			cells := []string{
				stringField(comp, "Name"),
				stringField(comp, "Version"),
				strings.ToLower(stringField(comp, "System")),
				fmt.Sprintf("%d", intField(comp, "VulnCount")),
				strings.Join(flags, " "),
				toxic,
				depScopeCell(c, comp, transitive),
				langCell(c, comp),
			}
			fg.add(cells...)
		}
		shown++
	}
	fg.render(w)

	if showLayer && anyNonOSComponent(components) && !anyOriginAttributed(components) {
		fmt.Fprintln(w, c.low(`  note: ORIGIN "-" = not attributed; pass --scout to tag non-OS packages BASE vs APP`))
	}
	fmt.Fprintln(w)

	if showLayer {
		layers := collectLayerSummary(components)
		if len(layers) > 0 {
			fmt.Fprintln(w, c.bold("Affected layers"))
			lg := &grid{}
			lg.add("LAYER", "PKGS", "WORST", "CREATED BY")
			for _, l := range layers {
				lg.add(shortDigest(l.digest), fmt.Sprintf("%d", l.pkgs), c.sev(l.worst), trimCreatedBy(l.createdBy))
			}
			lg.render(w)
			fmt.Fprintln(w)
		}
	}

	reachRows := collectReachableVulns(components)
	if len(reachRows) > 0 {
		fmt.Fprintln(w, c.bold("Reachable vulnerabilities (called by your code)"))
		rg := &grid{}
		rg.add("SEV", "CVE", "PACKAGE", "CALL SITE")
		for _, r := range reachRows {
			callInfo := r.callSite
			if r.callLine != "" {
				callInfo = r.callLine
				if r.callSite != "" {
					callInfo += " (" + r.callSite + ")"
				}
			}

			displayID := r.cve
			if displayID == "" {
				displayID = r.id
			}
			rg.add(c.sev(r.sev), c.crit(displayID), r.pkg, callInfo)
		}
		rg.render(w)
		fmt.Fprintln(w)
	}

	const maxVulnRows = 200
	top := collectTopVulns(components)
	if len(top) > 0 {
		fmt.Fprintln(w, c.bold("Vulnerabilities"))
		vg := &grid{}

		if showLayer {
			vg.add("SEV", "CVE", "PACKAGE", "EPSS", "FIX", "FLAGS", "ORIGIN")
		} else {
			vg.add("SEV", "CVE", "PACKAGE", "EPSS", "FIX", "FLAGS")
		}
		shown := 0
		for _, t := range top {
			if shown >= maxVulnRows {
				vg.add(fmt.Sprintf("... (%d more - use --format json for full list)", len(top)-shown))
				break
			}
			flags := []string{}
			if t.kev {
				flags = append(flags, c.high("KEV"))
			}
			if t.poc {
				flags = append(flags, c.med("PoC"))
			}

			switch t.reach {
			case "reachable":
				flags = append(flags, c.crit("called"))
			case "unreachable":
				flags = append(flags, c.green("not-called"))
			}
			epss := ""
			if t.epss > 0 {
				epss = fmt.Sprintf("%.2f", t.epss)
			}

			displayID := t.cve
			if displayID == "" {
				displayID = t.id
			}
			if showLayer {
				vg.add(c.sev(t.sev), displayID, t.pkg, epss, t.fix, strings.Join(flags, " "),
					c.origin(originLabel(t.system, t.origin, strings.EqualFold(t.scope, "optional"))))
			} else {
				vg.add(c.sev(t.sev), displayID, t.pkg, epss, t.fix, strings.Join(flags, " "))
			}
			shown++
		}
		vg.render(w)
		fmt.Fprintln(w)
	}

	renderDependencyPaths(w, c, components)

	return nil
}

func renderDependencyPaths(w io.Writer, c colors, components reflect.Value) {
	type row struct {
		pkg       string
		label     string // "(vuln)" or "(toxic)"
		paths     [][]string
		remDirect string
		remFixVer string
		remVia    string
		remNote   string
	}
	var rows []row
	for i := 0; i < components.Len(); i++ {
		comp := components.Index(i)
		paths := stringMatrixField(comp, "DependencyPaths")
		if len(paths) == 0 {
			continue
		}
		vulns := comp.FieldByName("Vulnerabilities")
		hasVulns := vulns.IsValid() && vulns.Len() > 0
		pkg := fmt.Sprintf("%s@%s", stringField(comp, "Name"), stringField(comp, "Version"))
		switch {
		case hasVulns:
			direct, fixVer, via, note := remediationParts(comp)
			rows = append(rows, row{pkg: pkg, label: c.high("(vuln)"), paths: paths,
				remDirect: direct, remFixVer: fixVer, remVia: via, remNote: note})
		case boolNested(comp, "Toxic", "Found"):
			// A toxic (protestware) lib is treated like a vulnerability, just
			// under a different name.
			direct, fixVer, via, note := toxicRemediationParts(comp)
			rows = append(rows, row{pkg: pkg, label: c.high("(toxic)"), paths: paths,
				remDirect: direct, remFixVer: fixVer, remVia: via, remNote: note})
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintln(w, c.bold("Dependency paths")+c.low("  (* = update this; green = version to bump it to)"))
	const maxRows = 50
	sep := c.low(" -> ")
	for i, r := range rows {
		if i >= maxRows {
			fmt.Fprintln(w, c.low(fmt.Sprintf("  ... (%d more - use --format json for the full list)", len(rows)-i)))
			break
		}

		_, compVer := splitNameVer(r.pkg)
		// The green upgrade target is only attached to the father when the
		// finding is fixed by bumping it (parent-bump); "override" findings have
		// no helpful father version and get a trailing note instead.
		inlineFix := r.remVia == "parent-bump" && r.remFixVer != ""

		fmt.Fprintf(w, "  %s %s\n", r.pkg, r.label)
		for _, p := range r.paths {
			if len(p) == 0 {
				continue
			}

			hops := append([]string(nil), p...)
			// The chain ends at the flagged lib, so pin its last hop to the
			// version that was actually flagged. In --compare the path is grafted
			// from the source SBOM, which can record a different (require-edge)
			// version than the one the image ships - showing that here just looked
			// like an unexplained second version of the same package.
			if compVer != "" {
				last := len(hops) - 1
				if n, _ := splitNameVer(hops[last]); n != "" {
					hops[last] = n + "@" + compVer
				}
			}
			// Show the upgrade target right next to the father lib, e.g.
			//   *express@4.17.1 → 4.21.1 -> cookie@0.4.0
			if inlineFix {
				if n, _ := splitNameVer(p[0]); strings.EqualFold(n, r.remDirect) {
					hops[0] += c.green(" → " + r.remFixVer)
				}
			}
			hops[0] = c.crit("*") + hops[0]
			fmt.Fprintf(w, "    %s\n", strings.Join(hops, sep))
		}
		if !inlineFix && r.remDirect != "" && r.remFixVer != "" {
			fix := fmt.Sprintf("pin %s → %s", r.remDirect, r.remFixVer)
			if r.remNote != "" {
				fix += " (" + r.remNote + ")"
			}
			fmt.Fprintf(w, "    %s %s\n", c.green("fix:"), fix)
		}
	}
	fmt.Fprintln(w)
}

// remediationParts returns the computed upgrade for a component's first
// vulnerability that has one: the direct ("father") dependency to change, the
// version to move it to, how (parent-bump vs override), and any note.
func remediationParts(comp reflect.Value) (direct, fixVer, via, note string) {
	vulns := comp.FieldByName("Vulnerabilities")
	if !vulns.IsValid() {
		return "", "", "", ""
	}
	for i := 0; i < vulns.Len(); i++ {
		rem := vulns.Index(i).FieldByName("Remediation")
		if !rem.IsValid() || rem.Kind() != reflect.Ptr || rem.IsNil() {
			continue
		}
		r := rem.Elem()
		return stringField(r, "Direct"), stringField(r, "FixVersion"),
			stringField(r, "Via"), stringField(r, "Note")
	}
	return "", "", "", ""
}

// toxicRemediationParts returns the upgrade computed for a toxic package.
func toxicRemediationParts(comp reflect.Value) (direct, fixVer, via, note string) {
	tox := comp.FieldByName("Toxic")
	if !tox.IsValid() {
		return "", "", "", ""
	}
	rem := tox.FieldByName("Remediation")
	if !rem.IsValid() || rem.Kind() != reflect.Ptr || rem.IsNil() {
		return "", "", "", ""
	}
	r := rem.Elem()
	return stringField(r, "Direct"), stringField(r, "FixVersion"),
		stringField(r, "Via"), stringField(r, "Note")
}

// depScopeCell renders the ORIGIN cell for non-image scans: whether the package
// is a direct dependency or pulled in transitively. A recorded dependency path
// (or an optional/used-transitive scope) means transitive.
func depScopeCell(c colors, comp reflect.Value, transitive bool) string {
	if transitive || len(stringMatrixField(comp, "DependencyPaths")) > 0 {
		return c.low("transitive")
	}
	return "direct"
}

// langCell renders the LANG cell. With reachability data it keeps the
// relevance-coloured "relevant-<lang>" label; otherwise it shows the plain
// ecosystem language (js, go, python, ...).
func langCell(c colors, comp reflect.Value) string {
	if relevant, known := relevantField(comp, "Relevant"); known {
		return c.lang(
			langLabel(stringField(comp, "System"), stringField(comp, "PURL"), stringField(comp, "Language")),
			relevant, known,
		)
	}
	return c.low(plainLangLabel(stringField(comp, "System"), stringField(comp, "PURL")))
}
