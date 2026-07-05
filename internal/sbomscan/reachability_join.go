package sbomscan

import (
	"context"
	"fmt"
	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/reachability"
	"strings"
)

func applyReachability(cr *ComponentReport, oracle *reachability.Result) {
	if oracle == nil {
		return
	}
	modPath := goModulePath(cr)
	atomEco, atomPURL := purlEcosystem(cr.PURL), purlNoVersion(cr.PURL)

	usage := func() reachability.State {
		if modPath != "" {
			return oracle.PackageUsage(modPath)
		}
		if st := oracle.AtomPackageUsage(atomEco, atomPURL); st != reachability.StateUnknown {
			return st
		}
		return oracle.ImportPackageUsage(atomEco, atomPURL)
	}
	pkgUsage := usage()

	switch pkgUsage {
	case reachability.StateReachable, reachability.StateInUse:
		if oracle.IsTransitiveImport(atomPURL) {
			cr.PackageUsage = "used-transitive"
		} else {
			cr.PackageUsage = "used"

			if modPath != "" {
				cr.ImportSite = oracle.GoImportSite(modPath)
				cr.ImportLine = oracle.GoImportLine(modPath)
			} else if atomPURL != "" {
				cr.ImportSite = oracle.ImportSite(atomPURL)
				cr.ImportLine = oracle.ImportLine(atomPURL)
			}
		}
	case reachability.StateDead:
		cr.PackageUsage = "unused"
	}
	applyLanguageRelevance(cr, oracle)

	for j := range cr.Vulnerabilities {
		v := &cr.Vulnerabilities[j]
		ids := make([]string, 0, 2+len(v.Aliases))
		ids = append(ids, v.ID, v.CVE)
		ids = append(ids, v.Aliases...)
		st := oracle.Lookup(ids...)
		if st == reachability.StateUnknown {

			st = pkgUsage
		}
		switch st {
		case reachability.StateReachable:
			v.Reachable = string(st)
			v.CallSite = oracle.VulnCallSite(ids...)
			v.CallLine = oracle.VulnCallLine(ids...)
		case reachability.StateUnreachable:
			v.Reachable = string(st)

		}
	}
}

func injectGovulncheckFindings(components *[]ComponentReport, oracle *reachability.Result) {
	if oracle == nil || len(oracle.CalledModules) == 0 {
		return
	}

	for i := range *components {
		cr := &(*components)[i]
		modPath := goModulePath(cr)
		if modPath == "" || modPath == "stdlib" {
			continue
		}
		for _, goID := range oracle.CalledIDsForModule(modPath) {
			primaryID, aliasIDs := bestVulnID(goID, oracle.GOAliases[goID])

			alreadyPresent := vulnHasID(cr.Vulnerabilities, primaryID)
			if !alreadyPresent {
				for _, a := range aliasIDs {
					if vulnHasID(cr.Vulnerabilities, a) {
						alreadyPresent = true
						break
					}
				}
			}
			if alreadyPresent {
				continue
			}
			cr.Vulnerabilities = append(cr.Vulnerabilities, onlinescan.Vulnerability{
				ID:        primaryID,
				Aliases:   aliasIDs,
				Severity:  oracle.GOSeverity[goID],
				Reachable: string(reachability.StateReachable),
				CallSite:  oracle.VulnCallSite(goID),
				CallLine:  oracle.VulnCallLine(goID),
			})
		}
		cr.TopSeverity, cr.VulnCount = topAndCount(cr.Vulnerabilities)
	}

	stdlibIDs := oracle.CalledIDsForModule("stdlib")
	if len(stdlibIDs) == 0 {
		return
	}
	goVer := oracle.GoVersion
	if goVer == "" {
		goVer = "unknown"
	}
	relevant := true
	stdlib := ComponentReport{
		PURL:              fmt.Sprintf("pkg:golang/stdlib@%s", goVer),
		System:            "golang",
		Name:              "stdlib",
		Version:           goVer,
		Scope:             "required",
		PackageUsage:      "used",
		Language:          "go",
		LanguageRelevance: LanguageRelevanceUsed,
		Relevant:          &relevant,
		Class:             "lang-pkgs",
		Type:              "golang",
	}
	for _, goID := range stdlibIDs {
		primaryID, aliasIDs := bestVulnID(goID, oracle.GOAliases[goID])
		stdlib.Vulnerabilities = append(stdlib.Vulnerabilities, onlinescan.Vulnerability{
			ID:        primaryID,
			Aliases:   aliasIDs,
			Severity:  oracle.GOSeverity[goID],
			Reachable: string(reachability.StateReachable),
			CallSite:  oracle.VulnCallSite(goID),
			CallLine:  oracle.VulnCallLine(goID),
		})
	}
	stdlib.Vulnerabilities = dedupeVulns(stdlib.Vulnerabilities)
	stdlib.TopSeverity, stdlib.VulnCount = topAndCount(stdlib.Vulnerabilities)
	*components = append(*components, stdlib)
}

func backfillSyntheticSeverities(ctx context.Context, components *[]ComponentReport, o Options) {
	if len(*components) == 0 {
		return
	}

	var cves []string
	seen := map[string]struct{}{}
	for _, cr := range *components {
		for _, v := range cr.Vulnerabilities {
			if v.Severity != "" || v.Reachable == "" {
				continue
			}
			cve := v.CVE
			if cve == "" {
				cve = v.ID
			}
			if cve == "" {
				continue
			}
			upper := strings.ToUpper(cve)
			if !strings.HasPrefix(upper, "CVE-") && !strings.HasPrefix(upper, "GHSA-") {
				continue
			}
			if _, dup := seen[upper]; dup {
				continue
			}
			seen[upper] = struct{}{}
			cves = append(cves, cve)
		}
	}
	if len(cves) == 0 {
		return
	}
	sevMap := onlinescan.FetchCVESeverities(ctx, cves, onlinescan.Options{
		Logger: o.Logger,
	})
	if len(sevMap) == 0 {
		return
	}

	upper := func(s string) string { return strings.ToUpper(s) }
	for i := range *components {
		for j := range (*components)[i].Vulnerabilities {
			v := &(*components)[i].Vulnerabilities[j]
			if v.Severity != "" {
				continue
			}
			cve := v.CVE
			if cve == "" {
				cve = v.ID
			}
			if sev, ok := sevMap[upper(cve)]; ok && sev != "" {
				v.Severity = sev
			}
		}

		cr := &(*components)[i]
		cr.TopSeverity, cr.VulnCount = topAndCount(cr.Vulnerabilities)
	}
}
