package sbomscan

import (
	"testing"

	"sca-go/cli/internal/onlinescan"
)

func TestFilterVulnsByVersion(t *testing.T) {
	comps := []ComponentReport{
		{
			System: "golang", Name: "golang.org/x/crypto", Version: "v0.49.0",
			PURL: "pkg:golang/golang.org/x/crypto@v0.49.0",
			Vulnerabilities: []onlinescan.Vulnerability{
				{ID: "CVE-2025-22869", Fixed: []string{"0.35.0"}}, // fixed below 0.49 -> drop
				{ID: "CVE-2025-47914", Fixed: []string{"0.45.0"}}, // fixed below 0.49 -> drop
				{ID: "CVE-2026-39827", Fixed: []string{"0.52.0"}}, // still affected -> keep
				{ID: "GHSA-nofix", Fixed: nil},                    // no fix info -> keep
			},
		},
		{
			// Reachable findings are call-graph confirmed: never dropped.
			System: "golang", Name: "reachable/lib", Version: "v2.0.0",
			PURL: "pkg:golang/reachable/lib@v2.0.0",
			Vulnerabilities: []onlinescan.Vulnerability{
				{ID: "CVE-REACH", Fixed: []string{"1.0.0"}, Reachable: "reachable"},
			},
		},
		{
			// OS packages are handled by distro_filter; leave them untouched even
			// though apk versions never parse as plain semver.
			System: "apk", Name: "musl", Version: "1.2.4_git20230717-r5",
			PURL: "pkg:apk/alpine/musl@1.2.4_git20230717-r5",
			Vulnerabilities: []onlinescan.Vulnerability{
				{ID: "CVE-OS", Fixed: []string{"1.0.0"}},
			},
		},
	}
	for i := range comps {
		comps[i].TopSeverity, comps[i].VulnCount = topAndCount(comps[i].Vulnerabilities)
	}

	filterVulnsByVersion(comps)

	crypto := comps[0]
	if crypto.VulnCount != 2 {
		t.Fatalf("crypto vulns = %d, want 2 (0.52 fix + no-fix kept)", crypto.VulnCount)
	}
	if vulnHasID(crypto.Vulnerabilities, "CVE-2025-22869") || vulnHasID(crypto.Vulnerabilities, "CVE-2025-47914") {
		t.Errorf("already-fixed CVEs should be dropped: %+v", crypto.Vulnerabilities)
	}
	if !vulnHasID(crypto.Vulnerabilities, "CVE-2026-39827") || !vulnHasID(crypto.Vulnerabilities, "GHSA-nofix") {
		t.Errorf("applicable / unknown-fix CVEs should be kept: %+v", crypto.Vulnerabilities)
	}

	if comps[1].VulnCount != 1 {
		t.Errorf("reachable finding must not be dropped, got %d", comps[1].VulnCount)
	}
	if comps[2].VulnCount != 1 {
		t.Errorf("OS package must be left to distro_filter, got %d", comps[2].VulnCount)
	}
}

func TestVersionPastAllFixes_MultiBranch(t *testing.T) {
	cur, _ := parseRelease("1.26.0")
	// Fixed on two branches: 1.25.10 and 1.26.3. 1.26.0 is past the 1.25 fix but
	// not the 1.26 one, so it is still affected and must not be dropped.
	if versionPastAllFixes(cur, []string{"1.25.10", "1.26.3"}) {
		t.Error("1.26.0 is below the 1.26.3 fix; should still be affected")
	}
	done, _ := parseRelease("1.26.4")
	if !versionPastAllFixes(done, []string{"1.25.10", "1.26.3"}) {
		t.Error("1.26.4 is at/above every fix; should be considered not affected")
	}
}
