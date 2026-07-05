package onlinescan

import "testing"

func TestParseDLAList_ExtractsCVEsPerAdvisory(t *testing.T) {
	body := []byte(`[04 Jan 2026] DLA-3712-1 openssl - security update
	{CVE-2023-0286 CVE-2023-0464}
	[stretch] - openssl 1.1.0l-1~deb9u9
	[buster] - openssl 1.1.1n-0+deb10u4
[01 Jan 2026] DSA-5800-1 curl - security update
	{CVE-2024-2398}
	[bookworm] - curl 7.88.1-10+deb12u8
[unparseable line]
[20 Dec 2025] DLA-3711-1 nothing - security update
	{CVE-2023-0286}
`)

	byCVE := map[string][]string{}
	byAdvisory := map[string][]string{}
	byPkgRelease := map[string]map[string][]dlaFix{}
	parseDLAList(body, byCVE, byAdvisory, byPkgRelease)

	if got := byCVE["CVE-2023-0286"]; len(got) != 2 {
		t.Fatalf("CVE-2023-0286 should map to two advisories, got %v", got)
	}
	if got := byCVE["CVE-2023-0464"]; len(got) != 1 || got[0] != "DLA-3712-1" {
		t.Errorf("CVE-2023-0464 → %v; want [DLA-3712-1]", got)
	}
	if got := byCVE["CVE-2024-2398"]; len(got) != 1 || got[0] != "DSA-5800-1" {
		t.Errorf("CVE-2024-2398 → %v; want [DSA-5800-1]", got)
	}

	if got := byAdvisory["DLA-3712-1"]; len(got) != 2 {
		t.Errorf("DLA-3712-1 should cover two CVEs, got %v", got)
	}
	if got := byAdvisory["DSA-5800-1"]; len(got) != 1 || got[0] != "CVE-2024-2398" {
		t.Errorf("DSA-5800-1 → %v; want [CVE-2024-2398]", got)
	}

	opensslFixes := byPkgRelease["openssl"]["stretch"]
	if len(opensslFixes) != 1 {
		t.Fatalf("openssl/stretch should have 1 fix, got %v", opensslFixes)
	}
	if opensslFixes[0].FixedVersion != "1.1.0l-1~deb9u9" {
		t.Errorf("openssl stretch fix = %q; want 1.1.0l-1~deb9u9", opensslFixes[0].FixedVersion)
	}
	if len(opensslFixes[0].CVEs) != 2 {
		t.Errorf("openssl stretch fix should cover 2 CVEs, got %v", opensslFixes[0].CVEs)
	}
	curlFixes := byPkgRelease["curl"]["bookworm"]
	if len(curlFixes) != 1 || curlFixes[0].FixedVersion != "7.88.1-10+deb12u8" {
		t.Errorf("curl bookworm fix = %v; want [{..., 7.88.1-10+deb12u8}]", curlFixes)
	}
}

func TestParseDLAList_FixLinesBeforeCVEList(t *testing.T) {
	body := []byte(`[15 Mar 2019] DSA-4400-1 openssl - security update
	[stretch] - openssl 1.1.0j-1+deb9u3
	[buster] - openssl 1.1.1a-1
	{CVE-2019-1543}
[10 Jan 2019] DSA-4360-1 curl - security update
	{CVE-2018-16890 CVE-2019-3822 CVE-2019-3823}
	[stretch] - curl 7.52.1-5+deb9u9
`)

	byCVE := map[string][]string{}
	byAdvisory := map[string][]string{}
	byPkgRelease := map[string]map[string][]dlaFix{}
	parseDLAList(body, byCVE, byAdvisory, byPkgRelease)

	opensslFixes := byPkgRelease["openssl"]["stretch"]
	if len(opensslFixes) != 1 {
		t.Fatalf("openssl/stretch from pre-CVE fix lines: got %d fixes, want 1", len(opensslFixes))
	}
	if opensslFixes[0].FixedVersion != "1.1.0j-1+deb9u3" {
		t.Errorf("openssl stretch fix = %q; want 1.1.0j-1+deb9u3", opensslFixes[0].FixedVersion)
	}
	if len(opensslFixes[0].CVEs) != 1 || opensslFixes[0].CVEs[0] != "CVE-2019-1543" {
		t.Errorf("openssl stretch fix CVEs = %v; want [CVE-2019-1543]", opensslFixes[0].CVEs)
	}

	curlFixes := byPkgRelease["curl"]["stretch"]
	if len(curlFixes) != 1 || curlFixes[0].FixedVersion != "7.52.1-5+deb9u9" {
		t.Errorf("curl/stretch fix = %v; want [{..., 7.52.1-5+deb9u9}]", curlFixes)
	}
	if len(curlFixes[0].CVEs) != 3 {
		t.Errorf("curl/stretch fix CVEs = %v; want 3 CVEs", curlFixes[0].CVEs)
	}
}

func TestDLAIndex_NilLookupIsSafe(t *testing.T) {
	var d *dlaIndex
	if got := d.LookupCVE("CVE-2023-0286"); got != nil {
		t.Errorf("nil receiver should return nil, got %v", got)
	}
}
