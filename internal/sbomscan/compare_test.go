package sbomscan

import (
	"testing"

	"sca-go/cli/internal/onlinescan"
)

func comp(purl, name, ver, scope string, vulns ...onlinescan.Vulnerability) ComponentReport {
	c := ComponentReport{PURL: purl, System: "golang", Name: name, Version: ver, Scope: scope, Vulnerabilities: vulns, Origin: OriginApp}
	c.TopSeverity, c.VulnCount = topAndCount(vulns)
	return c
}

func TestMergeSourceVulns(t *testing.T) {
	image := &Report{Components: []ComponentReport{
		comp("pkg:golang/github.com/jackc/pgx/v5@v5.7.2", "github.com/jackc/pgx/v5", "v5.7.2", "",
			onlinescan.Vulnerability{ID: "CVE-1111", CVE: "CVE-1111", Severity: "HIGH"}),
		{PURL: "pkg:apk/alpine/musl@1.2", System: "apk", Name: "musl", Version: "1.2", Origin: OriginImage,
			Vulnerabilities: []onlinescan.Vulnerability{{ID: "CVE-9999", CVE: "CVE-9999", Severity: "HIGH"}}},
	}}
	source := &Report{Components: []ComponentReport{

		comp("pkg:golang/github.com/jackc/pgx/v5@v5.7.2", "github.com/jackc/pgx/v5", "v5.7.2", "optional",
			onlinescan.Vulnerability{ID: "CVE-2222", CVE: "CVE-2222", Severity: "HIGH"}),

		comp("pkg:golang/golang.org/x/text@v0.3.0", "golang.org/x/text", "v0.3.0", "required",
			onlinescan.Vulnerability{ID: "CVE-3333", CVE: "CVE-3333", Severity: "MEDIUM"}),

		comp("pkg:golang/example.com/clean@v1.0.0", "example.com/clean", "v1.0.0", "required"),
	}}

	MergeSourceVulns(image, source, nil)

	byName := map[string]ComponentReport{}
	for _, c := range image.Components {
		byName[c.Name] = c
	}
	pgx := byName["github.com/jackc/pgx/v5"]
	if pgx.VulnCount != 2 {
		t.Errorf("pgx vulns after union = %d, want 2 (CVE-1111 + CVE-2222)", pgx.VulnCount)
	}
	if pgx.Scope != "optional" {
		t.Errorf("pgx scope = %q, want optional (transitive, from source)", pgx.Scope)
	}
	if _, ok := byName["golang.org/x/text"]; !ok {
		t.Error("source-only vulnerable lib golang.org/x/text was not added")
	}
	if _, ok := byName["example.com/clean"]; ok {
		t.Error("source-only CLEAN lib example.com/clean must not be added")
	}

	if image.Totals.Transitive != 1 {
		t.Errorf("Transitive = %d, want 1 (pgx)", image.Totals.Transitive)
	}
	if image.Totals.Direct != 1 {
		t.Errorf("Direct = %d, want 1 (x/text)", image.Totals.Direct)
	}
}

func TestMergeSourceVulns_NoCrossVersionContamination(t *testing.T) {
	// The image bundles golang.org/x/crypto@v0.49.0 (only the CVEs that still
	// affect 0.49). The source declares golang.org/x/crypto@v0.31.0 (older, more
	// CVEs). Merging must not push the 0.31.0-only CVE onto the 0.49.0 entry.
	image := &Report{Components: []ComponentReport{
		comp("pkg:golang/golang.org/x/crypto@v0.49.0", "golang.org/x/crypto", "v0.49.0", "",
			onlinescan.Vulnerability{ID: "CVE-2026-39827", CVE: "CVE-2026-39827", Severity: "HIGH"}),
	}}
	source := &Report{Components: []ComponentReport{
		comp("pkg:golang/golang.org/x/crypto@v0.31.0", "golang.org/x/crypto", "v0.31.0", "optional",
			onlinescan.Vulnerability{ID: "CVE-2025-22869", CVE: "CVE-2025-22869", Severity: "HIGH"}),
	}}

	MergeSourceVulns(image, source, nil)

	var hi, lo *ComponentReport
	for i := range image.Components {
		switch image.Components[i].Version {
		case "v0.49.0":
			hi = &image.Components[i]
		case "v0.31.0":
			lo = &image.Components[i]
		}
	}
	if hi == nil {
		t.Fatal("image crypto@v0.49.0 went missing after merge")
	}
	if hi.VulnCount != 1 || vulnHasID(hi.Vulnerabilities, "CVE-2025-22869") {
		t.Errorf("v0.49.0 must keep only its own CVE, got %d vulns incl 0.31.0's: %+v",
			hi.VulnCount, hi.Vulnerabilities)
	}
	if lo == nil {
		t.Fatal("source-only crypto@v0.31.0 should be added as its own component")
	}
	if lo.VulnCount != 1 || !vulnHasID(lo.Vulnerabilities, "CVE-2025-22869") {
		t.Errorf("v0.31.0 entry should carry its own CVE, got %+v", lo.Vulnerabilities)
	}
}

func TestFromSource_VersionAware(t *testing.T) {
	// Source declares golang.org/x/crypto@v0.31.0. The image also bundles a
	// tool built with v0.49.0. Only the version your code actually uses is APP;
	// the foreign version stays an image library.
	src := SourceLibSet([]byte(`{"components":[{"purl":"pkg:golang/golang.org/x/crypto@v0.31.0"}]}`))

	inCode := ComponentReport{
		PURL: "pkg:golang/golang.org/x/crypto@v0.31.0", System: "golang",
		Name: "golang.org/x/crypto", Version: "v0.31.0",
	}
	fromImage := ComponentReport{
		PURL: "pkg:golang/golang.org/x/crypto@v0.49.0", System: "golang",
		Name: "golang.org/x/crypto", Version: "v0.49.0",
	}

	if !fromSource(&inCode, src, nil) {
		t.Error("source-matched version should be attributed to APP")
	}
	if fromSource(&fromImage, src, nil) {
		t.Error("a version present only in the image must not be APP (should be LIB(image))")
	}
}

func TestMarkImageLibs(t *testing.T) {
	comps := []ComponentReport{
		{System: "golang", PURL: "pkg:golang/golang.org/x/crypto@v0.49.0", Origin: OriginImage},
		{System: "apk", PURL: "pkg:apk/alpine/musl@1.2.4-r5", Origin: OriginImage},
		{System: "golang", PURL: "pkg:golang/golang.org/x/crypto@v0.31.0", Origin: OriginApp},
	}
	markImageLibs(comps)

	if comps[0].Origin != OriginImageLib {
		t.Errorf("language lib in image origin = %q, want image-lib", comps[0].Origin)
	}
	if comps[1].Origin != OriginImage {
		t.Errorf("OS package origin = %q, want image (stays)", comps[1].Origin)
	}
	if comps[2].Origin != OriginApp {
		t.Errorf("app component origin = %q, want app (untouched)", comps[2].Origin)
	}
}

func TestSourceScopeMap_GoIndirectProperty(t *testing.T) {
	bom := []byte(`{"components":[
		{"purl":"pkg:golang/example.com/direct@v1.0.0"},
		{"purl":"pkg:golang/example.com/indirect@v1.0.0","properties":[{"name":"cdx:go:indirect","value":"true"}]},
		{"purl":"pkg:npm/left-pad@1.3.0","scope":"optional"}
	]}`)
	m := SourceScopeMap(bom)
	if m["pkg:golang/example.com/indirect"] != "optional" {
		t.Errorf("go indirect not mapped to optional: %v", m)
	}
	if m["pkg:npm/left-pad"] != "optional" {
		t.Errorf("npm scope not preserved: %v", m)
	}
	if _, ok := m["pkg:golang/example.com/direct"]; ok {
		t.Error("direct dep with no scope signal should be omitted")
	}
}
