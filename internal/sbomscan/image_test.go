package sbomscan

import (
	"testing"

	"sca-go/cli/internal/reachability"
	"sca-go/cli/internal/trivy"
)

func sampleTrivyReport() *trivy.Report {
	return &trivy.Report{
		ArtifactName: "php:7.0",
		Metadata:     trivy.Metadata{OS: &trivy.OS{Family: "debian", Name: "9.6", EOSL: true}},
		Results: []trivy.Result{{
			Target: "php:7.0 (debian 9.6)",
			Class:  "os-pkgs",
			Type:   "debian",
			Packages: []trivy.Package{
				{Name: "apt", Version: "1.4.8", SrcName: "apt",
					Identifier: trivy.Identifier{PURL: "pkg:deb/debian/apt@1.4.8?arch=amd64"},
					Layer:      trivy.Layer{DiffID: "sha256:layer1"}},
				{Name: "zlib1g", Version: "1.2.8",
					Identifier: trivy.Identifier{PURL: "pkg:deb/debian/zlib1g@1.2.8"}},
			},
			Vulnerabilities: []trivy.Vulnerability{
				{
					VulnerabilityID:  "CVE-2019-3462",
					PkgName:          "apt",
					PkgIdentifier:    trivy.Identifier{PURL: "pkg:deb/debian/apt@1.4.8?arch=amd64"},
					InstalledVersion: "1.4.8",
					FixedVersion:     "1.4.9",
					Status:           "fixed",
					Severity:         "high",
					Title:            "apt redirect issue",
					PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2019-3462",
					Layer:            trivy.Layer{DiffID: "sha256:layer1"},
					CVSS: map[string]trivy.CVSS{
						"nvd": {V2Score: 9.3, V3Score: 8.1, V3Vector: "CVSS:3.1/AV:N"},
					},
				},
				{
					VulnerabilityID:  "GHSA-xxxx-yyyy",
					PkgName:          "zlib1g",
					PkgIdentifier:    trivy.Identifier{PURL: "pkg:deb/debian/zlib1g@1.2.8"},
					InstalledVersion: "1.2.8",
					Severity:         "MEDIUM",
					CVSS: map[string]trivy.CVSS{
						"ghsa": {V2Score: 5.0, V2Vector: "AV:N/AC:L"},
					},
				},
			},
		}},
	}
}

func TestAdaptTrivy_MapsPackagesAndVulns(t *testing.T) {
	results, ros := adaptTrivy(sampleTrivyReport())

	if ros == nil || ros.Family != "debian" || ros.Version != "9.6" {
		t.Fatalf("OS mapping wrong: %+v", ros)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 components, got %d", len(results))
	}

	byName := map[string]int{}
	for _, r := range results {
		byName[r.Name] = len(r.Vulnerabilities)
		if r.System != "deb" {
			t.Errorf("%s: system = %q, want deb", r.Name, r.System)
		}
	}
	if byName["apt"] != 1 || byName["zlib1g"] != 1 {
		t.Fatalf("vuln attachment wrong: %v", byName)
	}

	var apt *resultView
	for _, r := range results {
		if r.Name == "apt" {
			v := r.Vulnerabilities[0]
			apt = &resultView{
				cve: v.CVE, sev: v.Severity, score: v.CVSS,
				vector: v.CVSSVector, src: v.SeveritySource,
				fixed: v.Fixed, layer: r.LayerDigest,
			}
		}
	}
	if apt == nil {
		t.Fatal("apt component missing")
	}
	if apt.cve != "CVE-2019-3462" {
		t.Errorf("CVE not extracted: %q", apt.cve)
	}
	if apt.sev != "HIGH" {
		t.Errorf("severity not normalised: %q", apt.sev)
	}
	if apt.score != 8.1 || apt.vector != "CVSS:3.1/AV:N" {
		t.Errorf("CVSS v3 not preferred: score=%v vector=%q", apt.score, apt.vector)
	}
	if apt.src != "trivy" {
		t.Errorf("severitySource = %q, want trivy", apt.src)
	}
	if len(apt.fixed) != 1 || apt.fixed[0] != "1.4.9" {
		t.Errorf("fixed version not mapped: %v", apt.fixed)
	}
	if apt.layer != "sha256:layer1" {
		t.Errorf("layer not mapped: %q", apt.layer)
	}
}

type resultView struct {
	cve, sev, vector, src, layer string
	score                        float64
	fixed                        []string
}

func TestConvertVuln_NonCVEIDLeavesCVEEmpty(t *testing.T) {
	results, _ := adaptTrivy(sampleTrivyReport())
	for _, r := range results {
		if r.Name != "zlib1g" {
			continue
		}
		v := r.Vulnerabilities[0]
		if v.CVE != "" {
			t.Errorf("GHSA id leaked into CVE field: %q", v.CVE)
		}
		if v.ID != "GHSA-xxxx-yyyy" {
			t.Errorf("ID not preserved: %q", v.ID)
		}
		if v.CVSS != 5.0 {
			t.Errorf("v2 fallback score wrong: %v", v.CVSS)
		}
	}
}

func TestBuildImageReport_OriginAttribution(t *testing.T) {
	tr := &trivy.Report{
		ArtifactName: "my-app:latest",
		Metadata: trivy.Metadata{
			OS:      &trivy.OS{Family: "debian", Name: "12"},
			DiffIDs: []string{"sha256:base0", "sha256:app0"},
			ImageConfig: trivy.ImageConfig{
				RootFS: trivy.RootFS{DiffIDs: []string{"sha256:base0", "sha256:app0"}},
				History: []trivy.History{
					{CreatedBy: "/bin/sh -c #(nop) ADD file:... in /"},
					{CreatedBy: "COPY node_modules /app/node_modules"},
				},
			},
		},
		Results: []trivy.Result{{
			Target: "my-app:latest (debian 12)",
			Class:  "os-pkgs",
			Type:   "debian",
			Packages: []trivy.Package{
				{Name: "apt", Version: "2.6", Identifier: trivy.Identifier{PURL: "pkg:deb/debian/apt@2.6"},
					Layer: trivy.Layer{DiffID: "sha256:base0"}},
				{Name: "left-pad", Version: "1.3.0", Identifier: trivy.Identifier{PURL: "pkg:npm/left-pad@1.3.0"},
					Layer: trivy.Layer{DiffID: "sha256:app0"}},
				{Name: "ghost", Version: "0", Identifier: trivy.Identifier{PURL: "pkg:npm/ghost@0"}},
			},
		}},
	}
	results, ros := adaptTrivy(tr)
	base := baseAttribution{known: true, set: map[string]bool{"sha256:base0": true}}
	rep := buildImageReport("image:my-app:latest", ros, tr, results, base, nil, nil, nil)

	got := map[string]ComponentReport{}
	for _, c := range rep.Components {
		got[c.Name] = c
	}
	if got["apt"].Origin != OriginBase {
		t.Errorf("apt origin = %q, want base", got["apt"].Origin)
	}
	if got["left-pad"].Origin != OriginApp {
		t.Errorf("left-pad origin = %q, want app", got["left-pad"].Origin)
	}

	if got["ghost"].Origin != OriginUnknown {
		t.Errorf("ghost origin = %q, want unknown", got["ghost"].Origin)
	}

	if got["left-pad"].LayerCreatedBy != "COPY node_modules /app/node_modules" {
		t.Errorf("left-pad createdBy = %q", got["left-pad"].LayerCreatedBy)
	}
}

func TestBuildImageReport_OriginEmptyWhenNoBase(t *testing.T) {
	tr := sampleTrivyReport()
	results, ros := adaptTrivy(tr)
	rep := buildImageReport("image:php:7.0", ros, tr, results, baseAttribution{}, nil, nil, nil)
	for _, c := range rep.Components {
		if c.Origin != "" {
			t.Errorf("%s: origin = %q, want empty (no base known)", c.Name, c.Origin)
		}
	}
}

func TestBuildImageReport_Totals(t *testing.T) {
	tr := sampleTrivyReport()
	results, ros := adaptTrivy(tr)

	rep := buildImageReport("image:php:7.0", ros, tr, results, baseAttribution{}, nil, nil, nil)

	if rep.Totals.Components != 2 {
		t.Errorf("components = %d, want 2", rep.Totals.Components)
	}
	if rep.Totals.WithVulns != 2 {
		t.Errorf("withVulns = %d, want 2", rep.Totals.WithVulns)
	}
	if rep.Totals.HIGH != 1 || rep.Totals.MEDIUM != 1 {
		t.Errorf("severity rollup wrong: HIGH=%d MEDIUM=%d", rep.Totals.HIGH, rep.Totals.MEDIUM)
	}
	if rep.Source != "image:php:7.0" {
		t.Errorf("source = %q", rep.Source)
	}
	for _, c := range rep.Components {
		if c.Class != "os-pkgs" || c.Type != "debian" {
			t.Errorf("%s: class/type not from trivy: %q/%q", c.Name, c.Class, c.Type)
		}
	}
}

func TestBuildImageReport_ReachabilityJoin(t *testing.T) {
	tr := &trivy.Report{
		ArtifactName: "my-app:latest",
		Results: []trivy.Result{{
			Target: "my-app:latest",
			Class:  "lang-pkgs",
			Type:   "gomod",
			Packages: []trivy.Package{
				{Name: "github.com/jackc/pgx/v5", Version: "v5.7.2",
					Identifier: trivy.Identifier{PURL: "pkg:golang/github.com/jackc/pgx/v5@v5.7.2"}},
				{Name: "apt", Version: "1.4.8",
					Identifier: trivy.Identifier{PURL: "pkg:deb/debian/apt@1.4.8"}},
			},
			Vulnerabilities: []trivy.Vulnerability{
				{VulnerabilityID: "CVE-2026-33815", PkgName: "github.com/jackc/pgx/v5",
					PkgIdentifier:    trivy.Identifier{PURL: "pkg:golang/github.com/jackc/pgx/v5@v5.7.2"},
					InstalledVersion: "v5.7.2", Severity: "HIGH"},
				{VulnerabilityID: "CVE-2019-3462", PkgName: "apt",
					PkgIdentifier:    trivy.Identifier{PURL: "pkg:deb/debian/apt@1.4.8"},
					InstalledVersion: "1.4.8", Severity: "HIGH"},
			},
		}},
	}
	results, ros := adaptTrivy(tr)

	oracle := &reachability.Result{
		ByVuln: map[string]reachability.State{
			"GO-2026-4771":   reachability.StateReachable,
			"CVE-2026-33815": reachability.StateReachable,
		},
		HaveModuleUsage: true,
		Modules:         map[string]bool{"github.com/jackc/pgx/v5": true},
	}

	sourceLibs := SourceLibSet([]byte(`{"components":[{"purl":"pkg:golang/github.com/jackc/pgx/v5@v5.7.2"}]}`))

	rep := buildImageReport("image:my-app:latest", ros, tr, results, baseAttribution{}, oracle, sourceLibs, nil)

	got := map[string]ComponentReport{}
	for _, c := range rep.Components {
		got[c.Name] = c
	}
	pgx := got["github.com/jackc/pgx/v5"]

	if pgx.Origin != OriginApp {
		t.Errorf("pgx origin = %q, want app", pgx.Origin)
	}
	if len(pgx.Vulnerabilities) != 1 || pgx.Vulnerabilities[0].Reachable != "reachable" {
		t.Fatalf("pgx CVE reachable = %+v, want reachable", pgx.Vulnerabilities)
	}

	apt := got["apt"]
	if apt.Origin != OriginImage {
		t.Errorf("apt origin = %q, want image", apt.Origin)
	}
	if r := apt.Vulnerabilities[0].Reachable; r != "" {
		t.Errorf("apt CVE reachable = %q, want empty (oracle has no verdict)", r)
	}
	if rep.Totals.Reachable != 1 {
		t.Errorf("Totals.Reachable = %d, want 1 (pgx CVE)", rep.Totals.Reachable)
	}
	if rep.Totals.ReachUnknown != 1 {
		t.Errorf("Totals.ReachUnknown = %d, want 1 (apt's CVE, undecided)", rep.Totals.ReachUnknown)
	}
}

func TestBuildImageReport_StdlibVersionAttribution(t *testing.T) {
	tr := &trivy.Report{
		ArtifactName: "my-app:latest",
		Results: []trivy.Result{{
			Target: "my-app:latest", Class: "lang-pkgs", Type: "gomod",
			Packages: []trivy.Package{
				{Name: "stdlib", Version: "v1.22.12", Identifier: trivy.Identifier{PURL: "pkg:golang/stdlib@v1.22.12"}},
				{Name: "stdlib", Version: "v1.25.9", Identifier: trivy.Identifier{PURL: "pkg:golang/stdlib@v1.25.9"}},
			},
		}},
	}
	results, ros := adaptTrivy(tr)
	oracle := &reachability.Result{GoVersion: "go1.22.12"}
	rep := buildImageReport("image:my-app:latest", ros, tr, results, baseAttribution{}, oracle, map[string]bool{}, nil)

	for _, c := range rep.Components {
		switch c.Version {
		case "v1.22.12":
			if c.Origin != OriginApp {
				t.Errorf("app stdlib %s origin = %q, want app", c.Version, c.Origin)
			}
		case "v1.25.9":
			if c.Origin != OriginImageLib {
				t.Errorf("foreign stdlib %s origin = %q, want image-lib", c.Version, c.Origin)
			}
		}
	}
}

func TestBuildImageReport_NoReachabilityWhenNil(t *testing.T) {
	tr := sampleTrivyReport()
	results, ros := adaptTrivy(tr)
	rep := buildImageReport("image:php:7.0", ros, tr, results, baseAttribution{}, nil, nil, nil)
	if rep.Totals.Reachable+rep.Totals.Unreachable+rep.Totals.ReachUnknown != 0 {
		t.Errorf("reachability totals non-zero without --compare: %+v", rep.Totals)
	}
	for _, c := range rep.Components {
		for _, v := range c.Vulnerabilities {
			if v.Reachable != "" {
				t.Errorf("%s: vuln %s marked %q without --compare", c.Name, v.ID, v.Reachable)
			}
		}
	}
}
