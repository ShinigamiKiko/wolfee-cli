package sbomscan

import (
	"testing"

	"deps.dev/util/semver"

	"sca-go/cli/internal/onlinescan"
)

func TestDepsDevTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantPath string
		wantSV   semver.System
	}{
		{"NPM", "npm", semver.NPM},
		{"GO", "go", semver.Go},
		{"MAVEN", "maven", semver.Maven},
		{"PYPI", "pypi", semver.PyPI},
		{"CARGO", "cargo", semver.Cargo},
		{"NUGET", "nuget", semver.NuGet},
		{"RUBYGEMS", "rubygems", semver.RubyGems},
	}
	for _, c := range cases {
		path, sv, ok := depsDevTarget(c.in)
		if !ok || path != c.wantPath || sv != c.wantSV {
			t.Errorf("depsDevTarget(%q) = (%q,%v,%v), want (%q,%v,true)", c.in, path, sv, ok, c.wantPath, c.wantSV)
		}
	}
	for _, in := range []string{"DEBIAN", "RPM", "ALPINE", "PACKAGIST", ""} {
		if _, _, ok := depsDevTarget(in); ok {
			t.Errorf("depsDevTarget(%q) should be unsupported", in)
		}
	}
}

// TestSemverOrdering guards the core invariant that fixed the downgrade bug:
// the semver system must order versions correctly so we never treat an older
// release as "newer than current".
func TestSemverOrdering(t *testing.T) {
	if semver.NPM.Compare("3.21.7", "4.4.6") >= 0 {
		t.Error("npm: 3.21.7 must be older than 4.4.6 (downgrade guard)")
	}
	if semver.NPM.Compare("4.21.1", "4.17.1") <= 0 {
		t.Error("npm: 4.21.1 must be newer than 4.17.1")
	}
	if semver.Go.Compare("v1.3.0", "v1.2.3") <= 0 {
		t.Error("go: v1.3.0 must be newer than v1.2.3")
	}
}

func TestSwapPURLVersion(t *testing.T) {
	cases := []struct {
		purl string
		ver  string
		want string
	}{
		{"pkg:npm/cookie@0.4.0", "0.7.1", "pkg:npm/cookie@0.7.1"},
		{"pkg:npm/%40angular/core@15.2.0", "16.0.0", "pkg:npm/%40angular/core@16.0.0"},
		{"pkg:golang/github.com/foo/bar@v1.2.3?type=module", "v1.3.0", "pkg:golang/github.com/foo/bar@v1.3.0"},
		{"pkg:pypi/requests@2.0", "2.31.0", "pkg:pypi/requests@2.31.0"},
	}
	for _, c := range cases {
		if got := swapPURLVersion(c.purl, c.ver); got != c.want {
			t.Errorf("swapPURLVersion(%q,%q) = %q, want %q", c.purl, c.ver, got, c.want)
		}
	}
}

func TestFindChildVersion(t *testing.T) {
	deps := &depsDevDependencies{Nodes: []depsDevDepNode{
		{VersionKey: depsDevVersionKey{Name: "express", Version: "4.21.1"}, Relation: "SELF"},
		{VersionKey: depsDevVersionKey{Name: "@nuxt/ui", Version: "0.7.1"}, Relation: "INDIRECT"},
	}}
	// Scoped names must match exactly (they come from purl.Parse, not labels).
	if v, ok := findChildVersion(deps, "@nuxt/ui"); !ok || v != "0.7.1" {
		t.Fatalf("findChildVersion = (%q,%v), want (0.7.1,true)", v, ok)
	}
	// SELF node with the same name as the child must be ignored.
	if _, ok := findChildVersion(deps, "express"); ok {
		t.Fatal("findChildVersion should skip SELF")
	}
	if _, ok := findChildVersion(deps, "lodash"); ok {
		t.Fatal("absent package must report not present")
	}
}

func TestVulnStillPresent(t *testing.T) {
	target := &onlinescan.Vulnerability{ID: "GHSA-pxg6-pf52-xh8x", CVE: "CVE-2024-47764"}
	if !vulnStillPresent([]onlinescan.Vulnerability{{ID: "GHSA-xxxx", CVE: "CVE-2024-47764"}}, target) {
		t.Error("should match on CVE")
	}
	if !vulnStillPresent([]onlinescan.Vulnerability{{ID: "OSV-1", Aliases: []string{"GHSA-pxg6-pf52-xh8x"}}}, target) {
		t.Error("should match on alias")
	}
	if vulnStillPresent([]onlinescan.Vulnerability{{CVE: "CVE-2020-0001"}}, target) {
		t.Error("unrelated vuln should not match")
	}
}
