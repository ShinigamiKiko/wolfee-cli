package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildNPMTransitivePURLs(t *testing.T) {
	dir := t.TempDir()

	lockJSON := `{
  "lockfileVersion": 2,
  "packages": {
    "": {},
    "node_modules/react": {
      "dependencies": { "loose-envify": "^1.4.0" }
    },
    "node_modules/loose-envify": {
      "dependencies": { "js-tokens": "^4.0.0" }
    },
    "node_modules/js-tokens": {}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	direct := map[string]bool{
		"pkg:npm/react": true,
	}
	trans := buildNPMTransitivePURLs(dir, direct)
	if trans == nil {
		t.Fatal("expected non-nil transitive map")
	}
	if !trans["pkg:npm/loose-envify"] {
		t.Error("expected loose-envify in transitive set")
	}
	if !trans["pkg:npm/js-tokens"] {
		t.Error("expected js-tokens in transitive set")
	}

	if trans["pkg:npm/react"] {
		t.Error("react (direct) should not be in transitive set")
	}
}

func TestBuildNPMTransitivePURLs_ScopedPackage(t *testing.T) {
	dir := t.TempDir()

	lockJSON := `{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/@babel/core": {
      "dependencies": { "@babel/runtime": "^7.0.0" }
    },
    "node_modules/@babel/runtime": {}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	direct := map[string]bool{
		"pkg:npm/%40babel/core": true,
	}
	trans := buildNPMTransitivePURLs(dir, direct)
	if trans == nil {
		t.Fatal("expected non-nil transitive map")
	}
	if !trans["pkg:npm/%40babel/runtime"] {
		t.Errorf("expected @babel/runtime in transitive set, got %v", trans)
	}
}

func TestBuildNPMTransitivePURLs_NoLockFile(t *testing.T) {
	dir := t.TempDir()
	result := buildNPMTransitivePURLs(dir, map[string]bool{"pkg:npm/react": true})
	if result != nil {
		t.Error("expected nil when no lock file")
	}
}

func TestNpmLockKeyToName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"node_modules/react", "react"},
		{"node_modules/@babel/core", "@babel/core"},
		{"node_modules/react/node_modules/scheduler", "scheduler"},
	}
	for _, c := range cases {
		got := npmLockKeyToName(c.in)
		if got != c.want {
			t.Errorf("npmLockKeyToName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPurlKeyToNPMName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pkg:npm/react", "react"},
		{"pkg:npm/%40babel/core", "@babel/core"},
		{"pkg:pypi/requests", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := purlKeyToNPMName(c.in)
		if got != c.want {
			t.Errorf("purlKeyToNPMName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsTransitiveImport(t *testing.T) {
	r := &Result{
		HaveImportUsage: map[string]bool{"npm": true},
		ImportedPURLs:   map[string]bool{"pkg:npm/react": true},
		TransitivePURLs: map[string]bool{"pkg:npm/loose-envify": true},
		HaveLockGraph:   true,
	}

	if r.IsTransitiveImport("pkg:npm/react") {
		t.Error("direct import should not be transitive")
	}

	if !r.IsTransitiveImport("pkg:npm/loose-envify") {
		t.Error("loose-envify should be transitive")
	}

	if r.IsTransitiveImport("pkg:npm/unknown") {
		t.Error("unknown package should not be transitive")
	}

	r.HaveLockGraph = false
	if r.IsTransitiveImport("pkg:npm/loose-envify") {
		t.Error("without lock graph should return false")
	}
}
