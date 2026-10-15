package sbomscan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func composerComp(group, name, version string) ComponentReport {
	ref := fmt.Sprintf("pkg:composer/%s/%s@%s", group, name, version)
	return ComponentReport{BOMRef: ref, PURL: ref, System: "PACKAGIST", Group: group, Name: name, Version: version}
}

// A Symfony application: composer.json has no "name", so cdxgen emits no root
// and twig/twig - required by the project and by twig-bundle - has a parent.
func namelessComposerReport() *Report {
	twig := composerComp("twig", "twig", "v3.8.0")
	bundle := composerComp("symfony", "twig-bundle", "v5.4.31")
	guzzle := composerComp("guzzlehttp", "guzzle", "7.6.1")
	psr7 := composerComp("guzzlehttp", "psr7", "2.4.5")
	phpunit := composerComp("phpunit", "phpunit", "9.5.16")
	phpunit.Scope = "optional"
	return &Report{
		Components: []ComponentReport{twig, bundle, guzzle, psr7, phpunit},
		Dependencies: []Dependency{
			{Ref: bundle.BOMRef, DependsOn: []string{twig.BOMRef}},
			{Ref: guzzle.BOMRef, DependsOn: []string{psr7.BOMRef}},
			{Ref: twig.BOMRef}, {Ref: psr7.BOMRef}, {Ref: phpunit.BOMRef},
		},
	}
}

func writeComposerJSON(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func directOf(r *Report) map[string]string {
	out := map[string]string{}
	for _, c := range r.Components {
		switch {
		case c.Direct == nil:
			out[componentName(&c)] = "unknown"
		case *c.Direct:
			out[componentName(&c)] = "direct"
		default:
			out[componentName(&c)] = "transitive"
		}
	}
	return out
}

func TestManifestRoot_ComposerWithoutName(t *testing.T) {
	r := namelessComposerReport()
	dir := writeComposerJSON(t, `{"type": "project",
		"require": {"php": ">=8.1", "twig/twig": "^3.8", "symfony/twig-bundle": "5.4.*", "guzzlehttp/guzzle": "^7.6"},
		"require-dev": {"phpunit/phpunit": "^9.5"}}`)

	root := manifestRoot(r, dir)
	if len(root) != 1 || len(root[0].DependsOn) != 4 {
		t.Fatalf("manifest root = %+v, want edges to the 4 required packages", root)
	}
	annotateDependencyPaths(r, root...)
	annotateDirect(r, root...)

	got := directOf(r)
	want := map[string]string{
		"twig/twig": "direct", "symfony/twig-bundle": "direct", "guzzlehttp/guzzle": "direct",
		"phpunit/phpunit": "direct", "guzzlehttp/psr7": "transitive",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("direct = %v, want %v", got, want)
	}
	for _, c := range r.Components {
		if c.Name == "psr7" && fmt.Sprint(c.DependencyPaths) != "[[guzzlehttp/guzzle@7.6.1 guzzlehttp/psr7@2.4.5]]" {
			t.Errorf("psr7 paths = %v, want them to start at the direct dependency", c.DependencyPaths)
		}
	}
	if len(r.Dependencies) != 5 {
		t.Errorf("the manifest root must not be added to the report's graph, got %d entries", len(r.Dependencies))
	}
}

func TestManifestRoot_NotNeededWhenSBOMHasRoot(t *testing.T) {
	r := namelessComposerReport()
	r.Document = &Document{Metadata: &DocumentMetadata{Component: &DocumentComponent{BOMRef: "pkg:composer/acme/app@1.0.0"}}}
	r.Dependencies = append(r.Dependencies, Dependency{Ref: "pkg:composer/acme/app@1.0.0",
		DependsOn: []string{"pkg:composer/symfony/twig-bundle@v5.4.31", "pkg:composer/guzzlehttp/guzzle@7.6.1"}})
	dir := writeComposerJSON(t, `{"require": {"twig/twig": "^3.8"}}`)

	if root := manifestRoot(r, dir); root != nil {
		t.Errorf("an SBOM with root edges must be used as is, got %+v", root)
	}
	annotateDirect(r)
	if got := directOf(r); got["twig/twig"] != "transitive" || got["symfony/twig-bundle"] != "direct" {
		t.Errorf("direct = %v, want the SBOM root's edges", got)
	}
}

func TestAnnotateDirect_NoRootFallsBackToParentless(t *testing.T) {
	// --bom input without a project directory: packages nothing requires are
	// direct; twig, required by twig-bundle, cannot be told apart.
	r := namelessComposerReport()
	annotateDirect(r, manifestRoot(r, "")...)
	want := map[string]string{
		"twig/twig": "transitive", "symfony/twig-bundle": "direct", "guzzlehttp/guzzle": "direct",
		"phpunit/phpunit": "direct", "guzzlehttp/psr7": "transitive",
	}
	if got := directOf(r); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("direct = %v, want %v", got, want)
	}
}

func TestAnnotateDirect_GoIndirectStaysTransitive(t *testing.T) {
	mod := "pkg:golang/example.com/app@v1.0.0"
	direct := ComponentReport{BOMRef: "pkg:golang/example.com/a@v1.0.0", Name: "a", Version: "v1.0.0"}
	indirect := ComponentReport{BOMRef: "pkg:golang/example.com/b@v1.0.0", Name: "b", Version: "v1.0.0",
		Properties: []Property{{Name: "cdx:go:indirect", Value: "true"}}}
	r := &Report{
		Document:     &Document{Metadata: &DocumentMetadata{Component: &DocumentComponent{BOMRef: mod}}},
		Components:   []ComponentReport{direct, indirect},
		Dependencies: []Dependency{{Ref: mod, DependsOn: []string{direct.BOMRef, indirect.BOMRef}}},
	}
	annotateDirect(r)
	if got := directOf(r); got["a"] != "direct" || got["b"] != "transitive" {
		t.Errorf("direct = %v, want go.mod's // indirect module transitive", got)
	}
}

func TestComposerRequires(t *testing.T) {
	dir := writeComposerJSON(t, `{"require": {"php": ">=8.1", "ext-json": "*", "Twig/Twig": "^3"}, "require-dev": {"phpunit/phpunit": "^9"}}`)
	got := composerRequires(filepath.Join(dir, "composer.json"))
	if fmt.Sprint(got) != "map[phpunit/phpunit:true twig/twig:true]" {
		t.Errorf("requires = %v", got)
	}
	if composerRequires(filepath.Join(t.TempDir(), "composer.json")) != nil {
		t.Error("a missing composer.json must yield nothing")
	}
}
