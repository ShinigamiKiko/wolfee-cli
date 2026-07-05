package sbomscan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"sca-go/cli/internal/onlinescan"
)

func gnode(ref, name, ver string) ComponentReport {
	return ComponentReport{BOMRef: ref, Name: name, Version: ver, PURL: "pkg:test/" + name + "@" + ver}
}

func dep(ref string, on ...string) Dependency { return Dependency{Ref: ref, DependsOn: on} }

func withRoot(root string, deps []Dependency, comps ...ComponentReport) *Report {
	return &Report{
		Document:     &Document{Metadata: &DocumentMetadata{Component: &DocumentComponent{BOMRef: root}}},
		Dependencies: deps,
		Components:   comps,
	}
}

func pathsOf(r *Report, name string) [][]string {
	for i := range r.Components {
		if r.Components[i].Name == name {
			return r.Components[i].DependencyPaths
		}
	}
	return nil
}

func TestDependencyPathsLinear(t *testing.T) {

	r := withRoot("root",
		[]Dependency{dep("root", "a"), dep("a", "b"), dep("b", "c")},
		gnode("a", "a", "1"), gnode("b", "b", "2"), gnode("c", "c", "3"),
	)
	annotateDependencyPaths(r)

	if got := pathsOf(r, "a"); got != nil {
		t.Errorf("direct dep a should have no paths, got %v", got)
	}
	if got, want := pathsOf(r, "b"), [][]string{{"a@1", "b@2"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("b paths: got %v want %v", got, want)
	}
	if got, want := pathsOf(r, "c"), [][]string{{"a@1", "b@2", "c@3"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("c paths: got %v want %v", got, want)
	}
}

func TestDependencyPathsWeb(t *testing.T) {

	r := withRoot("root",
		[]Dependency{dep("root", "a", "d"), dep("a", "b"), dep("d", "b"), dep("b", "c")},
		gnode("a", "a", "1"), gnode("d", "d", "4"), gnode("b", "b", "2"), gnode("c", "c", "3"),
	)
	annotateDependencyPaths(r)

	if got, want := pathsOf(r, "b"), [][]string{{"a@1", "b@2"}, {"d@4", "b@2"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("b paths: got %v want %v", got, want)
	}
	if got, want := pathsOf(r, "c"), [][]string{{"a@1", "b@2", "c@3"}, {"d@4", "b@2", "c@3"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("c paths: got %v want %v", got, want)
	}
}

func TestDependencyPathsPrefersParentChainOverRootShortcut(t *testing.T) {

	r := withRoot("root",
		[]Dependency{
			dep("root", "direct", "middle"),
			dep("direct", "middle"),
			dep("middle", "leaf"),
			dep("leaf", "vuln"),
		},
		gnode("direct", "direct-dep", "1.0.0"),
		gnode("middle", "middle-dep", "2.0.0"),
		gnode("leaf", "leaf-dep", "3.0.0"),
		gnode("vuln", "vulnerable-dep", "4.0.0"),
	)
	annotateDependencyPaths(r)

	if got, want := pathsOf(r, "vulnerable-dep"), [][]string{{"direct-dep@1.0.0", "middle-dep@2.0.0", "leaf-dep@3.0.0", "vulnerable-dep@4.0.0"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("vulnerable-dep paths: got %v want %v", got, want)
	}
}

func TestDependencyPathsCycleTerminates(t *testing.T) {

	r := withRoot("root",
		[]Dependency{dep("root", "a"), dep("a", "b"), dep("b", "a", "c")},
		gnode("a", "a", "1"), gnode("b", "b", "2"), gnode("c", "c", "3"),
	)
	annotateDependencyPaths(r)

	if got, want := pathsOf(r, "c"), [][]string{{"a@1", "b@2", "c@3"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("c paths under cycle: got %v want %v", got, want)
	}
}

func TestDependencyPathsCapped(t *testing.T) {

	fanout := maxDepPaths + 7
	names := make([]string, 0, fanout)
	for i := 0; i < fanout; i++ {
		names = append(names, fmt.Sprintf("n%d", i))
	}
	deps := []Dependency{dep("root", names...)}
	comps := []ComponentReport{gnode("t", "t", "9")}
	for _, n := range names {
		deps = append(deps, dep(n, "t"))
		comps = append(comps, gnode(n, n, "1"))
	}
	r := withRoot("root", deps, comps...)
	annotateDependencyPaths(r)

	if got := pathsOf(r, "t"); len(got) != maxDepPaths {
		t.Errorf("t routes: got %d want capped at %d", len(got), maxDepPaths)
	}
}

func TestDependencyPathsStripsOwnModule(t *testing.T) {

	r := withRoot("root",
		[]Dependency{dep("root", "mod"), dep("mod", "dep"), dep("dep", "vuln")},
		ComponentReport{BOMRef: "mod", Name: "mymod", Version: "0.0.0", Type: "application"},
		gnode("dep", "dep", "1"),
		gnode("vuln", "vuln", "2"),
	)
	annotateDependencyPaths(r)

	if got := pathsOf(r, "dep"); got != nil {
		t.Errorf("dep should be direct after module strip, got %v", got)
	}

	if got, want := pathsOf(r, "vuln"), [][]string{{"dep@1", "vuln@2"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("vuln path: got %v want %v", got, want)
	}
}

func TestDependencyPathsStripsVersionlessModule(t *testing.T) {

	r := withRoot("proj",
		[]Dependency{dep("proj", "mod"), dep("mod", "pgx"), dep("pgx", "crypto")},
		ComponentReport{BOMRef: "mod", Name: "sca-go"},
		gnode("pgx", "github.com/jackc/pgx/v5", "v5.7.2"),
		gnode("crypto", "golang.org/x/crypto", "v0.31.0"),
	)
	annotateDependencyPaths(r)

	if got := pathsOf(r, "github.com/jackc/pgx/v5"); got != nil {
		t.Errorf("pgx should be direct after versionless-module strip, got %v", got)
	}
	want := [][]string{{"github.com/jackc/pgx/v5@v5.7.2", "golang.org/x/crypto@v0.31.0"}}
	if got := pathsOf(r, "golang.org/x/crypto"); !reflect.DeepEqual(got, want) {
		t.Errorf("crypto path: got %v want %v", got, want)
	}
}

func TestDependencyPathsNoGraph(t *testing.T) {

	r := &Report{Components: []ComponentReport{gnode("a", "a", "1")}}
	annotateDependencyPaths(r)
	if got := pathsOf(r, "a"); got != nil {
		t.Errorf("no-graph: got %v want nil", got)
	}
}

func TestDependencyPathsRootless(t *testing.T) {

	r := &Report{
		Dependencies: []Dependency{dep("a", "b"), dep("b", "c")},
		Components:   []ComponentReport{gnode("a", "a", "1"), gnode("b", "b", "2"), gnode("c", "c", "3")},
	}
	annotateDependencyPaths(r)

	if got := pathsOf(r, "a"); got != nil {
		t.Errorf("inferred-root a should have no paths, got %v", got)
	}
	if got, want := pathsOf(r, "c"), [][]string{{"a@1", "b@2", "c@3"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("c paths (rootless): got %v want %v", got, want)
	}
}

func TestDependencyPathsJSONShape(t *testing.T) {
	c := ComponentReport{Name: "x", Version: "1", DependencyPaths: [][]string{{"a@1", "x@1"}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"dependencyPaths":[["a@1","x@1"]]`) {
		t.Errorf("dependencyPaths key/shape missing in JSON: %s", b)
	}

	b2, _ := json.Marshal(ComponentReport{Name: "d", Version: "2"})
	if strings.Contains(string(b2), "dependencyPaths") {
		t.Errorf("empty paths should be omitted: %s", b2)
	}
}

func TestMergeSourceVulnsCarriesPaths(t *testing.T) {
	vuln := func(cve, sev string) onlinescan.Vulnerability {
		return onlinescan.Vulnerability{CVE: cve, Severity: sev}
	}
	image := &Report{Components: []ComponentReport{
		{PURL: "pkg:golang/x@1", Name: "x", Version: "1", Origin: OriginApp},
	}}
	source := &Report{
		Dependencies: []Dependency{dep("root", "d"), dep("d", "x"), dep("d", "y")},
		Components: []ComponentReport{
			{BOMRef: "x", PURL: "pkg:golang/x@1", Name: "x", Version: "1",
				DependencyPaths: [][]string{{"d@2", "x@1"}}, Vulnerabilities: []onlinescan.Vulnerability{vuln("CVE-1", "HIGH")}},
			{BOMRef: "y", PURL: "pkg:golang/y@1", Name: "y", Version: "1",
				DependencyPaths: [][]string{{"d@2", "y@1"}}, Vulnerabilities: []onlinescan.Vulnerability{vuln("CVE-2", "LOW")}},
		},
	}
	MergeSourceVulns(image, source, nil)

	if got, want := image.Components[0].DependencyPaths, [][]string{{"d@2", "x@1"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("matched comp paths: got %v want %v", got, want)
	}

	var y *ComponentReport
	for i := range image.Components {
		if image.Components[i].Name == "y" {
			y = &image.Components[i]
		}
	}
	if y == nil {
		t.Fatalf("source-only component y was not appended: %s", fmt.Sprint(image.Components))
	}
	if got, want := y.DependencyPaths, [][]string{{"d@2", "y@1"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("appended comp paths: got %v want %v", got, want)
	}

	if len(image.Dependencies) != len(source.Dependencies) {
		t.Errorf("image.Dependencies: got %d edges want %d", len(image.Dependencies), len(source.Dependencies))
	}
}
