package sbomscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// manifestRootRef names the root manifestRoot adds. It never reaches the
// report: the edges only feed direct/transitive detection and dependency paths.
const manifestRootRef = "wolfee:manifest-root"

// manifestRoot builds the project's root edges when the SBOM has none. cdxgen
// adds them for composer only when composer.json has a "name", which
// applications (type "project") usually lack; without a root every package
// that something else also requires looks transitive. The requirements are
// read from composer.json in dir; versions still come from the SBOM, i.e.
// composer.lock.
func manifestRoot(r *Report, dir string) []Dependency {
	if r == nil || dir == "" || len(rootChildren(r, r.Dependencies)) > 0 {
		return nil
	}
	required := composerRequires(filepath.Join(dir, "composer.json"))
	if len(required) == 0 {
		return nil
	}
	var refs []string
	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef == "" || !strings.HasPrefix(strings.ToLower(c.PURL), "pkg:composer/") {
			continue
		}
		if required[strings.ToLower(componentName(c))] {
			refs = append(refs, c.BOMRef)
		}
	}
	if len(refs) == 0 {
		return nil
	}
	sort.Strings(refs)
	return []Dependency{{Ref: manifestRootRef, DependsOn: refs}}
}

// composerRequires lists the packages composer.json requires, dev ones
// included. Platform requirements (php, ext-*) have no vendor and are skipped.
func composerRequires(path string) map[string]bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	out := map[string]bool{}
	for _, reqs := range []map[string]string{m.Require, m.RequireDev} {
		for name := range reqs {
			if strings.Contains(name, "/") {
				out[strings.ToLower(name)] = true
			}
		}
	}
	return out
}

// annotateDirect marks each component direct when the project itself depends
// on it, transitive otherwise - also when other packages pull it in too. A Go
// module cdxgen flags indirect stays transitive although go.mod lists it.
// Components outside the dependency graph keep Direct nil.
func annotateDirect(r *Report, extra ...Dependency) {
	if r == nil {
		return
	}
	deps := withExtraDeps(r.Dependencies, extra)
	roots := graphRoots(r, deps)
	direct := rootChildren(r, deps)
	if len(direct) == 0 {
		// No root edges and no manifest: a package nothing else requires can
		// only be there because the project requires it. One that others
		// require too cannot be told apart and reads transitive.
		direct = parentless(deps, roots)
	}
	if len(direct) == 0 {
		return
	}
	inGraph := map[string]bool{}
	for _, d := range deps {
		inGraph[d.Ref] = true
		for _, on := range d.DependsOn {
			inGraph[on] = true
		}
	}
	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef == "" || roots[c.BOMRef] || !inGraph[c.BOMRef] {
			continue
		}
		d := direct[c.BOMRef] && !goIndirect(c)
		c.Direct = &d
	}
}

// parentless lists the graph's nodes that no other package depends on.
func parentless(deps []Dependency, roots map[string]bool) map[string]bool {
	hasParent := map[string]bool{}
	for _, d := range deps {
		if roots[d.Ref] {
			continue
		}
		for _, on := range d.DependsOn {
			hasParent[on] = true
		}
	}
	out := map[string]bool{}
	for _, d := range deps {
		for _, ref := range append([]string{d.Ref}, d.DependsOn...) {
			if ref != "" && !roots[ref] && !hasParent[ref] {
				out[ref] = true
			}
		}
	}
	return out
}

func goIndirect(c *ComponentReport) bool {
	for _, p := range c.Properties {
		if strings.EqualFold(p.Name, "cdx:go:indirect") && strings.EqualFold(strings.TrimSpace(p.Value), "true") {
			return true
		}
	}
	return false
}
