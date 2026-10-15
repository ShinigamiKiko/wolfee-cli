package sbomscan

import (
	"sort"
	"strings"
)

const (
	maxDepPaths = 100

	maxDepPathLen = 32

	maxDepVisits = 50000
)

// annotateDependencyPaths records, for every component, the chains from a
// direct dependency down to it. extra edges (a manifest root, see manifestRoot)
// join the SBOM's own graph.
func annotateDependencyPaths(r *Report, extra ...Dependency) {
	if r == nil || len(r.Components) == 0 {
		return
	}
	deps := withExtraDeps(r.Dependencies, extra)
	if len(deps) == 0 {
		return
	}

	parents := make(map[string][]string, len(deps))
	for _, d := range deps {
		if d.Ref == "" {
			continue
		}
		for _, on := range d.DependsOn {
			if on == "" {
				continue
			}
			parents[on] = append(parents[on], d.Ref)
		}
	}

	label := make(map[string]string, len(r.Components))
	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef != "" {
			label[c.BOMRef] = pkgLabel(componentName(c), c.Version)
		}
	}
	roots := graphRoots(r, deps)

	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef == "" || roots[c.BOMRef] {
			continue
		}
		refPaths, truncated := resolveDepPaths(c.BOMRef, parents, roots)
		if len(refPaths) == 0 {
			continue
		}
		out := make([][]string, 0, len(refPaths))
		for _, rp := range refPaths {
			lp := make([]string, 0, len(rp))
			for _, ref := range rp {
				if l := label[ref]; l != "" {
					lp = append(lp, l)
				} else {
					lp = append(lp, cleanRef(ref))
				}
			}
			out = append(out, lp)
		}
		c.DependencyPaths = out
		c.DependencyPathsTruncated = truncated
	}
}

func withExtraDeps(deps, extra []Dependency) []Dependency {
	if len(extra) == 0 {
		return deps
	}
	return append(append([]Dependency(nil), extra...), deps...)
}

// graphRoots returns the nodes that stand for the project itself: the SBOM's
// metadata component, and any node with children that is an application or
// has no version (a root cdxgen did not list as a component, or the manifest
// root).
func graphRoots(r *Report, deps []Dependency) map[string]bool {
	version := make(map[string]string, len(r.Components))
	appNode := make(map[string]bool)
	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef == "" {
			continue
		}
		version[c.BOMRef] = strings.TrimSpace(c.Version)
		if strings.EqualFold(c.Type, "application") {
			appNode[c.BOMRef] = true
		}
	}

	roots := map[string]bool{}
	if r.Document != nil && r.Document.Metadata != nil && r.Document.Metadata.Component != nil {
		if rr := r.Document.Metadata.Component.BOMRef; rr != "" {
			roots[rr] = true
		}
	}
	for _, d := range deps {
		if d.Ref != "" && len(d.DependsOn) > 0 && (appNode[d.Ref] || version[d.Ref] == "") {
			roots[d.Ref] = true
		}
	}
	return roots
}

// rootChildren lists what the project depends on directly: the children of
// its graph roots.
func rootChildren(r *Report, deps []Dependency) map[string]bool {
	roots := graphRoots(r, deps)
	direct := map[string]bool{}
	for _, d := range deps {
		if !roots[d.Ref] {
			continue
		}
		for _, on := range d.DependsOn {
			if on != "" && !roots[on] {
				direct[on] = true
			}
		}
	}
	return direct
}

func resolveDepPaths(target string, parents map[string][]string, roots map[string]bool) ([][]string, bool) {
	onStack := map[string]bool{target: true}
	budget := maxDepVisits

	var walk func(node string, depth int) ([][]string, bool)
	walk = func(node string, depth int) ([][]string, bool) {
		if budget <= 0 || depth > maxDepPathLen {
			return nil, true
		}
		budget--

		var nonRoot []string
		for _, p := range parents[node] {
			if roots[p] {
				continue
			}
			if onStack[p] {
				continue
			}
			nonRoot = append(nonRoot, p)
		}

		var paths [][]string
		truncated := false

		if len(nonRoot) == 0 {
			paths = append(paths, []string{node})
		}
		for _, p := range nonRoot {
			onStack[p] = true
			subPaths, subTruncated := walk(p, depth+1)
			truncated = truncated || subTruncated
			for _, sub := range subPaths {

				np := make([]string, len(sub)+1)
				copy(np, sub)
				np[len(sub)] = node
				paths = append(paths, np)
				if len(paths) >= maxDepPaths {
					truncated = true
					break
				}
			}
			onStack[p] = false
			if len(paths) >= maxDepPaths {
				break
			}
		}
		return paths, truncated
	}

	var out [][]string
	truncated := false
	seen := map[string]bool{}
	paths, walkTruncated := walk(target, 0)
	truncated = truncated || walkTruncated
	for _, p := range paths {
		if len(p) < 2 {
			continue
		}
		k := strings.Join(p, "\x00")
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
		if len(out) >= maxDepPaths {
			truncated = true
			break
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) < len(out[j])
		}
		return strings.Join(out[i], ">") < strings.Join(out[j], ">")
	})
	return out, truncated
}

// componentName is the name with its group (symfony/yaml, @scope/pkg), as the
// output's qualifiedName shows it, so packages of different vendors that share
// a bare name (cache, core) get distinct labels.
func componentName(c *ComponentReport) string {
	group := strings.TrimSuffix(strings.TrimSpace(c.Group), "/")
	if group == "" || strings.HasPrefix(c.Name, group+"/") {
		return c.Name
	}
	return group + "/" + c.Name
}

func pkgLabel(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	switch {
	case name == "":
		return ""
	case version == "":
		return name
	default:
		return name + "@" + version
	}
}

func cleanRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if rest, ok := strings.CutPrefix(ref, "pkg:"); ok {
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			return rest[i+1:]
		}
	}
	return ref
}
