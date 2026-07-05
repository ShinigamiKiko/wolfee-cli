package sbomscan

import (
	"sort"
	"strings"
)

const (
	maxDepPaths = 25

	maxDepPathLen = 32

	maxDepVisits = 50000
)

func annotateDependencyPaths(r *Report) {
	if r == nil || len(r.Dependencies) == 0 || len(r.Components) == 0 {
		return
	}

	parents := make(map[string][]string, len(r.Dependencies))
	hasChildren := make(map[string]bool, len(r.Dependencies))
	for _, d := range r.Dependencies {
		if d.Ref == "" {
			continue
		}
		if len(d.DependsOn) > 0 {
			hasChildren[d.Ref] = true
		}
		for _, on := range d.DependsOn {
			if on == "" {
				continue
			}
			parents[on] = append(parents[on], d.Ref)
		}
	}

	label := make(map[string]string, len(r.Components))
	version := make(map[string]string, len(r.Components))
	appNode := make(map[string]bool)
	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef == "" {
			continue
		}
		label[c.BOMRef] = pkgLabel(c.Name, c.Version)
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
	for ref := range hasChildren {
		if appNode[ref] || version[ref] == "" {
			roots[ref] = true
		}
	}

	for i := range r.Components {
		c := &r.Components[i]
		if c.BOMRef == "" || roots[c.BOMRef] {
			continue
		}
		refPaths := resolveDepPaths(c.BOMRef, parents, roots)
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
	}
}

func resolveDepPaths(target string, parents map[string][]string, roots map[string]bool) [][]string {
	onStack := map[string]bool{target: true}
	budget := maxDepVisits

	var walk func(node string, depth int) [][]string
	walk = func(node string, depth int) [][]string {
		if budget <= 0 || depth > maxDepPathLen {
			return nil
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

		if len(nonRoot) == 0 {
			paths = append(paths, []string{node})
		}
		for _, p := range nonRoot {
			onStack[p] = true
			for _, sub := range walk(p, depth+1) {

				np := make([]string, len(sub)+1)
				copy(np, sub)
				np[len(sub)] = node
				paths = append(paths, np)
				if len(paths) >= maxDepPaths {
					break
				}
			}
			onStack[p] = false
			if len(paths) >= maxDepPaths {
				break
			}
		}
		return paths
	}

	var out [][]string
	seen := map[string]bool{}
	for _, p := range walk(target, 0) {
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
			break
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) < len(out[j])
		}
		return strings.Join(out[i], ">") < strings.Join(out[j], ">")
	})
	return out
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
