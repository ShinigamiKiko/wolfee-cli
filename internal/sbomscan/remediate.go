package sbomscan

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"deps.dev/util/semver"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/output"
	"sca-go/cli/internal/sbomscan/internal/purl"
)

const (
	remediationConcurrency = 8

	// maxRemediationCandidates bounds how many versions of a "father" we resolve
	// per finding. Popular packages have hundreds of releases; resolving every
	// one is prohibitively slow.
	maxRemediationCandidates = 25
)

// depsDevTarget maps the ecosystem returned by purl.Parse (uppercase, e.g.
// "NPM") to the deps.dev REST path segment and the matching semver system used
// for version comparison. ok is false for ecosystems deps.dev does not resolve.
func depsDevTarget(purlSystem string) (path string, sv semver.System, ok bool) {
	switch strings.ToUpper(purlSystem) {
	case "NPM":
		return "npm", semver.NPM, true
	case "GO":
		return "go", semver.Go, true
	case "MAVEN":
		return "maven", semver.Maven, true
	case "PYPI":
		return "pypi", semver.PyPI, true
	case "CARGO":
		return "cargo", semver.Cargo, true
	case "NUGET":
		return "nuget", semver.NuGet, true
	case "RUBYGEMS":
		return "rubygems", semver.RubyGems, true
	}
	return "", 0, false
}

// annotateRemediations fills in Vulnerability.Remediation for transitive
// findings by asking deps.dev which version of the nearest direct dependency
// ("father") stops pulling the vulnerable release, cross-checked against OSV.
// It is a networked stage; set WOLFEE_NO_REMEDIATE=1 to skip it.
func annotateRemediations(ctx context.Context, r *Report, hc *http.Client, log output.Logger) {
	if r == nil || os.Getenv("WOLFEE_NO_REMEDIATE") == "1" {
		return
	}

	// Names and versions must come from PURLs, not dependency-path labels: the
	// labels carry only the bare component name and drop the npm scope
	// (@nuxt/ui -> ui) or Maven group. Map each path label back to its PURL.
	labelPurl := make(map[string]string, len(r.Components))
	for i := range r.Components {
		c := &r.Components[i]
		labelPurl[pkgLabel(c.Name, c.Version)] = c.PURL
	}

	var targets []int
	for i := range r.Components {
		c := &r.Components[i]
		hasVulnPaths := len(c.Vulnerabilities) > 0 && len(c.DependencyPaths) > 0
		if !hasVulnPaths && !c.Toxic.Found {
			continue
		}
		psys, _, _, ok := purl.Parse(c.PURL)
		if !ok {
			continue
		}
		if _, _, supported := depsDevTarget(psys); !supported {
			continue
		}
		targets = append(targets, i)
	}
	if len(targets) == 0 {
		return
	}
	if log != nil {
		log.Step(fmt.Sprintf("Computing upgrade paths via deps.dev for %d transitive component(s)", len(targets)))
	}

	client := newDepsDevClient(hc)
	osv := &osvVersionCache{hc: hc, cache: map[string][]onlinescan.Vulnerability{}}

	sem := make(chan struct{}, remediationConcurrency)
	var wg sync.WaitGroup
	for _, idx := range targets {
		idx := idx
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			remediateComponent(ctx, &r.Components[idx], client, osv, labelPurl)
		}()
	}
	wg.Wait()
}

func remediateComponent(ctx context.Context, c *ComponentReport, client *depsDevClient, osv *osvVersionCache, labelPurl map[string]string) {
	// Vulnerability remediation needs a resolvable "father" from the dep path.
	if len(c.DependencyPaths) > 0 && len(c.DependencyPaths[0]) > 0 {
		if fatherPurl := labelPurl[c.DependencyPaths[0][0]]; fatherPurl != "" {
			for vi := range c.Vulnerabilities {
				v := &c.Vulnerabilities[vi]
				if v.Remediation != nil {
					continue
				}
				if rem := computeRemediation(ctx, client, osv, c, fatherPurl, v); rem != nil {
					v.Remediation = rem
				}
			}
		}
	}

	// Toxic (protestware) packages get an upgrade suggestion too, treated like
	// a vulnerability - independent of the dependency path.
	if c.Toxic.Found && c.Toxic.Remediation == nil {
		if rem := toxicRemediation(ctx, client, c); rem != nil {
			c.Toxic.Remediation = rem
		}
	}
}

// toxicRemediation suggests moving off a flagged release: the latest released
// (non-prerelease) version of the toxic package above the current one. When the
// package is transitive it is an override/pin; when direct, a plain bump.
func toxicRemediation(ctx context.Context, client *depsDevClient, c *ComponentReport) *onlinescan.Remediation {
	sys, name, ver, ok := purl.Parse(c.PURL)
	if !ok || ver == "" {
		return nil
	}
	path, sv, ok := depsDevTarget(sys)
	if !ok {
		return nil
	}
	if _, err := sv.Parse(ver); err != nil {
		return nil
	}
	pkg, err := client.versions(ctx, path, name)
	if err != nil || pkg == nil || len(pkg.Versions) == 0 {
		return nil
	}
	latest := ""
	for _, v := range pkg.Versions {
		vv := v.VersionKey.Version
		if vv == "" || sv.Compare(vv, ver) <= 0 {
			continue
		}
		if pv, err := sv.Parse(vv); err != nil || pv.IsPrerelease() {
			continue
		}
		if latest == "" || sv.Compare(vv, latest) > 0 {
			latest = vv
		}
	}
	if latest == "" {
		return nil
	}
	via := "direct-bump"
	if len(c.DependencyPaths) > 0 {
		via = "override"
	}
	return &onlinescan.Remediation{
		Direct: name, CurrentVersion: ver, FixVersion: latest, Via: via,
		Note: "flagged by toxic-repos; upgrade to a clean release and review",
	}
}

func computeRemediation(ctx context.Context, client *depsDevClient, osv *osvVersionCache, c *ComponentReport, fatherPurl string, v *onlinescan.Vulnerability) *onlinescan.Remediation {
	fSys, fatherName, fatherVer, ok := purl.Parse(fatherPurl)
	if !ok || fatherVer == "" {
		return nil
	}
	path, sv, ok := depsDevTarget(fSys)
	if !ok {
		return nil
	}
	// A parseable current version is required to order candidates safely and
	// avoid ever recommending a downgrade.
	if _, err := sv.Parse(fatherVer); err != nil {
		return nil
	}

	// The vulnerable package's own name/version come from its PURL too.
	childName, childVer := c.Name, c.Version
	if _, cn, cv, ok := purl.Parse(c.PURL); ok {
		childName, childVer = cn, cv
	}
	if strings.EqualFold(fatherName, childName) {
		return nil // finding is on the direct dep itself; its own Fixed applies
	}

	pkg, err := client.versions(ctx, path, fatherName)
	if err != nil || pkg == nil || len(pkg.Versions) == 0 {
		return nil
	}

	// Candidates: released (non-prerelease) versions strictly newer than the
	// current one, ordered ascending so the first fix found is the smallest bump.
	var cands []string
	for _, ver := range pkg.Versions {
		vv := ver.VersionKey.Version
		if vv == "" || sv.Compare(vv, fatherVer) <= 0 {
			continue
		}
		if pv, err := sv.Parse(vv); err != nil || pv.IsPrerelease() {
			continue
		}
		cands = append(cands, vv)
	}
	if len(cands) == 0 {
		return overrideRemediation(childName, childVer, fatherName, v)
	}
	sort.Slice(cands, func(i, j int) bool { return sv.Compare(cands[i], cands[j]) < 0 })

	latest := cands[len(cands)-1]
	// Test the smallest bumps first (up to the cap); if none in that window fix
	// it, fall back to the latest so a fix that only landed recently is still
	// reported rather than falsely concluding "no version helps".
	checked := 0
	for _, cand := range cands {
		if checked >= maxRemediationCandidates {
			break
		}
		checked++
		if rem := tryFatherVersion(ctx, client, osv, path, fatherName, fatherVer, cand, c, childName, childVer, v); rem != nil {
			return rem
		}
	}
	if checked >= maxRemediationCandidates && latest != cands[checked-1] {
		if rem := tryFatherVersion(ctx, client, osv, path, fatherName, fatherVer, latest, c, childName, childVer, v); rem != nil {
			rem.Note = "smallest bump not searched exhaustively; a lower version may also fix it"
			return rem
		}
	}

	return overrideRemediation(childName, childVer, fatherName, v)
}

// tryFatherVersion resolves father@cand and reports a remediation if it drops
// the vulnerable release (either removing the package or resolving it to a
// version OSV no longer flags for this advisory).
func tryFatherVersion(ctx context.Context, client *depsDevClient, osv *osvVersionCache, path, fatherName, fatherVer, cand string, c *ComponentReport, childName, childVer string, v *onlinescan.Vulnerability) *onlinescan.Remediation {
	deps, err := client.dependencies(ctx, path, fatherName, cand)
	if err != nil || deps == nil {
		return nil
	}
	resolved, present := findChildVersion(deps, childName)
	if !present {
		return &onlinescan.Remediation{
			Direct: fatherName, CurrentVersion: fatherVer,
			FixVersion: cand, ChildFixed: "(removed)", Via: "parent-bump",
		}
	}
	if resolved == "" || resolved == childVer {
		return nil // resolves to the same (vulnerable) version
	}
	vulns, err := osv.query(ctx, swapPURLVersion(c.PURL, resolved))
	if err != nil || vulnStillPresent(vulns, v) {
		return nil
	}
	return &onlinescan.Remediation{
		Direct: fatherName, CurrentVersion: fatherVer,
		FixVersion: cand, ChildFixed: resolved, Via: "parent-bump",
	}
}

// overrideRemediation is the fallback when no father version drops the vulnerable
// release: pin the package directly (npm overrides / yarn resolutions / go get).
func overrideRemediation(childName, childVer, fatherName string, v *onlinescan.Vulnerability) *onlinescan.Remediation {
	fixed := ""
	if len(v.Fixed) > 0 {
		fixed = v.Fixed[0]
	}
	note := fmt.Sprintf("no newer %s release resolves %s to a fixed version", fatherName, childName)
	if fixed == "" {
		note += "; no fixed version published upstream"
	}
	return &onlinescan.Remediation{
		Direct: childName, CurrentVersion: childVer,
		FixVersion: fixed, ChildFixed: fixed, Via: "override", Note: note,
	}
}

func findChildVersion(deps *depsDevDependencies, childName string) (string, bool) {
	for _, n := range deps.Nodes {
		if strings.EqualFold(n.Relation, "SELF") {
			continue
		}
		if strings.EqualFold(n.VersionKey.Name, childName) {
			return n.VersionKey.Version, true
		}
	}
	return "", false
}

// swapPURLVersion replaces the version in a PURL, preserving type/namespace/name
// casing (unlike purlNoVersion, which lowercases). Qualifiers and subpath are
// dropped, which OSV.dev does not need for a version query.
func swapPURLVersion(p, ver string) string {
	base := p
	if i := strings.IndexAny(base, "?#"); i >= 0 {
		base = base[:i]
	}
	if i := strings.LastIndexByte(base, '@'); i >= 0 {
		base = base[:i]
	}
	return base + "@" + ver
}

func vulnStillPresent(vulns []onlinescan.Vulnerability, target *onlinescan.Vulnerability) bool {
	want := map[string]bool{}
	add := func(s string) {
		if s = strings.ToUpper(strings.TrimSpace(s)); s != "" {
			want[s] = true
		}
	}
	add(target.ID)
	add(target.CVE)
	for _, a := range target.Aliases {
		add(a)
	}
	for _, vv := range vulns {
		if want[strings.ToUpper(vv.ID)] || want[strings.ToUpper(vv.CVE)] {
			return true
		}
		for _, a := range vv.Aliases {
			if want[strings.ToUpper(a)] {
				return true
			}
		}
	}
	return false
}

// osvVersionCache memoises OSV.dev lookups by PURL for the duration of a scan.
type osvVersionCache struct {
	hc    *http.Client
	mu    sync.Mutex
	cache map[string][]onlinescan.Vulnerability
}

func (o *osvVersionCache) query(ctx context.Context, p string) ([]onlinescan.Vulnerability, error) {
	o.mu.Lock()
	if v, ok := o.cache[p]; ok {
		o.mu.Unlock()
		return v, nil
	}
	o.mu.Unlock()

	vulns, err := onlinescan.QueryPURLVulns(ctx, o.hc, p)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.cache[p] = vulns
	o.mu.Unlock()
	return vulns, nil
}
