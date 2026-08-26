package sbomscan

import (
	"sort"
	"strings"

	"deps.dev/util/semver"

	"github.com/shinigamikiko/wolfee-cli/internal/onlinescan"
)

// FixPlan is the actionable view of a report. Groups contain vulnerabilities
// fixed by the same direct dependency upgrade; unresolved keeps findings for
// which no remediation was computed.
type FixPlan struct {
	Groups     []FixPlanGroup   `json:"groups,omitempty"`
	Unresolved []FixPlanPackage `json:"unresolved,omitempty"`
}

type FixPlanGroup struct {
	Direct         string           `json:"direct"`
	CurrentVersion string           `json:"currentVersion,omitempty"`
	FixVersion     string           `json:"fixVersion,omitempty"`
	ChildFixed     string           `json:"childFixed,omitempty"`
	Via            string           `json:"via,omitempty"`
	Note           string           `json:"note,omitempty"`
	Packages       []FixPlanPackage `json:"packages"`
}

type FixPlanPackage struct {
	Package                  string                 `json:"package"`
	PURL                     string                 `json:"purl,omitempty"`
	Vulnerabilities          []FixPlanVulnerability `json:"vulnerabilities"`
	DependencyPaths          [][]string             `json:"dependencyPaths,omitempty"`
	DependencyPathsTruncated bool                   `json:"dependencyPathsTruncated,omitempty"`
}

type FixPlanVulnerability struct {
	ID         string   `json:"id"`
	CVE        string   `json:"cve,omitempty"`
	Severity   string   `json:"severity"`
	FixVersion string   `json:"fixVersion,omitempty"`
	InKEV      bool     `json:"inKev,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
	PoCs       []string `json:"pocs,omitempty"`
}

func BuildFixPlan(r *Report) *FixPlan {
	if r == nil {
		return nil
	}

	plan := &FixPlan{}
	groups := make(map[string]*FixPlanGroup)
	groupPackages := make(map[string]map[string]*FixPlanPackage)
	unresolved := make(map[string]*FixPlanPackage)
	seen := make(map[string]bool)

	for _, c := range r.Components {
		for _, v := range c.Vulnerabilities {
			id := v.ID
			if id == "" {
				id = v.CVE
			}
			if id == "" {
				continue
			}
			vulnKey := c.PURL + "\x00" + id
			rem := v.Remediation
			if rem == nil && len(v.Fixed) > 0 {
				// cdxgen supplies the dependency graph and OSV supplies the known
				// fixed version. Do not parse a package-manager lockfile here.
				rem = &onlinescan.Remediation{
					Direct: c.Name, CurrentVersion: c.Version,
					FixVersion: v.Fixed[0], ChildFixed: v.Fixed[0],
					Via: "osv-fixed", Note: "fixed version from OSV; parent upgrade was not resolved",
				}
			}
			if rem != nil {
				groupKey := strings.Join([]string{rem.Direct, rem.CurrentVersion, rem.Via}, "\x00")
				group := groups[groupKey]
				if group == nil {
					group = &FixPlanGroup{
						Direct: rem.Direct, CurrentVersion: rem.CurrentVersion,
						FixVersion: rem.FixVersion, ChildFixed: rem.ChildFixed,
						Via: rem.Via, Note: rem.Note,
					}
					groups[groupKey] = group
					groupPackages[groupKey] = make(map[string]*FixPlanPackage)
				} else if group.FixVersion != rem.FixVersion {
					group.FixVersion = maxFixVersion(group.FixVersion, rem.FixVersion)
					group.ChildFixed = group.FixVersion
				}
				pkgKey := c.PURL
				if pkgKey == "" {
					pkgKey = c.Name + "\x00" + c.Version
				}
				pkg := groupPackages[groupKey][pkgKey]
				if pkg == nil {
					pkg = &FixPlanPackage{Package: pkgLabel(c.Name, c.Version), PURL: c.PURL,
						DependencyPaths: c.DependencyPaths, DependencyPathsTruncated: c.DependencyPathsTruncated}
					groupPackages[groupKey][pkgKey] = pkg
					group.Packages = append(group.Packages, *pkg)
				}
				mergeFixPlanPaths(pkg, c)
				if !seen[vulnKey+"\x00"+groupKey] {
					seen[vulnKey+"\x00"+groupKey] = true
					pkg.Vulnerabilities = append(pkg.Vulnerabilities, fixPlanVulnerability(v, rem.FixVersion))
				}
				continue
			}

			if seen[vulnKey] {
				continue
			}
			seen[vulnKey] = true
			pkgKey := c.PURL
			if pkgKey == "" {
				pkgKey = c.Name + "\x00" + c.Version
			}
			pkg := unresolved[pkgKey]
			if pkg == nil {
				pkg = &FixPlanPackage{Package: pkgLabel(c.Name, c.Version), PURL: c.PURL,
					DependencyPaths: c.DependencyPaths, DependencyPathsTruncated: c.DependencyPathsTruncated}
				unresolved[pkgKey] = pkg
			}
			mergeFixPlanPaths(pkg, c)
			pkg.Vulnerabilities = append(pkg.Vulnerabilities, fixPlanVulnerability(v, ""))
		}
	}

	for _, group := range groups {
		for i := range group.Packages {
			key := group.Packages[i].PURL
			if key == "" {
				key = group.Packages[i].Package
			}
			if pkg := groupPackages[fixPlanGroupKey(*group)][key]; pkg != nil {
				group.Packages[i] = *pkg
			}
		}
		sortFixPlanPackages(group.Packages)
		plan.Groups = append(plan.Groups, *group)
	}
	for _, pkg := range unresolved {
		if len(pkg.Vulnerabilities) > 0 {
			sortFixPlanVulnerabilities(pkg.Vulnerabilities)
			plan.Unresolved = append(plan.Unresolved, *pkg)
		}
	}

	sort.Slice(plan.Groups, func(i, j int) bool { return plan.Groups[i].Direct < plan.Groups[j].Direct })
	sortFixPlanPackages(plan.Unresolved)
	if len(plan.Groups) == 0 && len(plan.Unresolved) == 0 {
		return nil
	}
	return plan
}

func fixPlanGroupKey(g FixPlanGroup) string {
	return strings.Join([]string{g.Direct, g.CurrentVersion, g.Via}, "\x00")
}

func fixPlanVulnerability(v onlinescan.Vulnerability, fixVersion string) FixPlanVulnerability {
	return FixPlanVulnerability{ID: v.ID, CVE: v.CVE, Severity: v.Severity, FixVersion: fixVersion, InKEV: v.InKEV, EPSS: v.EPSS, PoCs: v.PoCs}
}

func maxFixVersion(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	leftVersion := strings.TrimPrefix(left, "v")
	rightVersion := strings.TrimPrefix(right, "v")
	if _, leftErr := semver.NPM.Parse(leftVersion); leftErr == nil {
		if _, rightErr := semver.NPM.Parse(rightVersion); rightErr == nil && semver.NPM.Compare(rightVersion, leftVersion) > 0 {
			return right
		}
	}
	return left
}

func mergeFixPlanPaths(pkg *FixPlanPackage, c ComponentReport) {
	pkg.DependencyPathsTruncated = pkg.DependencyPathsTruncated || c.DependencyPathsTruncated
	seen := make(map[string]bool, len(pkg.DependencyPaths))
	for _, path := range pkg.DependencyPaths {
		seen[strings.Join(path, "\x00")] = true
	}
	for _, path := range c.DependencyPaths {
		key := strings.Join(path, "\x00")
		if !seen[key] {
			pkg.DependencyPaths = append(pkg.DependencyPaths, path)
			seen[key] = true
		}
	}
}

func sortFixPlanPackages(packages []FixPlanPackage) {
	sort.Slice(packages, func(i, j int) bool { return packages[i].Package < packages[j].Package })
	for i := range packages {
		sortFixPlanVulnerabilities(packages[i].Vulnerabilities)
	}
}

func sortFixPlanVulnerabilities(vulns []FixPlanVulnerability) {
	sort.Slice(vulns, func(i, j int) bool {
		left, right := vulns[i].CVE, vulns[j].CVE
		if left == "" {
			left = vulns[i].ID
		}
		if right == "" {
			right = vulns[j].ID
		}
		return left < right
	})
}
