package sbomscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/output"
	"sca-go/cli/internal/reachability"
	"sca-go/cli/internal/trivy"
)

type ImageOptions struct {
	Image       string
	Platform    string
	Source      string
	Concurrency int
	Logger      output.Logger

	TrivyBin string

	TrivyExtraArgs []string

	SaveSBOM string

	Scout bool

	Reachability *reachability.Result

	SourceLibs map[string]bool

	SourceScope map[string]string
}

func ScanImage(ctx context.Context, o ImageOptions) (*Report, error) {
	if o.Logger != nil {
		if o.Platform == "" {
			o.Logger.Step(fmt.Sprintf("Scanning image %s with trivy", o.Image))
		} else {
			o.Logger.Step(fmt.Sprintf("Scanning image %s (platform=%s) with trivy", o.Image, o.Platform))
		}
	}
	tr, err := trivy.Scan(ctx, trivy.Options{
		Image:     o.Image,
		Platform:  o.Platform,
		Bin:       o.TrivyBin,
		ExtraArgs: o.TrivyExtraArgs,
		SaveSBOM:  o.SaveSBOM,
		Logger:    o.Logger,
	})
	if err != nil {
		return nil, err
	}

	results, ros := adaptTrivy(tr)
	if o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("Trivy reported %d packages", len(results)))
	}

	base := resolveBaseImage(ctx, o, tr)

	if err := onlinescan.Enrich(ctx, results, onlinescan.Options{
		Concurrency: o.Concurrency,
		Logger:      o.Logger,
	}); err != nil {
		return nil, fmt.Errorf("enrich: %w", err)
	}

	return buildImageReport(o.Source, ros, tr, results, base, o.Reachability, o.SourceLibs, o.SourceScope), nil
}

func adaptTrivy(tr *trivy.Report) ([]*onlinescan.ComponentResult, *ReportOS) {
	var ros *ReportOS
	if tr.Metadata.OS != nil {
		ros = &ReportOS{
			Family:  tr.Metadata.OS.Family,
			Name:    tr.Metadata.OS.Name,
			Version: tr.Metadata.OS.Name,
		}
	}

	var results []*onlinescan.ComponentResult
	byKey := map[string]*onlinescan.ComponentResult{}

	pkgKey := func(purl, name, version string) string {
		if purl != "" {
			return purl
		}
		return name + "@" + version
	}

	for _, res := range tr.Results {
		for _, p := range res.Packages {
			k := pkgKey(p.Identifier.PURL, p.Name, p.Version)
			if _, dup := byKey[k]; dup {
				continue
			}
			cr := &onlinescan.ComponentResult{
				Component: onlinescan.Component{
					System:  purlType(p.Identifier.PURL),
					Name:    p.Name,
					Source:  p.SrcName,
					Version: p.Version,
					PURL:    p.Identifier.PURL,
				},
				LayerDigest: p.Layer.DiffID,
			}
			byKey[k] = cr
			results = append(results, cr)
		}

		for _, v := range res.Vulnerabilities {
			k := pkgKey(v.PkgIdentifier.PURL, v.PkgName, v.InstalledVersion)
			cr := byKey[k]
			if cr == nil {
				cr = &onlinescan.ComponentResult{
					Component: onlinescan.Component{
						System:  purlType(v.PkgIdentifier.PURL),
						Name:    v.PkgName,
						Version: v.InstalledVersion,
						PURL:    v.PkgIdentifier.PURL,
					},
					LayerDigest: v.Layer.DiffID,
				}
				byKey[k] = cr
				results = append(results, cr)
			}
			cr.Vulnerabilities = append(cr.Vulnerabilities, convertVuln(v))
		}
	}
	return results, ros
}

func convertVuln(v trivy.Vulnerability) onlinescan.Vulnerability {
	score, vector := pickCVSS(v.CVSS)
	var fixed []string
	if v.FixedVersion != "" {
		fixed = []string{v.FixedVersion}
	}
	cve := ""
	if strings.HasPrefix(strings.ToUpper(v.VulnerabilityID), "CVE-") {
		cve = strings.ToUpper(v.VulnerabilityID)
	}
	return onlinescan.Vulnerability{
		ID:             v.VulnerabilityID,
		CVE:            cve,
		Title:          v.Title,
		Description:    v.Description,
		Summary:        v.Title,
		Severity:       strings.ToUpper(strings.TrimSpace(v.Severity)),
		CVSS:           score,
		CVSSVector:     vector,
		Published:      v.PublishedDate,
		Modified:       v.LastModifiedDate,
		Fixed:          fixed,
		Reference:      v.PrimaryURL,
		SeveritySource: "trivy",
		Status:         v.Status,
	}
}

func pickCVSS(m map[string]trivy.CVSS) (float64, string) {
	if len(m) == 0 {
		return 0, ""
	}
	pick := func(c trivy.CVSS) (float64, string) {
		if c.V3Score > 0 || c.V3Vector != "" {
			return c.V3Score, c.V3Vector
		}
		return c.V2Score, c.V2Vector
	}
	if c, ok := m["nvd"]; ok {
		return pick(c)
	}
	for _, c := range m {
		return pick(c)
	}
	return 0, ""
}

func purlType(p string) string {
	p = strings.TrimPrefix(p, "pkg:")
	if i := strings.IndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return ""
}

func buildImageReport(source string, ros *ReportOS, tr *trivy.Report, results []*onlinescan.ComponentResult, base baseAttribution, reach *reachability.Result, sourceLibs map[string]bool, sourceScope map[string]string) *Report {
	r := &Report{
		Generator:   "wolfee-cli",
		Source:      source,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		OS:          ros,
	}

	createdBy := tr.Metadata.LayerCreatedBy()

	var target, class, typ string
	for _, res := range tr.Results {
		if len(res.Packages) > 0 || len(res.Vulnerabilities) > 0 {
			target, class, typ = res.Target, res.Class, res.Type
			break
		}
	}
	if target == "" {
		target = source
	}

	for _, res := range results {
		vulns := dedupeVulns(res.Vulnerabilities)
		topSev, vc := topAndCount(vulns)
		cr := ComponentReport{
			PURL:            res.PURL,
			System:          res.System,
			Name:            res.Name,
			Version:         res.Version,
			Target:          target,
			Class:           class,
			Type:            typ,
			LayerDigest:     res.LayerDigest,
			LayerCreatedBy:  createdBy[res.LayerDigest],
			Origin:          base.classify(res.LayerDigest),
			Vulnerabilities: vulns,
			Malware:         res.Malware,
			Toxic:           res.Toxic,
			TopSeverity:     topSev,
			VulnCount:       vc,
		}
		if cr.Class == "" {
			cr.Class = inferClass(cr.System)
		}
		if cr.Type == "" {
			cr.Type = strings.ToLower(cr.System)
		}

		if sourceLibs != nil {
			if fromSource(&cr, sourceLibs, reach) {
				cr.Origin = OriginApp

				if sourceScope != nil {
					cr.Scope = sourceScope[strings.ToLower(purlNoVersion(cr.PURL))]
				}
			} else {
				cr.Origin = OriginImage
			}
		}

		applyReachability(&cr, reach)
		r.Components = append(r.Components, cr)
	}
	markImageLibs(r.Components)
	filterVulnsByVersion(r.Components)
	computeImageTotals(r, reach, sourceLibs != nil)
	return r
}

// markImageLibs distinguishes language libraries that ship in the image from OS
// packages: a non-OS component tagged OriginImage becomes OriginImageLib, while
// OS packages keep OriginImage. The table renders both the same (LIB(image) vs
// DEB/APK(image)); this only sharpens the JSON origin.
func markImageLibs(components []ComponentReport) {
	for i := range components {
		c := &components[i]
		if c.Origin == OriginImage && componentLanguage(c.System, c.PURL) != "os" {
			c.Origin = OriginImageLib
		}
	}
}

func computeImageTotals(r *Report, reach *reachability.Result, compareMode bool) {
	r.Totals = Totals{}
	seenCVE := map[string]struct{}{}
	for i := range r.Components {
		c := &r.Components[i]
		isApp := c.Origin == OriginApp
		r.Totals.Scanned++
		switch {
		case !compareMode:
			r.Totals.Direct++
		case isApp && strings.EqualFold(c.Scope, "optional"):
			r.Totals.Transitive++
		case isApp:
			r.Totals.Direct++
		}
		if c.VulnCount > 0 {
			r.Totals.WithVulns++
		}
		if c.Malware.Found {
			r.Totals.Malware++
		}
		if c.Toxic.Found {
			r.Totals.Toxic++
		}
		if reach != nil {
			switch c.PackageUsage {
			case "used", "used-transitive":
				r.Totals.PackageUsed++
			case "unused":
				r.Totals.PackageUnused++
			}
		}
		for _, v := range c.Vulnerabilities {
			dedupeKey := v.CVE
			if dedupeKey == "" {
				dedupeKey = v.ID
			}
			if dedupeKey != "" {
				if _, dup := seenCVE[dedupeKey]; dup {
					continue
				}
				seenCVE[dedupeKey] = struct{}{}
			}

			if reach != nil {
				switch v.Reachable {
				case string(reachability.StateReachable):
					r.Totals.Reachable++
				case string(reachability.StateUnreachable):
					r.Totals.Unreachable++
				default:
					r.Totals.ReachUnknown++
				}
			}
			switch strings.ToUpper(v.Severity) {
			case onlinescan.SevCritical:
				r.Totals.CRITICAL++
			case onlinescan.SevHigh:
				r.Totals.HIGH++
			case onlinescan.SevMedium:
				r.Totals.MEDIUM++
			case onlinescan.SevLow:
				r.Totals.LOW++
			default:
				r.Totals.UNKNOWN++
			}
			if v.InKEV {
				r.Totals.KEV++
			}
			if len(v.PoCs) > 0 {
				r.Totals.PoC++
			}
		}
	}
	r.Totals.Components = len(r.Components)
}
