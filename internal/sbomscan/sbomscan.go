package sbomscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/output"
	"sca-go/cli/internal/reachability"
	"sca-go/cli/internal/sbomscan/internal/purl"
)

type Options struct {
	BOMBytes    []byte
	Source      string
	Concurrency int
	Logger      output.Logger

	OS *ReportOS

	LayerResolver LayerResolver

	ExtraPackages []ExtraPackage

	TrivyDBSkip bool

	TrivyDBMirror string

	Reachability *reachability.Result
}

type ExtraPackage struct {
	PURL        string
	System      string
	Name        string
	Source      string
	Version     string
	LayerDigest string
	CreatedBy   string
}

type LayerResolver interface {
	Lookup(path string) string
	CreatedBy(diffID string) string
}

func ScanBOM(ctx context.Context, o Options) (*Report, error) {
	if len(o.BOMBytes) == 0 {
		return nil, errors.New("sbomscan: empty BOM input")
	}
	var doc cdxBOM
	if err := json.Unmarshal(o.BOMBytes, &doc); err != nil {
		return nil, fmt.Errorf("sbomscan: parse cyclonedx: %w", err)
	}

	r := &Report{
		Generator:    "wolfee-cli",
		Source:       o.Source,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		OS:           o.OS,
		Document:     buildDocument(&doc),
		Dependencies: buildDependencies(doc.Dependencies),
		Annotations:  buildAnnotations(doc.Annotations),
	}

	if len(o.ExtraPackages) > 0 {
		extra := make([]cdxComponent, 0, len(o.ExtraPackages))
		for _, p := range o.ExtraPackages {
			props := []cdxProperty{
				{Name: "wolfee:layer:diffid", Value: p.LayerDigest},
				{Name: "wolfee:layer:createdBy", Value: p.CreatedBy},
			}

			if p.Source != "" && p.Source != p.Name {
				props = append(props, cdxProperty{Name: "wolfee:pkg:source", Value: p.Source})
			}
			extra = append(extra, cdxComponent{
				Name:    p.Name,
				Version: p.Version,
				Purl:    p.PURL,

				Scope:      "required",
				Properties: props,
			})
		}
		doc.Components = append(extra, doc.Components...)
	}
	if len(doc.Components) == 0 {
		return r, nil
	}

	type key struct{ sys, name, ver, pur string }
	groups := map[key][]int{}
	parsed := make([]parsedComp, len(doc.Components))
	skipped := 0
	var skipExamples []string
	for i, c := range doc.Components {
		sys, purlName, ver, ok := purl.Parse(c.Purl)
		if !ok || sys == "" {
			skipped++

			if o.Logger != nil {
				reason := "unparseable purl"
				if c.Purl == "" {
					reason = "empty purl"
				} else if sys == "" {
					reason = "no ecosystem in purl"
				}
				o.Logger.Debug("sbomscan: skipped %q (%s) - purl=%q", strings.TrimSpace(c.Name), reason, truncate(c.Purl, 120))
			}
			if len(skipExamples) < 5 {
				ex := strings.TrimSpace(c.Name)
				if ex == "" {
					ex = truncate(c.Purl, 60)
				}
				if ex == "" {
					ex = "<no name, no purl>"
				}
				skipExamples = append(skipExamples, ex)
			}
			parsed[i] = parsedComp{raw: c, skip: true}
			continue
		}

		displayName := strings.TrimSpace(c.Name)
		if displayName == "" {
			displayName = purlName
		}
		if ver == "" {
			ver = c.Version
		}
		meta := extractComponentMeta(c, o.LayerResolver)
		if meta.layerCreatedBy == "" && meta.layerDigest != "" && o.LayerResolver != nil {
			meta.layerCreatedBy = o.LayerResolver.CreatedBy(meta.layerDigest)
		}

		scope := c.Scope
		if scope == "" {
			for _, prop := range c.Properties {
				switch strings.ToLower(prop.Name) {
				case "cdx:go:indirect":
					if strings.EqualFold(strings.TrimSpace(prop.Value), "true") {
						scope = "optional"
					}
				}
			}
		}

		var source string
		if displayName != purlName && isOSEcosystem(sys) {
			source = purlName
		}

		for _, prop := range c.Properties {
			if prop.Name == "wolfee:pkg:source" && strings.TrimSpace(prop.Value) != "" {
				source = strings.TrimSpace(prop.Value)
				break
			}
		}
		parsed[i] = parsedComp{
			raw:                c,
			sys:                sys,
			name:               displayName,
			source:             source,
			ver:                ver,
			layer:              meta.layerDigest,
			createdBy:          meta.layerCreatedBy,
			class:              meta.class,
			pkgType:            meta.pkgType,
			target:             meta.target,
			introducedBy:       meta.introducedBy,
			occurrences:        meta.occurrences,
			hashes:             toReportHashes(c.Hashes),
			licenses:           toReportLicenses(c.Licenses),
			evidenceIdentities: parseEvidenceIdentity(c.Evidence),
			properties:         toReportProperties(c.Properties),
			scope:              scope,
		}

		k := key{sys, purlName, ver, c.Purl}
		groups[k] = append(groups[k], i)
	}

	uniques := make([]onlinescan.Component, 0, len(groups))
	uniqIdx := make(map[key]int, len(groups))
	for k, idxs := range groups {
		uniqIdx[k] = len(uniques)
		layer, createdBy := "", ""
		var source string

		seenBin := map[string]struct{}{}
		var binaryNames []string
		for _, i := range idxs {
			if parsed[i].source != "" && source == "" {
				source = parsed[i].source
			}
			if parsed[i].layer != "" && layer == "" {
				layer = parsed[i].layer
				createdBy = parsed[i].createdBy
			}
			if dn := strings.TrimSpace(parsed[i].raw.Name); dn != "" && dn != k.name {
				if _, dup := seenBin[dn]; !dup {
					seenBin[dn] = struct{}{}
					binaryNames = append(binaryNames, dn)
				}
			}
		}
		uniques = append(uniques, onlinescan.Component{
			System: k.sys, Name: k.name, Source: source, Version: k.ver, PURL: k.pur,
			LayerDigest: layer,
			CreatedBy:   createdBy,
			BinaryNames: binaryNames,
		})
	}

	scanRes, err := onlinescan.Scan(ctx, uniques, onlinescan.Options{
		Concurrency:   o.Concurrency,
		Logger:        o.Logger,
		OS:            reportOSToOnlineOS(o.OS),
		TrivyDBSkip:   o.TrivyDBSkip,
		TrivyDBMirror: o.TrivyDBMirror,
	})
	if err != nil {
		return nil, fmt.Errorf("online scan: %w", err)
	}

	r.Totals.Components = len(parsed)
	r.Totals.Skipped = skipped
	if skipped > 0 && o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("Skipped %d component(s) with unparseable PURL (e.g. %s)", skipped, strings.Join(skipExamples, ", ")))
	}

	for k, idxs := range groups {
		res := scanRes[uniqIdx[k]]
		for _, i := range idxs {
			pc := parsed[i]

			layer := pc.layer
			createdBy := pc.createdBy
			if layer == "" {
				layer = res.LayerDigest
				createdBy = res.LayerCreatedBy
			}
			cr := ComponentReport{
				BOMRef:             pc.raw.BOMRef,
				PURL:               pc.raw.Purl,
				System:             pc.sys,
				Group:              pc.raw.Group,
				Name:               pc.name,
				Version:            pc.ver,
				Scope:              pc.scope,
				Target:             pc.target,
				Class:              pc.class,
				Type:               pc.pkgType,
				IntroducedBy:       pc.introducedBy,
				LayerDigest:        layer,
				LayerCreatedBy:     createdBy,
				Hashes:             pc.hashes,
				Licenses:           pc.licenses,
				Occurrences:        pc.occurrences,
				EvidenceIdentities: pc.evidenceIdentities,
				Properties:         pc.properties,
				Vulnerabilities:    res.Vulnerabilities,
				Malware:            res.Malware,
				Toxic:              res.Toxic,
				Error:              res.Error,
			}
			if cr.Target == "" {
				cr.Target = o.Source
			}
			if cr.Class == "" {
				cr.Class = inferClass(cr.System)
			}
			if cr.Type == "" {
				cr.Type = strings.ToLower(cr.System)
			}
			cr.TopSeverity, cr.VulnCount = topAndCount(res.Vulnerabilities)
			applyReachability(&cr, o.Reachability)
			cr.Vulnerabilities = dedupeVulns(cr.Vulnerabilities)
			cr.TopSeverity, cr.VulnCount = topAndCount(cr.Vulnerabilities)
			r.Components = append(r.Components, cr)
		}
	}

	injectGovulncheckFindings(&r.Components, o.Reachability)
	backfillSyntheticSeverities(ctx, &r.Components, o)
	filterVulnsByVersion(r.Components)

	annotateDependencyPaths(r)
	annotateRemediations(ctx, r, onlinescan.DefaultHTTPClient(), o.Logger)

	seenCVE := map[string]struct{}{}
	for _, c := range r.Components {
		if strings.ToLower(c.Scope) == "required" {
			r.Totals.Direct++
		} else {
			r.Totals.Transitive++
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
		if o.Reachability != nil {
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

			if o.Reachability != nil {
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
		r.Totals.Scanned++
	}

	return r, nil
}

func reportOSToOnlineOS(o *ReportOS) *onlinescan.ImageOS {
	if o == nil {
		return nil
	}
	if o.Family == "" && o.Version == "" && o.Codename == "" && o.Name == "" {
		return nil
	}
	return &onlinescan.ImageOS{
		Family:   o.Family,
		Name:     o.Name,
		Version:  o.Version,
		Codename: o.Codename,
		Arch:     o.Arch,
	}
}
