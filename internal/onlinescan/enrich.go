package onlinescan

import (
	"context"
	"fmt"
	"time"

	"sca-go/cli/internal/onlinescan/feedcache"
)

func Enrich(ctx context.Context, results []*ComponentResult, o Options) error {
	if o.HTTPClient == nil {
		o.HTTPClient = defaultHTTPClient()
	}
	if o.FeedSource == nil {
		feedHTTP := *o.HTTPClient
		feedHTTP.Timeout = 5 * time.Minute
		o.FeedSource = feedcache.NewDefault(&feedHTTP)
	}

	normaliseCVEFields(results)
	cves := uniqueCVEs(results)

	kev := newKEVSet()
	if len(cves) > 0 {
		if o.Logger != nil {
			o.Logger.Step("Fetching CISA KEV catalogue")
		}
		if err := kev.Load(ctx, o.FeedSource); err != nil && o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("kev unavailable: %v", err))
		}
	}

	var epssMap map[string]epssScore
	if len(cves) > 0 {
		if o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("Fetching EPSS scores for %d CVEs", len(cves)))
		}
		var err error
		epssMap, err = fetchEPSS(ctx, o.HTTPClient, cves)
		if err != nil && o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("epss: %v", err))
		}
		if o.Logger != nil && (err == nil || len(epssMap) > 0) {
			o.Logger.Step(fmt.Sprintf("EPSS matched %d/%d CVEs", len(epssMap), len(cves)))
		}
	}

	pocs := newPoCFetcher()
	pocs.Prefetch(ctx, o.HTTPClient, cves, o.Logger)

	ossf := newOSSFIndex()
	if o.Logger != nil {
		o.Logger.Step("Fetching ossf/malicious-packages index")
	}
	if err := ossf.Load(ctx, o.HTTPClient); err != nil && o.Logger != nil {
		if ossf.loaded {
			o.Logger.Step(fmt.Sprintf("ossf %v (index still usable)", err))
		} else {
			o.Logger.Step(fmt.Sprintf("ossf unavailable: %v", err))
		}
	}

	trep := newToxicReposIndex()
	if o.Logger != nil {
		o.Logger.Step("Fetching toxic-repos/toxic-repos feed")
	}
	if err := trep.Load(ctx, o.HTTPClient); err != nil && o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("toxic-repos unavailable: %v", err))
	}

	if o.Logger != nil {
		o.Logger.Step("Applying enrichments (KEV / EPSS / PoC / OSSF / toxic)")
	}
	for _, r := range results {
		for vi := range r.Vulnerabilities {
			cve := canonicalCVE(r.Vulnerabilities[vi].CVE)
			if cve == "" {
				continue
			}
			r.Vulnerabilities[vi].InKEV = kev.Has(cve)
			if e, ok := epssMap[cve]; ok {
				r.Vulnerabilities[vi].EPSS = e.EPSS
				r.Vulnerabilities[vi].EPSSPercentile = e.Percentile
			}
			r.Vulnerabilities[vi].PoCs = pocs.Lookup(ctx, o.HTTPClient, cve, 3)
		}
		r.Toxic = toxicReposToToxic(trep.Lookup(r.PURL, r.Name))
		if hits := ossf.Lookup(r.System, r.Name); len(hits) > 0 {
			if !r.Malware.Found {
				r.Malware = Malware{
					Found:     true,
					ID:        hits[0].MalID,
					Summary:   "package listed in ossf/malicious-packages",
					Reference: ossf.rawURL(hits[0].Path),
					Sources:   []string{"OSSF"},
				}
			} else if !containsStr(r.Malware.Sources, "OSSF") {
				r.Malware.Sources = append(r.Malware.Sources, "OSSF")
			}
			for _, h := range hits {
				r.Malware.MalIDs = appendUnique(r.Malware.MalIDs, h.MalID)
			}
		}
	}

	normaliseSeverities(results)
	return nil
}
