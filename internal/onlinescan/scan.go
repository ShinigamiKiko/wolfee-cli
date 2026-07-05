package onlinescan

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sca-go/cli/internal/onlinescan/feedcache"
	"sca-go/cli/internal/trivydb"
)

type Component struct {
	System      string
	Name        string
	Source      string
	Version     string
	PURL        string
	LayerDigest string
	CreatedBy   string

	BinaryNames []string
}

type ComponentResult struct {
	Component
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Malware         Malware         `json:"malware"`
	Toxic           Toxic           `json:"toxic"`

	LayerDigest string `json:"layerDigest,omitempty"`

	LayerCreatedBy string `json:"layerCreatedBy,omitempty"`
	Error          string `json:"error,omitempty"`
}

type Options struct {
	Concurrency int
	HTTPClient  *http.Client
	Logger      ProgressLogger

	OS *ImageOS

	FeedSource feedcache.Source

	TrivyDBSkip bool

	TrivyDBMirror string
}

type ImageOS struct {
	Family   string
	Name     string
	Version  string
	Codename string
	Arch     string
}

type ProgressLogger interface {
	Step(msg string)
	Progress(done, total int, label string)
}

func Scan(ctx context.Context, comps []Component, o Options) ([]*ComponentResult, error) {
	if o.HTTPClient == nil {
		o.HTTPClient = defaultHTTPClient()
	}
	if o.FeedSource == nil {

		feedHTTP := *o.HTTPClient
		feedHTTP.Timeout = 5 * time.Minute
		o.FeedSource = feedcache.NewDefault(&feedHTTP)
	}
	concurrency := o.Concurrency
	if concurrency <= 0 {
		concurrency = 16
	}

	results := make([]*ComponentResult, len(comps))
	for i, c := range comps {
		results[i] = &ComponentResult{
			Component:      c,
			LayerDigest:    c.LayerDigest,
			LayerCreatedBy: c.CreatedBy,
		}
	}

	var tdb *trivydb.Reader
	hasDebianComps := anyDebianComponent(results)
	if o.Logger != nil {
		osStr := "<none>"
		if o.OS != nil {
			osStr = fmt.Sprintf("%s %s (%s)", o.OS.Family, o.OS.Version, o.OS.Codename)
		}
		o.Logger.Step(fmt.Sprintf("Trivy DB stage: skip=%v hasDebianComps=%v OS=%s",
			o.TrivyDBSkip, hasDebianComps, osStr))
	}
	if !o.TrivyDBSkip && hasDebianComps && o.OS != nil {

		osVersion := o.OS.Version
		if fam := strings.ToLower(o.OS.Family); fam != "" {
			if alias := distroReleaseAliases[fam][strings.ToLower(osVersion)]; alias != "" &&
				len(alias) > 0 && alias[0] >= '0' && alias[0] <= '9' {
				osVersion = alias
			}
		}
		platform := platformString(o.OS.Family, osVersion)

		if age := trivydb.DBAge(""); !age.IsZero() {
			if o.Logger != nil {
				o.Logger.Step(fmt.Sprintf("Trivy DB: cache age %s (fetched %s)",
					time.Since(age).Round(time.Minute), age.UTC().Format("2006-01-02 15:04 UTC")))
			}
		} else if o.Logger != nil {
			o.Logger.Step("Trivy DB: no local cache - will download")
		}
		if o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("Fetching Trivy DB (platform=%s)", platform))
		}
		dbPath, wasDownloaded, dbErr := trivydb.EnsureDB(ctx, o.HTTPClient, "", o.TrivyDBMirror)
		if dbErr != nil {
			if o.Logger != nil {
				o.Logger.Step(fmt.Sprintf("trivy-db unavailable, falling back to tracker: %v", dbErr))
			}
		} else {
			if o.Logger != nil {
				if wasDownloaded {
					o.Logger.Step("Trivy DB: downloaded fresh copy from ghcr.io/aquasecurity/trivy-db:2")
				} else {
					o.Logger.Step("Trivy DB: using cached copy (within 6h TTL)")
				}
			}
			r, openErr := trivydb.Open(dbPath)
			if openErr != nil {
				if o.Logger != nil {
					o.Logger.Step(fmt.Sprintf("trivy-db open failed: %v", openErr))
				}
			} else {
				tdb = r
				defer tdb.Close()
				if o.Logger != nil {
					if platforms, plErr := tdb.ListPlatforms(); plErr == nil {
						o.Logger.Step(fmt.Sprintf("Trivy DB platforms available: %v", platforms))
					}
				}
				processed, added, withHits := stageTrivyDB(results, tdb, platform, o.OS.Family, osVersion, o.OS.Codename, o.OS.Arch, o.Logger)
				if o.Logger != nil {
					o.Logger.Step(fmt.Sprintf("Trivy DB: processed=%d added=%d components_with_hits=%d (platform=%s)",
						processed, added, withHits, platform))
				}
			}
		}
	}

	var deb *debianIndex
	var dla *dlaIndex
	debianPresent := anyDebianComponent(results)
	if debianPresent {
		deb = newDebianIndex()
		if o.Logger != nil {
			o.Logger.Step("Fetching Debian security tracker (primary source for distro packages)")
		}
		if err := deb.Load(ctx, o.HTTPClient); err != nil && o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("debian tracker unavailable, falling back to OSV: %v", err))
		}
	}

	trivyDBLoaded := tdb != nil && tdb.IsLoaded()
	osvSkipDistro := (deb != nil && deb.IsLoaded()) || trivyDBLoaded
	osvCount := len(results)
	if osvSkipDistro {
		osvCount = 0
		for _, r := range results {
			if !isDebianEcosystem(r.System) {
				osvCount++
			}
		}
	}
	if o.Logger != nil {
		if osvSkipDistro {
			o.Logger.Step(fmt.Sprintf("Querying OSV.dev for %d language-ecosystem components", osvCount))
		} else {
			o.Logger.Step(fmt.Sprintf("Querying OSV.dev for %d components", osvCount))
		}
	}
	stageOSV(ctx, o.HTTPClient, results, concurrency, o.Logger, osvSkipDistro)

	if deb != nil {
		applyDebian(results, deb)

		augmentFromDebianTracker(results, deb, o.OS, o.Logger, trivyDBLoaded)

		dla = newDLAIndex()
		if o.Logger != nil {
			o.Logger.Step("Fetching Debian DLA advisory list")
		}
		if err := dla.Load(ctx, o.FeedSource); err != nil && o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("dla list unavailable: %v", err))
		} else if o.Logger != nil {
			pkgs, fixes := dla.Stats()
			o.Logger.Step(fmt.Sprintf("DLA list loaded: %d source packages, %d release-specific fix entries", pkgs, fixes))
		}
	}
	if osvSkipDistro {

		stageOSVDistroFallback(ctx, o.HTTPClient, results, concurrency, o.Logger, trivyDBLoaded)
	}

	if dla != nil && o.OS != nil {
		applyDLAFixes(results, dla, o.OS, o.Logger)
	}

	normaliseCVEFields(results)

	cves := uniqueCVEs(results)

	kev := newKEVSet()
	if len(cves) > 0 {
		if o.Logger != nil {
			o.Logger.Step("Fetching CISA KEV catalogue")
		}
		if err := kev.Load(ctx, o.FeedSource); err != nil {
			if o.Logger != nil {
				o.Logger.Step(fmt.Sprintf("kev unavailable: %v", err))
			}
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
		o.Logger.Step("Applying enrichments (KEV / EPSS / PoC / DLA cross-refs)")
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
			if dla != nil {
				if adv := dla.LookupCVE(cve); len(adv) > 0 {
					r.Vulnerabilities[vi].RelatedAdvisories = mergeStringSet(r.Vulnerabilities[vi].RelatedAdvisories, adv)
				}
			}
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

	applyDistroFiltering(results, o.OS)

	if pending := cvesNeedingNVD(results); len(pending) > 0 {
		if o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("Querying NVD for %d CVEs without severity (capped at %d; raise via WOLFEE_NVD_MAX_LOOKUPS)", len(pending), nvdMaxLookups()))
		}
		applyNVD(results, fetchNVDScores(ctx, o.HTTPClient, pending, o.Logger))
	}

	if dla != nil {
		if o.Logger != nil {
			o.Logger.Step("Expanding DLA / DSA / USN advisory rows via constituent CVEs")
		}
		expandAdvisoryRows(results, dla)
	}

	normaliseSeverities(results)
	deduplicateBySourcePackage(results)

	return results, nil
}
