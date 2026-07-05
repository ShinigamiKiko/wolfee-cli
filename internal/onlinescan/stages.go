package onlinescan

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

func stageOSV(ctx context.Context, hc *http.Client, results []*ComponentResult, concurrency int, log ProgressLogger, skipDistro bool) {
	if concurrency > len(results) {
		concurrency = len(results)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var doneMu sync.Mutex
	done := 0

	total := 0
	for _, r := range results {
		if skipDistro && isDebianEcosystem(r.System) {
			continue
		}
		total++
	}

	for i := range results {
		i := i
		if skipDistro && isDebianEcosystem(results[i].System) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if results[i].PURL != "" {
				vulns, mal, err := queryOSV(ctx, hc, results[i].PURL)
				if err != nil {
					results[i].Error = err.Error()
				} else {
					results[i].Vulnerabilities = vulns
					results[i].Malware = mal
				}
			}

			doneMu.Lock()
			done++
			cur := done
			doneMu.Unlock()
			if log != nil {
				log.Progress(cur, total,
					fmt.Sprintf("%s/%s@%s", results[i].System, results[i].Name, results[i].Version))
			}
		}()
	}
	wg.Wait()
}

func stageOSVDistroFallback(ctx context.Context, hc *http.Client, results []*ComponentResult, concurrency int, log ProgressLogger, mergeOnly bool) {
	if concurrency > len(results) {
		concurrency = len(results)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	var targets []int
	for i, r := range results {
		if !isDebianEcosystem(r.System) || r.PURL == "" {
			continue
		}
		targets = append(targets, i)
	}
	if len(targets) == 0 {
		return
	}
	noData := 0
	for _, i := range targets {
		if len(results[i].Vulnerabilities) == 0 {
			noData++
		}
	}
	if log != nil {
		log.Step(fmt.Sprintf("Supplementing Debian tracker with OSV.dev for %d components (%d without tracker data)", len(targets), noData))
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var doneMu sync.Mutex
	done := 0
	for _, i := range targets {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			name := results[i].Name
			debugLog(log, name, "osv-fallback: querying PURL=%s (existing=%d vulns)", results[i].PURL, len(results[i].Vulnerabilities))
			vulns, mal, err := queryOSV(ctx, hc, results[i].PURL)
			if err != nil {
				debugLog(log, name, "osv-fallback: query error: %v", err)
				if len(results[i].Vulnerabilities) == 0 {
					results[i].Error = err.Error()
				}
			} else {
				debugLog(log, name, "osv-fallback: OSV returned %d vulns", len(vulns))
				existing := results[i].Vulnerabilities
				if len(existing) == 0 {

					results[i].Vulnerabilities = vulns
					results[i].Malware = mal
				} else {

					seenIdx := make(map[string]int, len(existing)*2)
					for idx, v := range existing {
						if v.CVE != "" {
							seenIdx[v.CVE] = idx
						}
						if v.ID != "" {
							seenIdx[v.ID] = idx
						}
					}
					for _, v := range vulns {

						mergedDistro := false
						for _, ck := range []string{v.CVE, v.ID} {
							if ck == "" {
								continue
							}
							if existIdx, dup := seenIdx[ck]; dup {
								debugLog(log, name, "osv-fallback: merging DistroStatus for existing %s: OSV=%v", ck, v.DistroStatus)
								existing[existIdx].DistroStatus = mergeDistroStatus(
									existing[existIdx].DistroStatus,
									v.DistroStatus,
								)
								mergedDistro = true
								break
							}
						}
						key := v.CVE
						if key == "" {
							key = v.ID
						}
						if mergedDistro {
							continue
						}
						if mergeOnly {

							debugLog(log, name, "osv-fallback: skipping new CVE %s (mergeOnly=true)", key)
							continue
						}

						if key != "" {
							if v.CVE != "" {
								seenIdx[v.CVE] = len(existing)
							}
							if v.ID != "" {
								seenIdx[v.ID] = len(existing)
							}
						}
						debugLog(log, name, "osv-fallback: adding new CVE %s", key)
						existing = append(existing, v)
					}
					results[i].Vulnerabilities = existing
				}
			}

			doneMu.Lock()
			done++
			cur := done
			doneMu.Unlock()
			if log != nil {
				log.Progress(cur, len(targets),
					fmt.Sprintf("%s/%s@%s", results[i].System, results[i].Name, results[i].Version))
			}
		}()
	}
	wg.Wait()
}
