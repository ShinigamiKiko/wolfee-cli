package onlinescan

import (
	"strings"
)

func augmentFromDebianTracker(results []*ComponentResult, idx *debianIndex, os *ImageOS, log ProgressLogger, mergeOnly bool) {
	if idx == nil {
		return
	}
	for _, r := range results {
		if !isDebianEcosystem(r.System) {
			continue
		}
		src := r.Source
		if src == "" {
			src = r.Name
		}
		records := idx.LookupSource(src)
		if len(records) == 0 {
			debugLog(log, r.Name, "tracker augment: no records for source=%s", src)
			continue
		}
		debugLog(log, r.Name, "tracker augment: %d CVEs in tracker for source=%s", len(records), src)

		seen := map[string]int{}
		for i, v := range r.Vulnerabilities {
			if v.CVE != "" {
				seen[v.CVE] = i + 1
			}
		}
		releases := releasesForImage(r.Component, "debian", os)
		for cve, rec := range records {
			distroRows := debianTrackerToDistroStatus(rec)
			if existing := seen[cve] - 1; existing >= 0 {

				r.Vulnerabilities[existing].DistroStatus = mergeDistroStatus(
					r.Vulnerabilities[existing].DistroStatus,
					distroRows,
				)
				continue
			}

			if mergeOnly {
				debugLog(log, r.Name, "tracker augment: %s skipped (mergeOnly=true; Trivy DB authoritative)", cve)
				continue
			}

			if !trackerHasRelevantRelease(rec, releases) {
				debugLog(log, r.Name, "tracker augment: %s skipped (no relevant release entry for %v)", cve, releases)
				continue
			}
			sev := severityFromTrackerUrgency(rec, releases)
			v := Vulnerability{
				ID:           cve,
				CVE:          cve,
				DistroStatus: distroRows,
				Reference:    "https://security-tracker.debian.org/tracker/" + cve,
			}
			if sev != "" {
				v.Severity = sev
				v.SeveritySource = "debian-tracker"
			}
			debugLog(log, r.Name, "tracker augment: adding new CVE %s sev=%s releases=%v", cve, sev, releases)
			r.Vulnerabilities = append(r.Vulnerabilities, v)
		}
	}
}

func severityFromTrackerUrgency(rec debianCVE, releases map[string]struct{}) string {
	pickUrgency := func() string {

		for rel, info := range rec.Releases {
			r := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rel), "-lts"))
			if _, ok := releases[r]; !ok {
				if alias := distroReleaseAliases["debian"][r]; alias != "" {
					if _, ok := releases[alias]; !ok {
						continue
					}
				} else {
					continue
				}
			}
			if info.Urgency != "" {
				return info.Urgency
			}
		}

		for _, info := range rec.Releases {
			if info.Urgency != "" {
				return info.Urgency
			}
		}
		return ""
	}
	urgency := strings.ToLower(strings.TrimSpace(pickUrgency()))
	urgency = strings.TrimRight(urgency, "*")
	switch urgency {
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low", "unimportant":
		return SevLow
	}
	return ""
}

func trackerHasRelevantRelease(rec debianCVE, releases map[string]struct{}) bool {
	if len(releases) == 0 {
		return true
	}
	for rel := range rec.Releases {
		r := strings.ToLower(strings.TrimSpace(rel))
		r = strings.TrimSuffix(r, "-lts")
		if _, ok := releases[r]; ok {
			return true
		}
		if alias := distroReleaseAliases["debian"][r]; alias != "" {
			if _, ok := releases[alias]; ok {
				return true
			}
		}
	}
	return false
}

func debianTrackerToDistroStatus(rec debianCVE) []DistroStatus {
	if len(rec.Releases) == 0 {
		return nil
	}
	out := make([]DistroStatus, 0, len(rec.Releases))
	for rel, info := range rec.Releases {
		out = append(out, DistroStatus{
			Distro:     "debian",
			Release:    strings.ToLower(strings.TrimSuffix(rel, "-lts")),
			Status:     normaliseDebianStatus(info),
			FixVersion: info.FixedVersion,
			Urgency:    info.Urgency,
			Source:     SeveritySourceDebianTracker,
		})
	}
	return out
}

func applyDLAFixes(results []*ComponentResult, idx *dlaIndex, os *ImageOS, log ProgressLogger) {
	if idx == nil || !idx.IsLoaded() {
		return
	}
	for _, r := range results {
		if !isDebianEcosystem(r.System) {
			continue
		}
		src := r.Source
		if src == "" {
			src = r.Name
		}
		releases := releasesForImage(r.Component, "debian", os)
		if len(releases) == 0 {
			continue
		}

		seen := map[string]struct{}{}
		var allFixes []dlaFix
		for rel := range releases {
			for _, fix := range idx.LookupPackageFixes(src, rel) {
				if _, dup := seen[fix.Advisory+"/"+rel]; dup {
					continue
				}
				seen[fix.Advisory+"/"+rel] = struct{}{}
				allFixes = append(allFixes, fix)
			}
		}
		if len(allFixes) == 0 {
			debugLog(log, r.Name, "DLA: no fixes found for source=%s releases=%v", src, releases)
			continue
		}
		debugLog(log, r.Name, "DLA: found %d fix entries for source=%s releases=%v", len(allFixes), src, releases)

		vulnIdx := make(map[string]int, len(r.Vulnerabilities))
		for i, v := range r.Vulnerabilities {
			if v.CVE != "" {
				vulnIdx[v.CVE] = i
			}
			if v.ID != "" {
				vulnIdx[v.ID] = i
			}
		}

		releaseCodename := dlaReleaseCodename(releases)

		for _, fix := range allFixes {
			dstatus := DistroStatus{
				Distro:     "debian",
				Release:    releaseCodename,
				Status:     "resolved",
				FixVersion: fix.FixedVersion,
				Source:     "dla",
			}

			advID := fix.Advisory
			if i, ok := vulnIdx[advID]; ok {
				debugLog(log, r.Name, "DLA: %s merging fixVer=%s release=%s into existing entry", advID, fix.FixedVersion, releaseCodename)
				r.Vulnerabilities[i].DistroStatus = mergeDistroStatus(
					r.Vulnerabilities[i].DistroStatus,
					[]DistroStatus{dstatus},
				)
			} else {
				debugLog(log, r.Name, "DLA: %s ADDING standalone entry fixVer=%s release=%s", advID, fix.FixedVersion, releaseCodename)
				v := Vulnerability{
					ID:           advID,
					CVE:          "",
					DistroStatus: []DistroStatus{dstatus},
					Reference:    "https://security-tracker.debian.org/tracker/" + advID,
				}
				r.Vulnerabilities = append(r.Vulnerabilities, v)
				vulnIdx[advID] = len(r.Vulnerabilities) - 1
			}

			for _, cve := range fix.CVEs {
				if i, ok := vulnIdx[cve]; ok {

					debugLog(log, r.Name, "DLA: %s %s merging fixVer=%s release=%s into existing entry", fix.Advisory, cve, fix.FixedVersion, releaseCodename)
					debugCVELog(log, r.Name, cve, "DLA: %s merging fixVer=%s release=%s into existing entry", fix.Advisory, fix.FixedVersion, releaseCodename)
					r.Vulnerabilities[i].DistroStatus = mergeDistroStatus(
						r.Vulnerabilities[i].DistroStatus,
						[]DistroStatus{dstatus},
					)
				} else {

					debugLog(log, r.Name, "DLA: %s %s adding new entry fixVer=%s release=%s", fix.Advisory, cve, fix.FixedVersion, releaseCodename)
					debugCVELog(log, r.Name, cve, "DLA: %s ADDING new entry fixVer=%s release=%s", fix.Advisory, fix.FixedVersion, releaseCodename)
					v := Vulnerability{
						ID:           cve,
						CVE:          cve,
						DistroStatus: []DistroStatus{dstatus},
						Reference:    "https://security-tracker.debian.org/tracker/" + cve,
					}
					r.Vulnerabilities = append(r.Vulnerabilities, v)
					vulnIdx[cve] = len(r.Vulnerabilities) - 1
				}
			}
		}
	}
}

func dlaReleaseCodename(releases map[string]struct{}) string {

	for rel := range releases {
		r := strings.ToLower(strings.TrimSpace(rel))
		if len(r) > 0 && (r[0] < '0' || r[0] > '9') {
			return r
		}
	}

	for rel := range releases {
		return strings.ToLower(strings.TrimSpace(rel))
	}
	return ""
}

func mergeStringSet(a []string, b []string) []string {
	if len(b) == 0 {
		return a
	}
	exists := make(map[string]struct{}, len(a))
	for _, s := range a {
		exists[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := exists[s]; ok {
			continue
		}
		exists[s] = struct{}{}
		a = append(a, s)
	}
	return a
}
