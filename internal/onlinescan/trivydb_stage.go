package onlinescan

import (
	"fmt"
	"strings"

	"sca-go/cli/internal/trivydb"
)

func stageTrivyDB(results []*ComponentResult, tdb *trivydb.Reader, platform, imageFamily, imageRelease, imageCodename, imageArch string, log ProgressLogger) (processed, added, withHits int) {
	for _, r := range results {
		if !isDebianEcosystem(r.System) {
			continue
		}
		processed++

		lookupNames := []string{r.Name}
		for _, bn := range r.BinaryNames {
			if bn != r.Name {
				lookupNames = append(lookupNames, bn)
			}
		}

		existing := vulnsByKey(r.Vulnerabilities)
		compAdded := 0
		for _, name := range lookupNames {
			advs, err := tdb.Lookup(platform, name)
			if err != nil {
				debugLog(log, r.Name, "trivy-db lookup error pkg=%s: %v", name, err)
				continue
			}
			if len(advs) == 0 {
				debugLog(log, r.Name, "trivy-db: no advisories for platform=%s pkg=%s", platform, name)
				continue
			}
			debugLog(log, r.Name, "trivy-db: found %d advisories for platform=%s pkg=%s", len(advs), platform, name)
			for _, adv := range advs {
				cve := pickCVEFromID(adv.VulnerabilityID)
				if adv.Status == trivydb.StatusNotAffected {
					debugLog(log, r.Name, "trivy-db: %s status=not-affected → skipped", adv.VulnerabilityID)
					debugCVELog(log, r.Name, cve, "trivy-db: via pkg=%s status=not-affected → skipped", name)
					continue
				}

				if !trivyArchMatches(adv.Arches, imageArch) {
					debugLog(log, r.Name, "trivy-db: %s arches=%v → skipped (image arch=%s)", adv.VulnerabilityID, adv.Arches, imageArch)
					continue
				}
				key := adv.VulnerabilityID
				if _, dup := existing[key]; dup {
					debugCVELog(log, r.Name, cve, "trivy-db: via pkg=%s already present → skipped", name)
					continue
				}

				vulnLookupID := cve
				if vulnLookupID == "" {
					vulnLookupID = adv.VulnerabilityID
				}
				detail, _ := tdb.LookupVuln(vulnLookupID)
				v := trivyAdvToVuln(adv, detail, imageFamily, imageRelease, imageCodename)
				debugLog(log, r.Name, "trivy-db: adding %s (via %s) status=%s fixVer=%q", adv.VulnerabilityID, name, v.DistroStatus[0].Status, adv.FixedVersion)
				debugCVELog(log, r.Name, cve, "trivy-db: ADDED via pkg=%s status=%s fixVer=%q", name, v.DistroStatus[0].Status, adv.FixedVersion)
				r.Vulnerabilities = append(r.Vulnerabilities, v)
				existing[key] = struct{}{}
				compAdded++
			}
		}
		if compAdded > 0 {
			debugLog(log, r.Name, "trivy-db: total %d new advisories added (looked up: %v)", compAdded, lookupNames)
			added += compAdded
			withHits++
		}
	}
	return
}

func trivyAdvToVuln(adv trivydb.Advisory, detail *trivydb.VulnDetail, family, release, codename string) Vulnerability {
	v := Vulnerability{
		ID:  adv.VulnerabilityID,
		CVE: pickCVEFromID(adv.VulnerabilityID),
	}
	if adv.FixedVersion != "" {
		v.Fixed = []string{adv.FixedVersion}
	}

	if detail != nil {

		sev := detail.SeverityV3
		if sev == trivydb.SeverityUnknown {
			sev = detail.Severity
		}
		if s := sev.String(); s != "" {
			v.Severity = s
			v.SeveritySource = SeveritySourceTrivyDB
		}
		if detail.CvssScoreV3 > 0 {
			v.CVSS = detail.CvssScoreV3
			v.CVSSVector = detail.CvssVectorV3
		} else if detail.CvssScore > 0 {
			v.CVSS = detail.CvssScore
			v.CVSSVector = detail.CvssVector
		}
		v.Title = detail.Title
		v.Description = detail.Description
	}

	releaseKey := strings.ToLower(strings.TrimSpace(codename))
	if releaseKey == "" {
		fam := strings.ToLower(family)
		if alias := distroReleaseAliases[fam][strings.ToLower(strings.TrimSpace(release))]; alias != "" {

			if len(alias) > 0 && (alias[0] < '0' || alias[0] > '9') {
				releaseKey = alias
			}
		}
		if releaseKey == "" {
			releaseKey = release
		}
	}

	v.DistroStatus = []DistroStatus{{
		Distro:     strings.ToLower(family),
		Release:    releaseKey,
		Status:     trivyStatusToDebianStatus(adv.Status, adv.FixedVersion),
		FixVersion: adv.FixedVersion,
		Source:     SeveritySourceTrivyDB,
	}}

	return v
}

func trivyStatusToDebianStatus(s trivydb.Status, fixedVersion string) string {
	switch s {
	case trivydb.StatusNotAffected:
		return "not-affected"
	case trivydb.StatusFixed:
		return "resolved"
	case trivydb.StatusAffected, trivydb.StatusUnderInvestigation:
		return "open"
	case trivydb.StatusWillNotFix:
		return "no-dsa"
	case trivydb.StatusFixDeferred:
		return "postponed"
	case trivydb.StatusEndOfLife:
		return "end-of-life"
	default:

		if fixedVersion != "" {
			return "resolved"
		}
		return "open"
	}
}

func pickCVEFromID(id string) string {
	if isCVEID(id) {
		return id
	}
	return extractEmbeddedCVE(id)
}

func vulnsByKey(vs []Vulnerability) map[string]struct{} {
	m := make(map[string]struct{}, len(vs)*2)
	for _, v := range vs {
		if v.ID != "" {
			m[v.ID] = struct{}{}
		}
		if v.CVE != "" {
			m[v.CVE] = struct{}{}
		}
	}
	return m
}

func trivyArchMatches(arches []string, imageArch string) bool {
	if len(arches) == 0 || imageArch == "" {
		return true
	}
	for _, a := range arches {
		if strings.EqualFold(a, imageArch) {
			return true
		}
	}
	return false
}

func platformString(family, version string) string {
	return fmt.Sprintf("%s %s", strings.ToLower(family), version)
}
