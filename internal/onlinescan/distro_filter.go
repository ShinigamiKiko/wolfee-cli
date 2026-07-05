package onlinescan

import (
	"fmt"
	os_ "os"
	"regexp"
	"strings"

	debversion "github.com/knqyf263/go-deb-version"
)

type distroComparator func(installed, fixed string) (patched bool, ok bool)

var distroComparators = map[string]distroComparator{
	"debian": isDebianPatched,
	"ubuntu": isDebianPatched,
}

var debianReleasePattern = regexp.MustCompile(`(?:^|[+~\.-])deb([0-9]+)(?:u[0-9]+)?(?:$|[+~\.-])`)

const (
	statusAffected           = "affected"
	statusFixDeferred        = "fix_deferred"
	statusWillNotFix         = "will_not_fix"
	statusNoDistroData       = "no_distro_data"
	statusUnderInvestigation = "under_investigation"
	statusLikelyAffected     = "likely_affected"
	statusLikelyFixed        = "likely_fixed"

	statusFixedInInstalled = "fixed_in_installed"
)

func applyDistroFiltering(results []*ComponentResult, os *ImageOS) {
	dbgPkg := strings.TrimSpace(os_.Getenv("WOLFEE_DEBUG_PKG"))
	dbgCVE := strings.ToUpper(strings.TrimSpace(os_.Getenv("WOLFEE_DEBUG_CVE")))
	for _, r := range results {
		if len(r.Vulnerabilities) == 0 {
			continue
		}
		isDebugPkg := dbgPkg != "" && (strings.EqualFold(r.Name, dbgPkg) || strings.EqualFold(r.Source, dbgPkg))
		filtered := make([]Vulnerability, 0, len(r.Vulnerabilities))
		for vi := range r.Vulnerabilities {
			v := r.Vulnerabilities[vi]
			keep, status, urgency := evaluateVulnerability(r.Component, v, os)
			isDebugCVE := dbgCVE != "" && strings.EqualFold(v.CVE, dbgCVE)
			if isDebugPkg || isDebugCVE {
				name := r.Name
				if isDebugCVE {
					name = r.Name + "/" + r.Source
				}
				if keep {
					fmt.Fprintf(os_.Stderr, "[DEBUG %s] distro_filter: KEEP %s status=%s urgency=%s installed=%s distroStatus=%s\n",
						name, v.CVE, status, urgency, r.Component.Version, formatDistroStatus(v.DistroStatus))
				} else {
					fmt.Fprintf(os_.Stderr, "[DEBUG %s] distro_filter: DROP %s installed=%s distroStatus=%s\n",
						name, v.CVE, r.Component.Version, formatDistroStatus(v.DistroStatus))
				}
			}
			if !keep {
				continue
			}
			v.Status = status
			if urgency != "" {
				applyUrgencySeverity(&v, urgency)
			}
			filtered = append(filtered, v)
		}
		r.Vulnerabilities = filtered
	}
}

func formatDistroStatus(ds []DistroStatus) string {
	if len(ds) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, d := range ds {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(d.Distro)
		sb.WriteByte(':')
		sb.WriteString(d.Release)
		sb.WriteByte('=')
		sb.WriteString(d.Status)
		if d.FixVersion != "" {
			sb.WriteByte('@')
			sb.WriteString(d.FixVersion)
		}
	}
	sb.WriteByte(']')
	return sb.String()
}

func evaluateVulnerability(c Component, v Vulnerability, os *ImageOS) (bool, string, string) {
	distro := distroForSystem(c.System)

	if distro == "" {
		return true, "", ""
	}

	if len(v.DistroStatus) == 0 {
		return true, statusAffected, ""
	}

	releases := releasesForImage(c, distro, os)

	var hit *DistroStatus
	var hitRank int
	var collectedUrgency string
	for i := range v.DistroStatus {
		st := &v.DistroStatus[i]
		if !strings.EqualFold(strings.TrimSpace(st.Distro), distro) {
			continue
		}
		if !releaseMatches(st.Release, releases) {
			continue
		}
		rank := distroStatusRank(*st)
		if hit == nil || rank > hitRank {
			hit = st
			hitRank = rank
		}
		if u := strings.ToLower(strings.TrimSpace(st.Urgency)); u != "" && collectedUrgency == "" {
			collectedUrgency = u
		}
	}

	if hit == nil {
		return true, classifyNoReleaseRow(c, v, distro, releases), ""
	}

	hitStatus := strings.ToLower(strings.TrimSpace(hit.Status))

	hitUrgency := collectedUrgency

	dbgCV := strings.ToUpper(strings.TrimSpace(os_.Getenv("WOLFEE_DEBUG_CVE")))
	if dbgCV != "" && strings.EqualFold(v.CVE, dbgCV) {
		fmt.Fprintf(os_.Stderr, "[DEBUG-CVE %s pkg=%s/%s] distro_filter/evaluate: hitStatus=%s hitUrgency=%s fixVer=%q hitRelease=%s hitSource=%s installed=%s\n",
			v.CVE, c.System, c.Name, hitStatus, hitUrgency, hit.FixVersion, hit.Release, hit.Source, c.Version)
	}

	switch hitStatus {
	case "resolved":
		fix := strings.TrimSpace(hit.FixVersion)
		if fix == "" {

			if dbgCV != "" && strings.EqualFold(v.CVE, dbgCV) {
				fmt.Fprintf(os_.Stderr, "[DEBUG-CVE %s pkg=%s/%s] distro_filter: resolved+emptyFix → KEEP affected\n", v.CVE, c.System, c.Name)
			}
			return true, statusAffected, hitUrgency
		}
		cmp := distroComparators[distro]
		installed := strings.TrimSpace(c.Version)
		if cmp != nil && installed != "" {
			if patched, ok := cmp(installed, fix); ok && patched {

				if same, seok := isDebianSameVersion(installed, fix); seok && same {
					if dbgCV != "" && strings.EqualFold(v.CVE, dbgCV) {
						fmt.Fprintf(os_.Stderr, "[DEBUG-CVE %s pkg=%s/%s] distro_filter: resolved installed==fixed → KEEP fixed_in_installed\n", v.CVE, c.System, c.Name)
					}
					return true, statusFixedInInstalled, hitUrgency
				}
				if dbgCV != "" && strings.EqualFold(v.CVE, dbgCV) {
					fmt.Fprintf(os_.Stderr, "[DEBUG-CVE %s pkg=%s/%s] distro_filter: resolved installed>fixed → DROP (installed=%s fix=%s)\n", v.CVE, c.System, c.Name, installed, fix)
				}
				return false, "", ""
			}
		}
		return true, statusAffected, hitUrgency
	case "open", "undetermined", "":
		switch hitUrgency {
		case "unimportant", "low*":
			return true, statusWillNotFix, hitUrgency
		case "postponed":
			return true, statusFixDeferred, hitUrgency
		}
		return true, statusAffected, hitUrgency
	case "no-dsa", "ignored":

		return true, statusWillNotFix, hitUrgency
	case "postponed":
		return true, statusFixDeferred, hitUrgency
	case "not-affected":
		if dbgCV != "" && strings.EqualFold(v.CVE, dbgCV) {
			fmt.Fprintf(os_.Stderr, "[DEBUG-CVE %s pkg=%s/%s] distro_filter: not-affected → DROP (release=%s source=%s)\n", v.CVE, c.System, c.Name, hit.Release, hit.Source)
		}
		return false, "", ""
	case "end-of-life":

		return true, statusAffected, hitUrgency
	}
	return true, statusAffected, hitUrgency
}

func debianUrgencyToSeverity(urgency string) string {
	u := strings.TrimRight(strings.ToLower(strings.TrimSpace(urgency)), "*")
	u = strings.TrimSuffix(u, "-lts")
	switch u {
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low", "unimportant":
		return SevLow
	}
	return ""
}

func applyUrgencySeverity(v *Vulnerability, urgency string) {
	debSev := debianUrgencyToSeverity(urgency)
	if debSev == "" {
		return
	}

	cur := strings.ToUpper(strings.TrimSpace(v.Severity))
	if cur == "" || cur == SevUnknownLabel {
		return
	}
	if severityRankDF[debSev] < severityRankDF[cur] {
		v.Severity = debSev
		v.SeveritySource = SeveritySourceDebianTracker
	}
}

func distroStatusRank(st DistroStatus) int {
	base := distroStatusBaseRank(strings.ToLower(strings.TrimSpace(st.Status)))
	if st.Source == SeveritySourceTrivyDB {
		return base + 10
	}
	return base
}

func distroStatusBaseRank(status string) int {
	switch status {
	case "resolved":
		return 6
	case "no-dsa", "ignored":
		return 5
	case "postponed":
		return 5
	case "not-affected":
		return 4
	case "open":
		return 3
	case "undetermined":
		return 2
	case "end-of-life":
		return 1
	default:
		return 0
	}
}

var severityRankDF = map[string]int{
	"":              0,
	SevUnknownLabel: 0,
	SevLow:          1,
	SevMedium:       2,
	SevHigh:         3,
	SevCritical:     4,
}

func releasesForImage(c Component, distro string, os *ImageOS) map[string]struct{} {
	out := map[string]struct{}{}
	if os != nil && strings.EqualFold(os.Family, distro) {
		if v := strings.ToLower(strings.TrimSpace(os.Version)); v != "" {
			out[v] = struct{}{}

			if i := strings.IndexByte(v, '.'); i > 0 {
				out[v[:i]] = struct{}{}
			}
		}
		if c := strings.ToLower(strings.TrimSpace(os.Codename)); c != "" {
			out[c] = struct{}{}
		}

		for r := range out {
			if alias := distroReleaseAliases[distro][r]; alias != "" {
				out[alias] = struct{}{}
			}
		}
	}

	for k := range releaseCandidates(c, distro) {
		out[k] = struct{}{}
		if alias := distroReleaseAliases[distro][k]; alias != "" {
			out[alias] = struct{}{}
		}
	}
	return out
}

var distroReleaseAliases = map[string]map[string]string{
	"debian": {
		"7": "wheezy", "wheezy": "7",
		"8": "jessie", "jessie": "8",
		"9": "stretch", "stretch": "9",
		"10": "buster", "buster": "10",
		"11": "bullseye", "bullseye": "11",
		"12": "bookworm", "bookworm": "12",
		"13": "trixie", "trixie": "13",
		"14": "forky", "forky": "14",
	},
	"ubuntu": {
		"14.04": "trusty", "trusty": "14.04",
		"16.04": "xenial", "xenial": "16.04",
		"18.04": "bionic", "bionic": "18.04",
		"20.04": "focal", "focal": "20.04",
		"22.04": "jammy", "jammy": "22.04",
		"24.04": "noble", "noble": "24.04",
	},
}

func distroForSystem(system string) string {
	switch strings.ToUpper(strings.TrimSpace(system)) {
	case "DEBIAN":
		return "debian"
	case "UBUNTU":
		return "ubuntu"
	default:
		return ""
	}
}

func releaseCandidates(c Component, distro string) map[string]struct{} {
	out := map[string]struct{}{}
	switch distro {
	case "debian", "ubuntu":
		for _, m := range debianReleasePattern.FindAllStringSubmatch(strings.TrimSpace(c.Version), -1) {
			if len(m) >= 2 && m[1] != "" {
				out[m[1]] = struct{}{}
			}
		}
	}
	return out
}

func releaseMatches(release string, candidates map[string]struct{}) bool {
	r := strings.ToLower(strings.TrimSpace(release))

	if r == "" {
		return true
	}
	if len(candidates) == 0 {

		return true
	}
	_, ok := candidates[r]
	return ok
}

func classifyNoReleaseRow(c Component, v Vulnerability, distro string, releases map[string]struct{}) string {
	installed := strings.TrimSpace(c.Version)
	cmp := distroComparators[distro]

	imageDebNum := imageDebianReleaseNum(releases)

	var fixVersions []string
	rows, openRows, openUnimportant := 0, 0, 0
	for _, st := range v.DistroStatus {
		if !strings.EqualFold(strings.TrimSpace(st.Distro), distro) {
			continue
		}
		rows++
		status := strings.ToLower(strings.TrimSpace(st.Status))
		urgency := strings.TrimRight(strings.ToLower(strings.TrimSpace(st.Urgency)), "*")
		fix := strings.TrimSpace(st.FixVersion)

		if status == "resolved" && fix != "" {
			fixVersions = append(fixVersions, fix)
		}
		if status == "open" {
			openRows++
			if urgency == "unimportant" {
				openUnimportant++
			}
		}
	}

	if rows == 0 {
		return statusNoDistroData
	}

	if len(fixVersions) > 0 {
		effective := fixVersions
		if imageDebNum != "" {
			var sameRelease []string
			for _, fv := range fixVersions {
				if isSameDebianReleaseFix(fv, imageDebNum) {
					sameRelease = append(sameRelease, fv)
				}
			}
			if len(sameRelease) > 0 {
				effective = sameRelease
			}
		}
		if cmp != nil && installed != "" {
			if earliest := earliestDebianVersion(effective, cmp); earliest != "" {
				if patched, ok := cmp(installed, earliest); ok {
					if patched {
						return statusLikelyFixed
					}
					return statusLikelyAffected
				}
			}
		}

		return statusLikelyAffected
	}

	if openRows == rows && openRows > 0 {
		if openUnimportant == openRows {

			return statusWillNotFix
		}
		return statusLikelyAffected
	}

	return statusNoDistroData
}

func imageDebianReleaseNum(releases map[string]struct{}) string {
	for r := range releases {
		r = strings.ToLower(strings.TrimSpace(r))

		if r != "" && r[0] >= '0' && r[0] <= '9' {
			return r
		}
	}
	return ""
}

func isSameDebianReleaseFix(fix, releaseNum string) bool {
	for _, m := range debianReleasePattern.FindAllStringSubmatch(fix, -1) {
		if len(m) >= 2 && m[1] == releaseNum {
			return true
		}
	}

	return false
}

func earliestDebianVersion(versions []string, cmp distroComparator) string {
	best := ""
	for _, v := range versions {
		if v == "" {
			continue
		}
		if best == "" {

			if _, ok := cmp(v, v); !ok {
				continue
			}
			best = v
			continue
		}

		patched, ok := cmp(v, best)
		if !ok {
			continue
		}
		if !patched {
			best = v
		}
	}
	return best
}

func isDebianPatched(installed, fixed string) (bool, bool) {
	iv, err := debversion.NewVersion(installed)
	if err != nil {
		return false, false
	}
	fv, err := debversion.NewVersion(fixed)
	if err != nil {
		return false, false
	}
	return iv.Compare(fv) >= 0, true
}

func isDebianSameVersion(installed, fixed string) (bool, bool) {
	iv, err := debversion.NewVersion(installed)
	if err != nil {
		return false, false
	}
	fv, err := debversion.NewVersion(fixed)
	if err != nil {
		return false, false
	}
	return iv.Compare(fv) == 0, true
}
