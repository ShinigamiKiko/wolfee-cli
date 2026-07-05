package reachability

import "strings"

type State string

const (
	StateUnknown     State = "unknown"
	StateUnreachable State = "unreachable"
	StateReachable   State = "reachable"

	StateInUse State = "in-use"
	StateDead  State = "dead"
)

type Result struct {
	ByVuln map[string]State

	ProjectLanguages map[string]bool

	Modules         map[string]bool
	HaveModuleUsage bool

	AtomReachablePURLs map[string]bool
	AtomEcosystems     map[string]bool

	ImportedPURLs   map[string]bool
	HaveImportUsage map[string]bool

	TransitivePURLs map[string]bool
	HaveLockGraph   bool

	CallSites map[string]string

	CallLines map[string]string

	ImportSites map[string]string

	ImportLines map[string]string

	GoImportSites map[string]string

	GoImportLines map[string]string

	CalledModules map[string]string

	GOAliases map[string][]string

	GOSeverity map[string]string

	GoVersion string

	MainModule string
}

func (r *Result) KnowsProjectLanguages() bool {
	return r != nil && len(r.ProjectLanguages) > 0
}

func (r *Result) HasProjectLanguage(language string) bool {
	if r == nil || len(r.ProjectLanguages) == 0 {
		return false
	}
	return r.ProjectLanguages[normalizeProjectLanguage(language)]
}

func (r *Result) AtomPackageUsage(ecosystem, purlNoVersion string) State {
	if r == nil || len(r.AtomEcosystems) == 0 {
		return StateUnknown
	}
	if ecosystem == "" || !r.AtomEcosystems[ecosystem] {
		return StateUnknown
	}
	if purlNoVersion != "" && r.AtomReachablePURLs[strings.ToLower(purlNoVersion)] {
		return StateReachable
	}
	return StateUnknown
}

func (r *Result) ImportPackageUsage(ecosystem, purlNoVersion string) State {
	if r == nil || len(r.HaveImportUsage) == 0 {
		return StateUnknown
	}
	if ecosystem == "" || !r.HaveImportUsage[ecosystem] {
		return StateUnknown
	}
	if purlNoVersion != "" {
		key := strings.ToLower(purlNoVersion)
		if r.ImportedPURLs[key] {
			return StateInUse
		}

		if r.HaveLockGraph && r.TransitivePURLs[key] {
			return StateInUse
		}
	}
	return StateDead
}

func (r *Result) IsTransitiveImport(purlNoVersion string) bool {
	if r == nil || !r.HaveLockGraph {
		return false
	}
	key := strings.ToLower(purlNoVersion)
	return r.TransitivePURLs[key] && !r.ImportedPURLs[key]
}

func (r *Result) VulnCallSite(ids ...string) string {
	if r == nil {
		return ""
	}
	for _, id := range ids {
		if s := r.CallSites[normID(id)]; s != "" {
			return s
		}
	}
	return ""
}

func (r *Result) VulnCallLine(ids ...string) string {
	if r == nil {
		return ""
	}
	for _, id := range ids {
		if s := r.CallLines[normID(id)]; s != "" {
			return s
		}
	}
	return ""
}

func (r *Result) ImportSite(purlNoVersion string) string {
	if r == nil {
		return ""
	}
	return r.ImportSites[strings.ToLower(purlNoVersion)]
}

func (r *Result) ImportLine(purlNoVersion string) string {
	if r == nil {
		return ""
	}
	return r.ImportLines[strings.ToLower(purlNoVersion)]
}

func (r *Result) GoImportSite(modulePath string) string {
	if r == nil {
		return ""
	}
	return r.GoImportSites[modulePath]
}

func (r *Result) GoImportLine(modulePath string) string {
	if r == nil {
		return ""
	}
	return r.GoImportLines[modulePath]
}

func (r *Result) PackageUsage(modulePaths ...string) State {
	if r == nil || !r.HaveModuleUsage {
		return StateUnknown
	}
	anyPath := false
	for _, m := range modulePaths {
		if m == "" {
			continue
		}
		anyPath = true
		if r.Modules[m] {
			return StateInUse
		}
	}

	if !anyPath {
		return StateUnknown
	}
	return StateDead
}

func normID(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

func (r *Result) CalledIDsForModule(modulePath string) []string {
	if r == nil || len(r.CalledModules) == 0 {
		return nil
	}
	var ids []string
	for id, mod := range r.CalledModules {
		if mod == modulePath {
			ids = append(ids, id)
		}
	}
	return ids
}

func (r *Result) set(id string, st State) {
	id = normID(id)
	if id == "" {
		return
	}
	if r.ByVuln == nil {
		r.ByVuln = map[string]State{}
	}
	if r.ByVuln[id] == StateReachable {
		return
	}
	r.ByVuln[id] = st
}

func (r *Result) Lookup(ids ...string) State {
	if r == nil || len(r.ByVuln) == 0 {
		return StateUnknown
	}
	out := StateUnknown
	for _, id := range ids {
		switch r.ByVuln[normID(id)] {
		case StateReachable:
			return StateReachable
		case StateUnreachable:
			out = StateUnreachable
		}
	}
	return out
}
