package sbomscan

import (
	"testing"

	"sca-go/cli/internal/reachability"
)

func TestApplyLanguageRelevance_UsedGoModule(t *testing.T) {
	oracle := &reachability.Result{
		ByVuln:           map[string]reachability.State{},
		ProjectLanguages: map[string]bool{"go": true},
		Modules:          map[string]bool{"github.com/acme/lib": true},
		HaveModuleUsage:  true,
	}
	cr := ComponentReport{PURL: "pkg:golang/github.com/acme/lib@v1.2.3", System: "golang", Name: "github.com/acme/lib"}

	applyReachability(&cr, oracle)

	if cr.Language != "go" || cr.LanguageRelevance != LanguageRelevanceUsed {
		t.Fatalf("language verdict = %q/%q, want go/used", cr.Language, cr.LanguageRelevance)
	}
	if cr.PackageUsage != "used" {
		t.Fatalf("PackageUsage = %q, want used", cr.PackageUsage)
	}
	if cr.Relevant == nil || !*cr.Relevant {
		t.Fatalf("Relevant = %v, want true for a Go lib in a Go project", cr.Relevant)
	}
}

func TestApplyLanguageRelevance_IrrelevantLanguage(t *testing.T) {
	oracle := &reachability.Result{
		ByVuln:           map[string]reachability.State{},
		ProjectLanguages: map[string]bool{"go": true},
	}
	cr := ComponentReport{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", System: "maven", Name: "log4j-core"}

	applyReachability(&cr, oracle)

	if cr.Language != "java" || cr.LanguageRelevance != LanguageRelevanceIrrelevant {
		t.Fatalf("language verdict = %q/%q, want java/irrelevant", cr.Language, cr.LanguageRelevance)
	}
	if cr.Relevant == nil || *cr.Relevant {
		t.Fatalf("Relevant = %v, want false for a Java lib in a Go project", cr.Relevant)
	}
}

func TestApplyLanguageRelevance_RuntimeOSWithCodeContext(t *testing.T) {
	oracle := &reachability.Result{
		ByVuln:           map[string]reachability.State{},
		ProjectLanguages: map[string]bool{"go": true},
	}
	cr := ComponentReport{PURL: "pkg:deb/debian/openssl@3.0", System: "deb", Name: "openssl"}

	applyReachability(&cr, oracle)

	if cr.Language != "os" || cr.LanguageRelevance != LanguageRelevanceRuntime {
		t.Fatalf("language verdict = %q/%q, want os/runtime", cr.Language, cr.LanguageRelevance)
	}
	if cr.Relevant != nil {
		t.Fatalf("Relevant = %v, want nil for an OS/runtime package", cr.Relevant)
	}
}

func TestApplyReachability_SkipsLanguageWithoutCodeContext(t *testing.T) {
	cr := ComponentReport{PURL: "pkg:npm/lodash@4.17.20", System: "npm", Name: "lodash"}

	applyReachability(&cr, nil)

	if cr.Language != "" || cr.LanguageRelevance != "" {
		t.Fatalf("language verdict = %q/%q, want empty without code context", cr.Language, cr.LanguageRelevance)
	}
	if cr.Relevant != nil {
		t.Fatalf("Relevant = %v, want nil without code context", cr.Relevant)
	}
}
