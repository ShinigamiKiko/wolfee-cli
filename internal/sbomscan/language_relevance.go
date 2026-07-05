package sbomscan

import (
	"strings"

	"sca-go/cli/internal/reachability"
)

const (
	LanguageRelevanceUsed       = "used"
	LanguageRelevanceTransitive = "transitive"
	LanguageRelevanceUnused     = "unused"
	LanguageRelevanceIrrelevant = "irrelevant"
	LanguageRelevanceRuntime    = "runtime"
	LanguageRelevanceUnknown    = "unknown"
)

func applyLanguageRelevance(cr *ComponentReport, oracle *reachability.Result) {
	lang := componentLanguage(cr.System, cr.PURL)
	cr.Language = lang
	cr.Relevant = nil
	if lang == "" {
		cr.LanguageRelevance = ""
		return
	}
	if lang == "os" {
		cr.LanguageRelevance = LanguageRelevanceRuntime
		return
	}
	if oracle != nil && oracle.KnowsProjectLanguages() {
		relevant := oracle.HasProjectLanguage(lang)
		cr.Relevant = &relevant
		if !relevant {
			cr.LanguageRelevance = LanguageRelevanceIrrelevant
			return
		}
	}

	switch cr.PackageUsage {
	case "used":
		cr.LanguageRelevance = LanguageRelevanceUsed
	case "used-transitive":
		cr.LanguageRelevance = LanguageRelevanceTransitive
	case "unused":
		cr.LanguageRelevance = LanguageRelevanceUnused
	default:
		cr.LanguageRelevance = LanguageRelevanceUnknown
	}
}

func componentLanguage(system, purl string) string {
	eco := strings.ToLower(strings.TrimSpace(system))
	if purlEco := purlEcosystem(purl); purlEco != "" {
		eco = purlEco
	}
	switch eco {
	case "deb", "dpkg", "apk", "apkdb", "rpm", "wolfi":
		return "os"
	case "go", "golang":
		return "go"
	case "npm":
		return "js"
	case "pypi", "pip":
		return "python"
	case "maven", "gradle":
		return "java"
	case "composer":
		return "php"
	case "cargo":
		return "rust"
	case "nuget":
		return "dotnet"
	case "gem":
		return "ruby"
	case "hex":
		return "elixir"
	case "pub":
		return "dart"
	case "swift":
		return "swift"
	case "conan":
		return "cpp"
	default:
		return ""
	}
}
