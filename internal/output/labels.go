package output

import (
	"reflect"
	"sort"
	"strings"
)

func anyOriginAttributed(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		switch stringField(components.Index(i), "Origin") {
		case "base", "app", "image", "image-lib":
			return true
		}
	}
	return false
}

func anyNonOSComponent(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		switch strings.ToLower(stringField(components.Index(i), "System")) {
		case "deb", "dpkg", "apk", "apkdb", "rpm", "wolfi", "":

		default:
			return true
		}
	}
	return false
}

func anyLayerDigest(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		if stringField(components.Index(i), "LayerDigest") != "" {
			return true
		}
	}
	return false
}

func anyLanguageRelevance(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		c := components.Index(i)
		if stringField(c, "Language") != "" || stringField(c, "LanguageRelevance") != "" {
			return true
		}
	}
	return false
}

type layerSummary struct {
	digest    string
	createdBy string
	pkgs      int
	worst     string
	rank      int
}

func collectLayerSummary(components reflect.Value) []layerSummary {
	if !components.IsValid() {
		return nil
	}
	by := map[string]*layerSummary{}
	for i := 0; i < components.Len(); i++ {
		c := components.Index(i)
		dig := stringField(c, "LayerDigest")
		if dig == "" {
			continue
		}
		s, ok := by[dig]
		if !ok {
			s = &layerSummary{digest: dig, createdBy: stringField(c, "LayerCreatedBy")}
			by[dig] = s
		} else if s.createdBy == "" {
			s.createdBy = stringField(c, "LayerCreatedBy")
		}
		s.pkgs++
		if r := rankComponent(c); r > s.rank {
			s.rank = r
			s.worst = stringField(c, "TopSeverity")
			if boolNested(c, "Malware", "Found") {
				s.worst = "CRITICAL"
			}
		}
	}
	out := make([]layerSummary, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank > out[j].rank
		}
		return out[i].pkgs > out[j].pkgs
	})
	return out
}

func trimCreatedBy(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, pfx := range []string{
		"/bin/sh -c #(nop) ",
		"/bin/sh -c #(nop)",
		"/bin/sh -c ",
	} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimSpace(s[len(pfx):])
			break
		}
	}
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

func originLabel(system, origin string, transitive bool) string {
	osType := ""
	switch strings.ToLower(strings.TrimSpace(system)) {
	case "deb", "apk", "rpm":
		osType = strings.ToUpper(strings.TrimSpace(system))
	}
	if osType != "" {

		if origin == "image" {
			return osType + "(image)"
		}
		return osType
	}

	switch origin {
	case "base":
		return "BASE"
	case "app":
		if transitive {
			return "APP(T)"
		}
		return "APP"
	case "image", "image-lib":
		return "LIB(image)"
	default:
		return "-"
	}
}

func langLabel(system, purl, language string) string {
	lang := normalizeLang(language)
	if lang == "" {
		lang = ecosystemLang(system, purl)
	}
	if lang == "" {
		return "unknown"
	}
	if lang == "os" {
		return "runtime/os"
	}
	return "relevant-" + displayLang(lang)
}

// plainLangLabel is the ecosystem language without the reachability "relevant-"
// framing, used when no call-graph relevance data is available.
func plainLangLabel(system, purl string) string {
	switch l := ecosystemLang(system, purl); l {
	case "":
		return "unknown"
	case "os":
		return "os"
	default:
		return displayLang(l)
	}
}

func ecosystemLang(system, purl string) string {
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

func purlEcosystem(purl string) string {
	purl = strings.TrimSpace(strings.ToLower(purl))
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[len("pkg:"):]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return ""
}

func normalizeLang(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "go", "golang":
		return "go"
	case "js", "javascript", "typescript", "node", "nodejs", "npm":
		return "js"
	case "py", "python", "pypi", "pip":
		return "python"
	case "java", "maven", "gradle":
		return "java"
	case "php", "composer":
		return "php"
	case "rust", "cargo":
		return "rust"
	case "dotnet", ".net", "nuget", "csharp", "c#":
		return "dotnet"
	case "ruby", "gem":
		return "ruby"
	case "elixir", "hex":
		return "elixir"
	case "dart", "pub":
		return "dart"
	case "swift":
		return "swift"
	case "cpp", "c++", "c", "conan":
		return "cpp"
	case "os", "runtime", "deb", "apk", "rpm":
		return "os"
	default:
		return ""
	}
}

func displayLang(lang string) string {
	switch normalizeLang(lang) {
	case "python":
		return "py"
	case "dotnet":
		return "dotnet"
	case "elixir":
		return "ex"
	default:
		return normalizeLang(lang)
	}
}

func shortDigest(d string) string {
	if d == "" {
		return ""
	}
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}

func countComponentErrors(components reflect.Value) int {
	if !components.IsValid() {
		return 0
	}
	n := 0
	for i := 0; i < components.Len(); i++ {
		if e := stringField(components.Index(i), "Error"); e != "" {
			n++
		}
	}
	return n
}
