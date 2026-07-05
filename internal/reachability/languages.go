package reachability

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var manifestLanguages = map[string]string{
	"go.mod":                   "go",
	"package.json":             "js",
	"pnpm-lock.yaml":           "js",
	"yarn.lock":                "js",
	"bun.lock":                 "js",
	"bun.lockb":                "js",
	"requirements.txt":         "python",
	"pyproject.toml":           "python",
	"setup.py":                 "python",
	"pipfile":                  "python",
	"poetry.lock":              "python",
	"uv.lock":                  "python",
	"pom.xml":                  "java",
	"build.gradle":             "java",
	"build.gradle.kts":         "java",
	"composer.json":            "php",
	"composer.lock":            "php",
	"cargo.toml":               "rust",
	"cargo.lock":               "rust",
	"packages.config":          "dotnet",
	"directory.packages.props": "dotnet",
	"gemfile":                  "ruby",
	"gemfile.lock":             "ruby",
	"mix.exs":                  "elixir",
	"mix.lock":                 "elixir",
	"pubspec.yaml":             "dart",
	"package.swift":            "swift",
	"conanfile.txt":            "cpp",
	"conanfile.py":             "cpp",
}

func detectProjectLanguages(root string) map[string]bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}

	langs := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipLanguageDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		name := strings.ToLower(d.Name())
		if lang := normalizeProjectLanguage(manifestLanguages[name]); lang != "" {
			langs[lang] = true
			return nil
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".csproj", ".fsproj", ".vbproj":
			langs["dotnet"] = true
		case ".gemspec":
			langs["ruby"] = true
		}
		return nil
	})
	if len(langs) == 0 {
		return nil
	}
	return langs
}

func skipLanguageDir(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv":
		return true
	default:
		return false
	}
}

func normalizeProjectLanguage(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "go", "golang":
		return "go"
	case "js", "javascript", "typescript", "node", "nodejs", "npm":
		return "js"
	case "py", "python", "pypi", "pip":
		return "python"
	case "java", "jvm", "maven", "gradle":
		return "java"
	case "php", "composer":
		return "php"
	case "rust", "cargo":
		return "rust"
	case "dotnet", ".net", "nuget", "csharp", "c#", "fsharp", "vb":
		return "dotnet"
	case "ruby", "gem":
		return "ruby"
	case "elixir", "erlang", "hex":
		return "elixir"
	case "dart", "pub":
		return "dart"
	case "swift":
		return "swift"
	case "cpp", "c++", "c", "conan":
		return "cpp"
	default:
		return ""
	}
}
