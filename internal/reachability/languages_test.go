package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectProjectLanguages(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/app\n")
	mustWrite(t, filepath.Join(dir, "frontend", "package.json"), `{"name":"app"}`)
	mustWrite(t, filepath.Join(dir, "worker", "pyproject.toml"), "[project]\nname = \"worker\"\n")
	mustWrite(t, filepath.Join(dir, "node_modules", "ignored", "pom.xml"), "<project />")

	langs := detectProjectLanguages(dir)
	for _, lang := range []string{"go", "js", "python"} {
		if !langs[lang] {
			t.Fatalf("expected %s language in %#v", lang, langs)
		}
	}
	if langs["java"] {
		t.Fatalf("node_modules manifest should be ignored: %#v", langs)
	}
}

func TestNormalizeProjectLanguage(t *testing.T) {
	cases := map[string]string{
		"golang":     "go",
		"nodejs":     "js",
		"npm":        "js",
		"pypi":       "python",
		"maven":      "java",
		"nuget":      "dotnet",
		"unknownish": "",
	}
	for in, want := range cases {
		if got := normalizeProjectLanguage(in); got != want {
			t.Errorf("normalizeProjectLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
