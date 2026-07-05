package reachability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxScanFileSize = 2 << 20

func findManifestDir(root, filename string) string {
	if _, err := os.Stat(filepath.Join(root, filename)); err == nil {
		return root
	}
	found := ""
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == root {
			return nil
		}
		name := d.Name()
		if name == "node_modules" || name == "vendor" || name == ".git" ||
			strings.HasPrefix(name, ".") {
			return filepath.SkipDir
		}
		if _, statErr := os.Stat(filepath.Join(path, filename)); statErr == nil {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func pkgImportUsage(_ context.Context, o Options, res *Result) {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return
	}
	probeNPM(dir, o, res)
	probePyPI(dir, o, res)
}

func probeNPM(dir string, o Options, res *Result) {

	npmRoot := findManifestDir(dir, "package.json")
	if npmRoot == "" {
		return
	}

	imported, err := scanJSImports(dir)
	if err != nil {
		if o.Logger != nil {
			o.Logger.Warn("reachability(npm): import-graph failed: %v - npm in-use/dead unavailable", err)
		}
		return
	}
	if res.ImportedPURLs == nil {
		res.ImportedPURLs = map[string]bool{}
	}
	if res.ImportSites == nil {
		res.ImportSites = map[string]string{}
	}
	if res.ImportLines == nil {
		res.ImportLines = map[string]string{}
	}
	if res.HaveImportUsage == nil {
		res.HaveImportUsage = map[string]bool{}
	}
	for key, hit := range imported {
		res.ImportedPURLs[key] = true
		res.ImportSites[key] = hit.site
		res.ImportLines[key] = hit.text
	}
	res.HaveImportUsage["npm"] = true

	trans := buildNPMTransitivePURLs(npmRoot, res.ImportedPURLs)
	if trans != nil {
		res.TransitivePURLs = trans
		res.HaveLockGraph = true
		if o.Logger != nil {
			o.Logger.Step(fmt.Sprintf(
				"Reachability(javascript): import-graph - %d packages imported in source, %d reachable transitively via package-lock.json",
				len(imported), len(trans),
			))
			o.Logger.Warn("reachability(npm): transitive deps (%d) are shown as 'transitive' - "+
				"their 'not-used' verdict is conservative; only direct imports are confirmed from source files",
				len(trans),
			)
		}
	} else if o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("Reachability(javascript): import-graph - %d packages imported in source", len(imported)))
		if _, lerr := os.Stat(filepath.Join(npmRoot, "package-lock.json")); lerr != nil {
			o.Logger.Warn("reachability(npm): package-lock.json not found - transitive dependencies cannot be distinguished from unused ones; run 'npm install' to generate it")
		}
	}
}

func probePyPI(dir string, o Options, res *Result) {

	pyManifests := []string{"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock"}
	pyRoot := ""
	for _, m := range pyManifests {
		if r := findManifestDir(dir, m); r != "" {
			pyRoot = r
			break
		}
	}
	if pyRoot == "" {
		return
	}

	imported, err := scanPyImports(dir)
	if err != nil {
		if o.Logger != nil {
			o.Logger.Warn("reachability(pypi): import-graph failed: %v - pypi in-use/dead unavailable", err)
		}
		return
	}
	if res.ImportedPURLs == nil {
		res.ImportedPURLs = map[string]bool{}
	}
	if res.ImportSites == nil {
		res.ImportSites = map[string]string{}
	}
	if res.ImportLines == nil {
		res.ImportLines = map[string]string{}
	}
	if res.HaveImportUsage == nil {
		res.HaveImportUsage = map[string]bool{}
	}
	for key, hit := range imported {
		res.ImportedPURLs[key] = true
		res.ImportSites[key] = hit.site
		res.ImportLines[key] = hit.text
	}
	res.HaveImportUsage["pypi"] = true
	if o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("Reachability(python): import-graph - %d packages imported in source", len(imported)))
	}
}

var (
	reJSFrom = regexp.MustCompile(`\bfrom\s+['"]([^'"./][^'"]*?)['"]`)

	reJSDynamic = regexp.MustCompile(`\bimport\s*\(\s*['"]([^'"./][^'"]*?)['"]\s*\)`)

	reJSRequire = regexp.MustCompile(`\brequire\s*\(\s*['"]([^'"./][^'"]*?)['"]\s*\)`)
)

var jsExts = map[string]bool{
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".mts": true, ".cts": true,
}

type importHit struct {
	site string
	text string
}

func scanJSImports(dir string) (map[string]importHit, error) {
	out := map[string]importHit{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == "dist" || name == "build" ||
				name == ".git" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !jsExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		data, ferr := io.ReadAll(io.LimitReader(f, maxScanFileSize+1))
		f.Close()
		if ferr != nil || len(data) > maxScanFileSize {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		for _, re := range []*regexp.Regexp{reJSFrom, reJSDynamic, reJSRequire} {
			for _, m := range re.FindAllSubmatchIndex(data, -1) {
				spec := string(data[m[2]:m[3]])
				key := npmSpecToPURLKey(spec)
				if key == "" {
					continue
				}
				if _, exists := out[key]; exists {
					continue
				}
				lineNum := 1 + bytes.Count(data[:m[0]], []byte{'\n'})
				out[key] = importHit{
					site: fmt.Sprintf("%s:%d", rel, lineNum),
					text: extractLine(data, m[0]),
				}
			}
		}
		return nil
	})
	return out, err
}

func extractLine(data []byte, pos int) string {
	start := bytes.LastIndexByte(data[:pos], '\n') + 1
	end := bytes.IndexByte(data[pos:], '\n')
	var line []byte
	if end < 0 {
		line = data[start:]
	} else {
		line = data[start : pos+end]
	}
	return strings.TrimSpace(string(line))
}

func npmSpecToPURLKey(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}

	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}

	if strings.HasPrefix(spec, "node:") {
		return ""
	}
	var pkg string
	if strings.HasPrefix(spec, "@") {

		parts := strings.SplitN(spec, "/", 3)
		if len(parts) < 2 {
			return ""
		}
		pkg = parts[0] + "/" + parts[1]
	} else {

		if i := strings.IndexByte(spec, '/'); i >= 0 {
			pkg = spec[:i]
		} else {
			pkg = spec
		}
	}
	pkg = strings.ToLower(pkg)
	if strings.HasPrefix(pkg, "@") {

		pkg = "%40" + pkg[1:]
	}
	return "pkg:npm/" + pkg
}

var (
	rePyImport = regexp.MustCompile(`(?m)^\s*import\s+([\w]+)`)

	rePyFrom = regexp.MustCompile(`(?m)^\s*from\s+([\w]+)`)
)

func scanPyImports(dir string) (map[string]importHit, error) {
	out := map[string]importHit{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "__pycache__" || name == ".venv" || name == "venv" ||
				name == ".git" || strings.HasPrefix(name, ".") ||
				name == "site-packages" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".py" {
			return nil
		}
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		data, ferr := io.ReadAll(io.LimitReader(f, maxScanFileSize+1))
		f.Close()
		if ferr != nil || len(data) > maxScanFileSize {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		for _, re := range []*regexp.Regexp{rePyImport, rePyFrom} {
			for _, m := range re.FindAllSubmatchIndex(data, -1) {
				name := string(data[m[2]:m[3]])
				key := pypiNameToPURLKey(name)
				if key == "" {
					continue
				}
				if _, exists := out[key]; exists {
					continue
				}
				lineNum := 1 + bytes.Count(data[:m[0]], []byte{'\n'})
				out[key] = importHit{
					site: fmt.Sprintf("%s:%d", rel, lineNum),
					text: extractLine(data, m[0]),
				}
			}
		}
		return nil
	})
	return out, err
}

func pypiNameToPURLKey(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	return "pkg:pypi/" + name
}
