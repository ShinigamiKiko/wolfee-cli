package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNpmSpecToPURLKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"react", "pkg:npm/react"},
		{"React", "pkg:npm/react"},
		{"lodash/fp", "pkg:npm/lodash"},
		{"@babel/core", "pkg:npm/%40babel/core"},
		{"@babel/core/something", "pkg:npm/%40babel/core"},
		{"@Angular/Common", "pkg:npm/%40angular/common"},
		{"node:fs", ""},
		{"./local", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := npmSpecToPURLKey(c.in)
		if got != c.want {
			t.Errorf("npmSpecToPURLKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPypiNameToPURLKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"requests", "pkg:pypi/requests"},
		{"Flask", "pkg:pypi/flask"},
		{"my_package", "pkg:pypi/my-package"},
		{"", ""},
	}
	for _, c := range cases {
		got := pypiNameToPURLKey(c.in)
		if got != c.want {
			t.Errorf("pypiNameToPURLKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScanJSImports(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "app.tsx"), []byte(`
import React from 'react'
import { something } from '@babel/core'
import styles from './local.css'
const x = require('lodash/fp')
import('react-dom')
`), 0o644); err != nil {
		t.Fatal(err)
	}

	nm := filepath.Join(dir, "node_modules", "vite")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "index.js"), []byte(`import something from 'evil'`), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := scanJSImports(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"pkg:npm/react":         true,
		"pkg:npm/%40babel/core": true,
		"pkg:npm/lodash":        true,
		"pkg:npm/react-dom":     true,
	}
	for k := range want {
		if got[k].site == "" {
			t.Errorf("missing expected import %q", k)
		}
	}
	if got["pkg:npm/evil"].site != "" {
		t.Error("node_modules should be skipped")
	}
}

func TestImportPackageUsage(t *testing.T) {

	var r *Result
	if got := r.ImportPackageUsage("npm", "pkg:npm/react"); got != StateUnknown {
		t.Errorf("nil result: got %q want unknown", got)
	}

	r = &Result{
		HaveImportUsage: map[string]bool{"npm": true},
		ImportedPURLs:   map[string]bool{"pkg:npm/react": true},
	}
	if got := r.ImportPackageUsage("npm", "pkg:npm/react"); got != StateInUse {
		t.Errorf("imported pkg: got %q want in-use", got)
	}

	if got := r.ImportPackageUsage("npm", "pkg:npm/vite"); got != StateDead {
		t.Errorf("unimported pkg: got %q want dead", got)
	}

	if got := r.ImportPackageUsage("pypi", "pkg:pypi/requests"); got != StateUnknown {
		t.Errorf("unprobed ecosystem: got %q want unknown", got)
	}
}
