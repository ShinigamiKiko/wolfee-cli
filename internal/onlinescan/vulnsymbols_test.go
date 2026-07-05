package onlinescan

import (
	"encoding/json"
	"testing"
)

const pgxLikeOSV = `{
  "id": "GO-2026-4771",
  "aliases": ["CVE-2026-33815", "GHSA-9jj7-4m8r-rfcm"],
  "summary": "SQL injection in github.com/jackc/pgx/v5",
  "affected": [{
    "package": {"ecosystem": "Go", "name": "github.com/jackc/pgx/v5"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "5.9.0"}]}],
    "ecosystem_specific": {
      "imports": [
        {"path": "github.com/jackc/pgx/v5", "symbols": ["Conn.Query", "Conn.Exec"]},
        {"path": "github.com/jackc/pgx/v5/pgconn", "symbols": ["PgConn.CopyFrom"]}
      ]
    }
  }]
}`

func TestExtractVulnSymbols_GoImports(t *testing.T) {
	var v osvVuln
	if err := json.Unmarshal([]byte(pgxLikeOSV), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := mapOSV(v)

	if len(got.VulnerableSymbols) != 2 {
		t.Fatalf("imports = %d; want 2 (%+v)", len(got.VulnerableSymbols), got.VulnerableSymbols)
	}
	if got.VulnerableSymbols[0].Path != "github.com/jackc/pgx/v5" {
		t.Errorf("path[0] = %q", got.VulnerableSymbols[0].Path)
	}
	if len(got.VulnerableSymbols[0].Symbols) != 2 || got.VulnerableSymbols[0].Symbols[0] != "Conn.Query" {
		t.Errorf("symbols[0] = %v; want [Conn.Query Conn.Exec]", got.VulnerableSymbols[0].Symbols)
	}
	if got.VulnerableSymbols[1].Path != "github.com/jackc/pgx/v5/pgconn" {
		t.Errorf("path[1] = %q", got.VulnerableSymbols[1].Path)
	}
}

func TestExtractVulnSymbols_NoSymbols(t *testing.T) {
	const noSym = `{
      "id": "GO-2025-9999",
      "affected": [{
        "package": {"ecosystem": "Go", "name": "example.com/x"},
        "ecosystem_specific": {"imports": [{"path": "example.com/x/pkg"}]}
      }]
    }`
	var v osvVuln
	if err := json.Unmarshal([]byte(noSym), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := mapOSV(v)
	if len(got.VulnerableSymbols) != 1 || got.VulnerableSymbols[0].Path != "example.com/x/pkg" {
		t.Fatalf("imports = %+v; want one path, no symbols", got.VulnerableSymbols)
	}
	if len(got.VulnerableSymbols[0].Symbols) != 0 {
		t.Errorf("symbols = %v; want empty", got.VulnerableSymbols[0].Symbols)
	}
}

func TestExtractVulnSymbols_NonGoSkipped(t *testing.T) {
	const npm = `{
      "id": "GHSA-npm",
      "affected": [{
        "package": {"ecosystem": "npm", "name": "vite"},
        "ecosystem_specific": {"imports": [{"path": "should-be-ignored"}]}
      }]
    }`
	var v osvVuln
	if err := json.Unmarshal([]byte(npm), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := mapOSV(v); len(got.VulnerableSymbols) != 0 {
		t.Errorf("non-Go must yield no symbols, got %+v", got.VulnerableSymbols)
	}
}
