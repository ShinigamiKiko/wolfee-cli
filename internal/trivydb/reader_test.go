package trivydb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func buildTestDB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "trivy.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()

	if err := db.Update(func(tx *bolt.Tx) error {

		root, err := tx.CreateBucketIfNotExists([]byte("advisory-detail"))
		if err != nil {
			return err
		}
		plat, err := root.CreateBucketIfNotExists([]byte("debian 12"))
		if err != nil {
			return err
		}
		pkg, err := plat.CreateBucketIfNotExists([]byte("curl"))
		if err != nil {
			return err
		}
		adv, _ := json.Marshal(rawAdvisory{
			FixedVersion: "7.88.1-10",
			Status:       int(StatusFixed),
		})
		if err := pkg.Put([]byte("CVE-2024-0001"), adv); err != nil {
			return err
		}

		adv2, _ := json.Marshal(rawAdvisory{
			FixedVersion: "",
			Status:       int(StatusWillNotFix),
		})
		if err := pkg.Put([]byte("CVE-2024-0002"), adv2); err != nil {
			return err
		}

		vulnB, err := tx.CreateBucketIfNotExists([]byte("vulnerability"))
		if err != nil {
			return err
		}
		detail, _ := json.Marshal(rawVuln{
			Severity:     int(SeverityHigh),
			SeverityV3:   int(SeverityCritical),
			CvssScoreV3:  9.8,
			CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Title:        "curl: heap overflow",
			Description:  "A heap overflow in curl.",
		})
		return vulnB.Put([]byte("CVE-2024-0001"), detail)
	}); err != nil {
		t.Fatalf("bolt.Update: %v", err)
	}
	return path
}

func TestLookup_found(t *testing.T) {
	dir := t.TempDir()
	path := buildTestDB(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	advs, err := r.Lookup("debian 12", "curl")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(advs) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advs))
	}

	byID := map[string]Advisory{}
	for _, a := range advs {
		byID[a.VulnerabilityID] = a
	}
	a1 := byID["CVE-2024-0001"]
	if a1.FixedVersion != "7.88.1-10" {
		t.Errorf("FixedVersion: got %q, want 7.88.1-10", a1.FixedVersion)
	}
	if a1.Status != StatusFixed {
		t.Errorf("Status: got %d, want %d", a1.Status, StatusFixed)
	}
	a2 := byID["CVE-2024-0002"]
	if a2.Status != StatusWillNotFix {
		t.Errorf("Status a2: got %d, want %d", a2.Status, StatusWillNotFix)
	}
}

func TestLookup_missingPlatform(t *testing.T) {
	dir := t.TempDir()
	path := buildTestDB(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	advs, err := r.Lookup("debian 11", "curl")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("expected empty, got %d advisories", len(advs))
	}
}

func TestLookup_missingPackage(t *testing.T) {
	dir := t.TempDir()
	path := buildTestDB(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	advs, err := r.Lookup("debian 12", "openssl")
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 0 {
		t.Errorf("expected empty, got %d advisories", len(advs))
	}
}

func TestLookupVuln_found(t *testing.T) {
	dir := t.TempDir()
	path := buildTestDB(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	detail, err := r.LookupVuln("CVE-2024-0001")
	if err != nil {
		t.Fatalf("LookupVuln: %v", err)
	}
	if detail == nil {
		t.Fatal("expected detail, got nil")
	}
	if detail.SeverityV3 != SeverityCritical {
		t.Errorf("SeverityV3: got %d, want %d", detail.SeverityV3, SeverityCritical)
	}
	if detail.CvssScoreV3 != 9.8 {
		t.Errorf("CvssScoreV3: got %v, want 9.8", detail.CvssScoreV3)
	}
	if detail.Title != "curl: heap overflow" {
		t.Errorf("Title: got %q", detail.Title)
	}
}

func TestLookupVuln_missing(t *testing.T) {
	dir := t.TempDir()
	path := buildTestDB(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	detail, err := r.LookupVuln("CVE-9999-9999")
	if err != nil {
		t.Fatal(err)
	}
	if detail != nil {
		t.Errorf("expected nil for missing vuln, got %+v", detail)
	}
}

func TestListPlatforms(t *testing.T) {
	dir := t.TempDir()
	path := buildTestDB(t, dir)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	platforms, err := r.ListPlatforms()
	if err != nil {
		t.Fatal(err)
	}
	if len(platforms) != 1 || platforms[0] != "debian 12" {
		t.Errorf("platforms: got %v, want [debian 12]", platforms)
	}
}

func TestSeverityString(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityUnknown, ""},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestIsLoaded_nilReader(t *testing.T) {
	var r *Reader
	if r.IsLoaded() {
		t.Error("nil Reader.IsLoaded() should be false")
	}
}

func TestEnsureDB_cacheHit(t *testing.T) {

	dir := t.TempDir()
	buildTestDB(t, dir)

	meta := &dbMeta{FetchedAt: time.Now().UTC()}
	b, _ := json.Marshal(meta)
	_ = os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644)

	got, _, err := EnsureDB(context.Background(), nil, dir, "")
	if err != nil {
		t.Fatalf("EnsureDB: %v", err)
	}
	if got != filepath.Join(dir, "trivy.db") {
		t.Errorf("got path %q, want %q", got, filepath.Join(dir, "trivy.db"))
	}
}
