package trivydb

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

type Advisory struct {
	VulnerabilityID string
	FixedVersion    string
	Status          Status

	Arches []string
}

type Status int

const (
	StatusUnknown            Status = 0
	StatusNotAffected        Status = 1
	StatusAffected           Status = 2
	StatusFixed              Status = 3
	StatusUnderInvestigation Status = 4
	StatusWillNotFix         Status = 5
	StatusFixDeferred        Status = 6
	StatusEndOfLife          Status = 7
)

type Severity int

const (
	SeverityUnknown  Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

type VulnDetail struct {
	Severity     Severity
	SeverityV3   Severity
	CvssScore    float64
	CvssVector   string
	CvssScoreV3  float64
	CvssVectorV3 string
	Title        string
	Description  string
}

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return ""
	}
}

type Reader struct {
	db *bolt.DB
}

func Open(path string) (*Reader, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("trivydb open %s: %w", path, err)
	}
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *Reader) IsLoaded() bool {
	return r != nil && r.db != nil
}

func (r *Reader) Lookup(platform, pkgName string) ([]Advisory, error) {
	if !r.IsLoaded() {
		return nil, nil
	}
	var out []Advisory
	err := r.db.View(func(tx *bolt.Tx) error {

		src := tx.Bucket([]byte(platform))
		if src == nil {

			root := tx.Bucket([]byte("advisory-detail"))
			if root == nil {
				return nil
			}
			src = root.Bucket([]byte(platform))
			if src == nil {
				return nil
			}
		}
		pkg := src.Bucket([]byte(pkgName))
		if pkg == nil {
			return nil
		}
		return pkg.ForEach(func(k, v []byte) error {
			var raw rawAdvisory
			if err := json.Unmarshal(v, &raw); err != nil {
				return nil
			}
			out = append(out, Advisory{
				VulnerabilityID: string(k),
				FixedVersion:    raw.FixedVersion,
				Status:          Status(raw.Status),
				Arches:          raw.Arches,
			})
			return nil
		})
	})
	return out, err
}

func (r *Reader) LookupVuln(vulnID string) (*VulnDetail, error) {
	if !r.IsLoaded() {
		return nil, nil
	}
	var out *VulnDetail
	err := r.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("vulnerability"))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(vulnID))
		if v == nil {
			return nil
		}
		var raw rawVuln
		if err := json.Unmarshal(v, &raw); err != nil {
			return err
		}
		out = &VulnDetail{
			Severity:     Severity(raw.Severity),
			SeverityV3:   Severity(raw.SeverityV3),
			CvssScore:    raw.CvssScore,
			CvssVector:   raw.CvssVector,
			CvssScoreV3:  raw.CvssScoreV3,
			CvssVectorV3: raw.CvssVectorV3,
			Title:        raw.Title,
			Description:  raw.Description,
		}
		return nil
	})
	return out, err
}

func (r *Reader) ListPackages(platform string, n int, fn func(string)) {
	if !r.IsLoaded() {
		return
	}
	_ = r.db.View(func(tx *bolt.Tx) error {
		src := tx.Bucket([]byte(platform))
		if src == nil {
			if root := tx.Bucket([]byte("advisory-detail")); root != nil {
				src = root.Bucket([]byte(platform))
			}
		}
		if src == nil {
			return nil
		}
		count := 0
		return src.ForEach(func(k, v []byte) error {
			if count >= n {
				return fmt.Errorf("stop")
			}
			if v == nil {
				fn(string(k))
				count++
			}
			return nil
		})
	})
}

func (r *Reader) ListTopBuckets() ([]string, error) {
	if !r.IsLoaded() {
		return nil, nil
	}
	var out []string
	err := r.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			out = append(out, string(name))
			return nil
		})
	})
	return out, err
}

var nonPlatformBuckets = map[string]bool{
	"vulnerability": true,
	"data-source":   true,
	"echo":          true,
}

func (r *Reader) ListPlatforms() ([]string, error) {
	if !r.IsLoaded() {
		return nil, nil
	}
	var out []string
	err := r.db.View(func(tx *bolt.Tx) error {

		if root := tx.Bucket([]byte("advisory-detail")); root != nil {
			return root.ForEach(func(k, v []byte) error {
				if v == nil {
					out = append(out, string(k))
				}
				return nil
			})
		}

		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			n := string(name)
			if !nonPlatformBuckets[n] {
				out = append(out, n)
			}
			return nil
		})
	})
	return out, err
}

type rawAdvisory struct {
	FixedVersion    string   `json:"FixedVersion"`
	AffectedVersion string   `json:"AffectedVersion,omitempty"`
	Status          int      `json:"Status,omitempty"`
	Arches          []string `json:"Arches,omitempty"`
	VendorIDs       []string `json:"VendorIDs,omitempty"`
}

type rawVuln struct {
	CvssScore    float64 `json:"CvssScore,omitempty"`
	CvssVector   string  `json:"CvssVector,omitempty"`
	CvssScoreV3  float64 `json:"CvssScoreV3,omitempty"`
	CvssVectorV3 string  `json:"CvssVectorV3,omitempty"`
	Severity     int     `json:"Severity,omitempty"`
	SeverityV3   int     `json:"SeverityV3,omitempty"`
	Title        string  `json:"Title,omitempty"`
	Description  string  `json:"Description,omitempty"`
}
