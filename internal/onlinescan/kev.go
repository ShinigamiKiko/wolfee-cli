package onlinescan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"sca-go/cli/internal/onlinescan/feedcache"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

func kevFeed() feedcache.Feed {
	return feedcache.Feed{
		Name: "kev",
		URL:  kevURL,
		TTL:  24 * time.Hour,
	}
}

type kevDoc struct {
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

type kevSet struct {
	once sync.Once
	set  map[string]struct{}
	err  error
}

func newKEVSet() *kevSet { return &kevSet{} }

func (k *kevSet) Load(ctx context.Context, src feedcache.Source) error {
	k.once.Do(func() {
		body, err := src.Open(ctx, kevFeed())
		if err != nil {
			k.err = fmt.Errorf("kev: %w", err)
			return
		}
		defer body.Close()

		const cap = 8 << 20
		b, err := io.ReadAll(io.LimitReader(body, cap+1))
		if err != nil {
			k.err = fmt.Errorf("kev read: %w", err)
			return
		}
		if len(b) > cap {
			k.err = fmt.Errorf("kev: body exceeds %d MiB cap", cap>>20)
			return
		}
		var doc kevDoc
		if err := json.Unmarshal(b, &doc); err != nil {
			k.err = fmt.Errorf("kev decode: %w", err)
			return
		}
		k.set = make(map[string]struct{}, len(doc.Vulnerabilities))
		for _, v := range doc.Vulnerabilities {
			if v.CveID != "" {
				k.set[v.CveID] = struct{}{}
			}
		}
	})
	return k.err
}

func (k *kevSet) Has(cve string) bool {
	if k == nil || k.set == nil || cve == "" {
		return false
	}
	_, ok := k.set[cve]
	return ok
}
