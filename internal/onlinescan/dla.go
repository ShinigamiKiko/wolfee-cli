package onlinescan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"sca-go/cli/internal/onlinescan/feedcache"
)

const (
	dlaListPrimary  = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list"
	dlaListFallback = "https://security-tracker.debian.org/tracker/data/DLA/list"
	dsaListPrimary  = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list"
	dsaListFallback = "https://security-tracker.debian.org/tracker/data/DSA/list"
)

func dlaFeed() feedcache.Feed {
	return feedcache.Feed{
		Name:         "dla-list",
		URL:          dlaListPrimary,
		FallbackURLs: []string{dlaListFallback},
		TTL:          24 * time.Hour,
	}
}

func dsaFeed() feedcache.Feed {
	return feedcache.Feed{
		Name:         "dsa-list",
		URL:          dsaListPrimary,
		FallbackURLs: []string{dsaListFallback},
		TTL:          24 * time.Hour,
	}
}

type dlaFix struct {
	Advisory     string
	CVEs         []string
	FixedVersion string
}

type dlaIndex struct {
	mu           sync.RWMutex
	loaded       bool
	byCVE        map[string][]string
	byAdvisory   map[string][]string
	byPkgRelease map[string]map[string][]dlaFix
	loadOnce     sync.Once
	loadErr      error
}

func newDLAIndex() *dlaIndex {
	return &dlaIndex{
		byCVE:        map[string][]string{},
		byAdvisory:   map[string][]string{},
		byPkgRelease: map[string]map[string][]dlaFix{},
	}
}

func (d *dlaIndex) Load(ctx context.Context, src feedcache.Source) error {
	d.loadOnce.Do(func() {
		byCVE := map[string][]string{}
		byAdvisory := map[string][]string{}
		byPkgRelease := map[string]map[string][]dlaFix{}
		for _, feed := range []feedcache.Feed{dlaFeed(), dsaFeed()} {
			body, err := src.Open(ctx, feed)
			if err != nil {
				if d.loadErr == nil {
					d.loadErr = err
				}
				continue
			}
			b, rerr := readPlainTextCapped(body)
			body.Close()
			if rerr != nil {
				if d.loadErr == nil {
					d.loadErr = fmt.Errorf("%s: %w", feed.Name, rerr)
				}
				continue
			}
			if perr := parseDLAList(b, byCVE, byAdvisory, byPkgRelease); perr != nil {
				if d.loadErr == nil {
					d.loadErr = fmt.Errorf("%s: parse: %w", feed.Name, perr)
				}
			}
		}
		d.mu.Lock()
		d.byCVE = byCVE
		d.byAdvisory = byAdvisory
		d.byPkgRelease = byPkgRelease
		d.loaded = true
		d.mu.Unlock()
	})
	return d.loadErr
}

func readPlainTextCapped(body io.Reader) ([]byte, error) {
	const cap = 32 << 20
	b, err := io.ReadAll(io.LimitReader(body, cap+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(b) > cap {
		return nil, fmt.Errorf("list exceeds %d MiB cap", cap>>20)
	}
	return b, nil
}

func (d *dlaIndex) LookupAdvisory(adv string) []string {
	if d == nil || adv == "" {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.loaded {
		return nil
	}
	cves := d.byAdvisory[adv]
	if len(cves) == 0 {
		return nil
	}
	out := make([]string, len(cves))
	copy(out, cves)
	return out
}

func (d *dlaIndex) LookupCVE(cve string) []string {
	if d == nil || cve == "" {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.loaded {
		return nil
	}
	ids := d.byCVE[cve]
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, len(ids))
	copy(out, ids)
	return out
}

var (
	dlaHeaderPattern = regexp.MustCompile(`^\[[^\]]+\]\s+((?:DLA|DSA)-[0-9]+(?:-[0-9]+)?)\b`)

	cveTokenPattern = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)

	dlaFixLinePattern = regexp.MustCompile(`^\s+\[([a-z][a-z0-9-]*)\]\s+-\s+(\S+)\s+(\S+)`)
)

func (d *dlaIndex) Stats() (pkgs, fixes int) {
	if d == nil {
		return
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	pkgs = len(d.byPkgRelease)
	for _, byRel := range d.byPkgRelease {
		for _, fs := range byRel {
			fixes += len(fs)
		}
	}
	return
}

func (d *dlaIndex) LookupPackageFixes(sourcePkg, release string) []dlaFix {
	if d == nil || sourcePkg == "" || release == "" {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.loaded {
		return nil
	}
	byRel := d.byPkgRelease[sourcePkg]
	if byRel == nil {
		return nil
	}
	fixes := byRel[strings.ToLower(strings.TrimSpace(release))]
	if len(fixes) == 0 {
		return nil
	}
	out := make([]dlaFix, len(fixes))
	copy(out, fixes)
	return out
}

type pendingFixLine struct {
	pkg, release, ver string
}

func parseDLAList(body []byte, byCVE, byAdvisory map[string][]string, byPkgRelease map[string]map[string][]dlaFix) error {
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var currentID string
	var pending []pendingFixLine
	for sc.Scan() {
		line := sc.Text()
		if m := dlaHeaderPattern.FindStringSubmatch(line); m != nil {

			if currentID != "" && len(pending) > 0 {
				flushPendingFixes(currentID, pending, byAdvisory, byPkgRelease)
			}
			currentID = m[1]
			pending = pending[:0]
			continue
		}
		if currentID == "" {
			continue
		}

		if m := dlaFixLinePattern.FindStringSubmatch(line); m != nil {
			release := strings.ToLower(strings.TrimSuffix(m[1], "-lts"))
			pkg := m[2]
			ver := m[3]

			if strings.HasPrefix(ver, "<") || pkg == "" || ver == "" {
				continue
			}
			cves := byAdvisory[currentID]
			if len(cves) == 0 {

				pending = append(pending, pendingFixLine{pkg: pkg, release: release, ver: ver})
				continue
			}
			recordFix(currentID, pkg, release, ver, cves, byPkgRelease)
			continue
		}

		hits := cveTokenPattern.FindAllString(line, -1)
		if len(hits) == 0 {
			continue
		}
		for _, cve := range hits {
			byCVE[cve] = appendUnique(byCVE[cve], currentID)
			if byAdvisory != nil {
				byAdvisory[currentID] = appendUnique(byAdvisory[currentID], cve)
			}
		}

		if len(pending) > 0 {
			cves := byAdvisory[currentID]
			if len(cves) > 0 {
				flushPendingFixes(currentID, pending, byAdvisory, byPkgRelease)
				pending = pending[:0]
			}
		}
	}

	if currentID != "" && len(pending) > 0 {
		flushPendingFixes(currentID, pending, byAdvisory, byPkgRelease)
	}
	return sc.Err()
}

func flushPendingFixes(advID string, pending []pendingFixLine, byAdvisory map[string][]string, byPkgRelease map[string]map[string][]dlaFix) {
	cves := byAdvisory[advID]
	for _, p := range pending {
		recordFix(advID, p.pkg, p.release, p.ver, cves, byPkgRelease)
	}
}

func recordFix(advID, pkg, release, ver string, cves []string, byPkgRelease map[string]map[string][]dlaFix) {
	fix := dlaFix{
		Advisory:     advID,
		CVEs:         append([]string(nil), cves...),
		FixedVersion: ver,
	}
	if byPkgRelease[pkg] == nil {
		byPkgRelease[pkg] = map[string][]dlaFix{}
	}
	byPkgRelease[pkg][release] = append(byPkgRelease[pkg][release], fix)
}
