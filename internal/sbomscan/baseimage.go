package sbomscan

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"sca-go/cli/internal/trivy"
)

const (
	OriginBase    = "base"
	OriginApp     = "app"
	OriginUnknown = "unknown"

	// OriginImage is an OS package that ships in the image (rendered DEB/APK/
	// RPM(image)). OriginImageLib is a language library that rode in with the
	// image but is not one of your source dependencies (rendered LIB(image)).
	OriginImage    = "image"
	OriginImageLib = "image-lib"
)

const (
	labelBaseName   = "org.opencontainers.image.base.name"
	labelBaseDigest = "org.opencontainers.image.base.digest"
)

type baseAttribution struct {
	known bool
	ref   string
	set   map[string]bool
}

func (b baseAttribution) classify(layerDiffID string) string {
	if !b.known {
		return ""
	}
	if strings.TrimSpace(layerDiffID) == "" {
		return OriginUnknown
	}
	if b.set[layerDiffID] {
		return OriginBase
	}
	return OriginApp
}

func resolveBaseImage(ctx context.Context, o ImageOptions, tr *trivy.Report) baseAttribution {
	if !o.Scout {
		return baseAttribution{}
	}

	ref, srcLabel := localBaseRef(tr)
	if ref == "" {
		o.step(fmt.Sprintf("No local base signal; asking docker scout for the base image of %s", o.Image))
		r, err := scoutBaseRef(ctx, o.Image)
		if err != nil {
			o.warn("base-image attribution skipped: %v", err)
			return baseAttribution{}
		}
		ref, srcLabel = r, "docker scout"
	}

	appDiffIDs := tr.Metadata.DiffIDOrder()
	if len(appDiffIDs) == 0 {
		o.warn("base-image attribution skipped: scanned image exposes no layer DiffIDs (squashed image or unsupported trivy)")
		return baseAttribution{}
	}

	o.step(fmt.Sprintf("Resolving base image %s (%s) for layer attribution", ref, srcLabel))
	baseDiffIDs, err := baseLayerDiffIDs(ctx, o, ref)
	if err != nil {
		o.warn("base-image attribution skipped: could not resolve %s: %v", ref, err)
		return baseAttribution{}
	}

	set, ok := basePrefixSet(baseDiffIDs, appDiffIDs)
	if !ok {
		o.warn("base-image %q is not a prefix of the scanned image's layers (%s) - origin left unknown to avoid mislabeling", ref, srcLabel)
		return baseAttribution{}
	}
	o.step(fmt.Sprintf("Base image %s: %d of %d layers attributed to base", ref, len(set), len(appDiffIDs)))
	return baseAttribution{known: true, ref: ref, set: set}
}

func localBaseRef(tr *trivy.Report) (ref, source string) {

	labels := tr.Metadata.ImageConfig.Config.Labels
	if pinned := pinnedRef(strings.TrimSpace(labels[labelBaseName]), strings.TrimSpace(labels[labelBaseDigest])); pinned != "" {
		return pinned, "image base labels"
	}

	if ref := baseRefFromHistory(tr); ref != "" {
		return ref, "rootfs in image history"
	}
	return "", ""
}

var rootfsAddRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9]*)-(?:mini)?rootfs-(\d+(?:\.\d+)+)`)

func baseRefFromHistory(tr *trivy.Report) string {
	for _, h := range tr.Metadata.ImageConfig.History {
		if m := rootfsAddRe.FindStringSubmatch(h.CreatedBy); m != nil {
			return strings.ToLower(m[1]) + ":" + m[2]
		}
	}
	return ""
}

func pinnedRef(name, digest string) string {
	name = strings.TrimSpace(name)
	digest = strings.TrimSpace(digest)
	if name == "" {
		return ""
	}
	if digest == "" {
		return name
	}

	repo := name
	if at := strings.LastIndex(repo, "@"); at >= 0 {
		repo = repo[:at]
	}
	slash := strings.LastIndex(repo, "/")
	if colon := strings.LastIndex(repo, ":"); colon > slash {
		repo = repo[:colon]
	}
	return repo + "@" + digest
}

func basePrefixSet(baseDiffIDs, appDiffIDs []string) (map[string]bool, bool) {
	if len(baseDiffIDs) == 0 || len(baseDiffIDs) > len(appDiffIDs) {
		return nil, false
	}
	set := make(map[string]bool, len(baseDiffIDs))
	for i, d := range baseDiffIDs {
		if d == "" || d != appDiffIDs[i] {
			return nil, false
		}
		set[d] = true
	}
	return set, true
}

func baseLayerDiffIDs(ctx context.Context, o ImageOptions, ref string) ([]string, error) {
	rep, err := trivy.Scan(ctx, trivy.Options{
		Image:     ref,
		Platform:  o.Platform,
		Bin:       o.TrivyBin,
		ExtraArgs: o.TrivyExtraArgs,
		Logger:    o.Logger,
	})
	if err != nil {
		return nil, err
	}
	diffIDs := rep.Metadata.DiffIDOrder()
	if len(diffIDs) == 0 {
		return nil, fmt.Errorf("base image %s exposed no layer DiffIDs", ref)
	}
	return diffIDs, nil
}

func (o ImageOptions) step(msg string) {
	if o.Logger != nil {
		o.Logger.Step(msg)
	}
}

func (o ImageOptions) warn(format string, args ...any) {
	if o.Logger != nil {
		o.Logger.Warn(format, args...)
	}
}
