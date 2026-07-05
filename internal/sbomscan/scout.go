package sbomscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func scoutBaseRef(ctx context.Context, image string) (string, error) {
	if strings.TrimSpace(image) == "" {
		return "", errors.New("docker scout: empty image reference")
	}

	cmd := exec.CommandContext(ctx, "docker", "scout", "quickview", image)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker scout quickview failed (%v) - %s", err, tail(out.String()))
	}
	ref := parseScoutBaseImage(out.String())
	if ref == "" {
		return "", errors.New("docker scout did not report a base image - scan by a repo:tag (not a bare image ID), make sure the scout plugin is installed and you are logged in (docker login); a private/unknown base scout can't name has no base-vs-app attribution")
	}
	return ref, nil
}

var (
	scoutANSIRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

	refTokenRe = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9._\-/:]*(?:@sha256:[0-9a-f]{7,64})?$`)

	versionRe = regexp.MustCompile(`^[0-9][0-9.]*$`)
)

func parseScoutBaseImage(s string) string {
	for _, raw := range strings.Split(s, "\n") {
		line := scoutANSIRe.ReplaceAllString(raw, "")
		i := strings.Index(strings.ToLower(line), "base image")
		if i < 0 {
			continue
		}
		rest := line[i+len("base image"):]
		rest = strings.ReplaceAll(rest, "│", " ")
		rest = strings.ReplaceAll(rest, "|", " ")
		for _, tok := range strings.Fields(rest) {
			if tok == "→" || tok == "->" {
				break
			}
			if isImageRef(tok) {
				return tok
			}
		}
	}
	return ""
}

func isImageRef(tok string) bool {
	if strings.Contains(tok, "://") {
		return false
	}
	if !strings.ContainsAny(tok, "/:") {
		return false
	}
	if !refTokenRe.MatchString(tok) {
		return false
	}
	return !versionRe.MatchString(tok)
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	const max = 300
	if len(s) > max {
		s = "..." + s[len(s)-max:]
	}
	return strings.ReplaceAll(s, "\n", " | ")
}
