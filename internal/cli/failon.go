package cli

import (
	"sca-go/cli/internal/sbomscan"
	"strings"
)

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
func (e *exitError) ExitCode() int { return e.code }

func evalFailOn(level string, r *sbomscan.Report) int {
	threshold := failOnThreshold(level)
	if threshold == 0 {
		return 0
	}
	worst := 0
	for _, c := range r.Components {
		if c.Malware.Found {
			if 4 > worst {
				worst = 4
			}
		}
		if rank := severityRank(c.TopSeverity); rank > worst {
			worst = rank
		}
	}
	if worst >= threshold {
		return 2
	}
	return 0
}

func failOnThreshold(level string) int {
	switch strings.ToLower(level) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
