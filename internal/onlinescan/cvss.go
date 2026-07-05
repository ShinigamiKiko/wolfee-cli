package onlinescan

import (
	"math"
	"strings"
)

func scoreCVSSVector(s string) (score float64, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ""
	}

	if strings.HasPrefix(s, "CVSS:") {

		end := strings.Index(s, "/")
		if end < 0 {
			return 0, ""
		}
		head := s[:end]
		body := s[end+1:]
		switch head {
		case "CVSS:3.0", "CVSS:3.1":
			return scoreV3(body), head
		case "CVSS:4.0":
			return scoreV4(body), head
		default:
			return 0, ""
		}
	}

	v2 := strings.Trim(s, "()")
	if score = scoreV2(v2); score > 0 {
		return score, "CVSS:2.0"
	}
	return 0, ""
}

func parseMetrics(body string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(body, "/") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
}

func roundUp1(x float64) float64 {
	return math.Ceil(x*10) / 10
}

func scoreV3(body string) float64 {
	m := parseMetrics(body)
	av, ok := v3AV[m["AV"]]
	if !ok {
		return 0
	}
	ac, ok := v3AC[m["AC"]]
	if !ok {
		return 0
	}
	ui, ok := v3UI[m["UI"]]
	if !ok {
		return 0
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0
	}
	pr, ok := v3PR(m["PR"], scope)
	if !ok {
		return 0
	}
	c, ok := v3CIA[m["C"]]
	if !ok {
		return 0
	}
	i, ok := v3CIA[m["I"]]
	if !ok {
		return 0
	}
	a, ok := v3CIA[m["A"]]
	if !ok {
		return 0
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploit := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0
	}
	var base float64
	if scope == "U" {
		base = math.Min(impact+exploit, 10)
	} else {
		base = math.Min(1.08*(impact+exploit), 10)
	}
	return roundUp1(base)
}

var v3AV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
var v3AC = map[string]float64{"L": 0.77, "H": 0.44}
var v3UI = map[string]float64{"N": 0.85, "R": 0.62}
var v3CIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

func v3PR(pr, scope string) (float64, bool) {
	switch pr {
	case "N":
		return 0.85, true
	case "L":
		if scope == "C" {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scope == "C" {
			return 0.50, true
		}
		return 0.27, true
	}
	return 0, false
}

func scoreV2(body string) float64 {
	m := parseMetrics(body)
	av, ok := v2AV[m["AV"]]
	if !ok {
		return 0
	}
	ac, ok := v2AC[m["AC"]]
	if !ok {
		return 0
	}
	au, ok := v2Au[m["Au"]]
	if !ok {
		return 0
	}
	c, ok := v2CIA[m["C"]]
	if !ok {
		return 0
	}
	i, ok := v2CIA[m["I"]]
	if !ok {
		return 0
	}
	a, ok := v2CIA[m["A"]]
	if !ok {
		return 0
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	exploit := 20 * av * ac * au
	fImpact := 1.176
	if impact == 0 {
		fImpact = 0
	}
	base := ((0.6 * impact) + (0.4 * exploit) - 1.5) * fImpact
	if base < 0 {
		base = 0
	}
	if base > 10 {
		base = 10
	}

	return math.Round(base*10) / 10
}

var v2AV = map[string]float64{"N": 1.0, "A": 0.646, "L": 0.395}
var v2AC = map[string]float64{"L": 0.71, "M": 0.61, "H": 0.35}
var v2Au = map[string]float64{"N": 0.704, "S": 0.56, "M": 0.45}
var v2CIA = map[string]float64{"N": 0, "P": 0.275, "C": 0.660}

func scoreV4(body string) float64 {
	m := parseMetrics(body)
	if _, ok := v4AV[m["AV"]]; !ok {
		return 0
	}

	severe := 0
	if m["AV"] == "N" {
		severe += 2
	} else if m["AV"] == "A" {
		severe++
	}
	if m["AC"] == "L" {
		severe++
	}
	if m["AT"] == "N" {
		severe++
	}
	if m["PR"] == "N" {
		severe += 2
	} else if m["PR"] == "L" {
		severe++
	}
	if m["UI"] == "N" {
		severe++
	}
	highImpact := 0
	for _, k := range []string{"VC", "VI", "VA"} {
		if m[k] == "H" {
			highImpact++
		}
	}
	subImpact := 0
	for _, k := range []string{"SC", "SI", "SA"} {
		if m[k] == "H" {
			subImpact++
		}
	}
	switch {
	case highImpact == 3 && severe >= 5:
		return 9.8
	case highImpact >= 2 && severe >= 4:
		return 8.1
	case highImpact >= 1 && severe >= 3:
		return 6.5
	case highImpact >= 1 || subImpact >= 1:
		return 4.3
	case severe >= 2:
		return 2.0
	}
	return 0
}

var v4AV = map[string]struct{}{"N": {}, "A": {}, "L": {}, "P": {}}

func ScoreCVSSVector(s string) (score float64, version string) {
	return scoreCVSSVector(s)
}

func SeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	case score > 0:
		return SevLow
	}
	return ""
}
