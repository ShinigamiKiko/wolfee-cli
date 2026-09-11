package output

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type SARIF struct{}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	CodeFlows  []sarifCodeFlow `json:"codeFlows,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *sarifMessage          `json:"message,omitempty"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
	Kinds    []string      `json:"kinds,omitempty"`
}

func (SARIF) Render(w io.Writer, report any) error {
	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	rulesByID := map[string]sarifRule{}
	var results []sarifResult

	v := reflect.Indirect(reflect.ValueOf(report))
	components := v.FieldByName("Components")
	if !components.IsValid() {

		doc.Runs = []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "wolfee"}}}}
		return encodeJSON(w, doc)
	}

	for i := 0; i < components.Len(); i++ {
		c := components.Index(i)
		pkgName := stringField(c, "Name")
		pkgVer := stringField(c, "Version")
		pkgEco := strings.ToLower(stringField(c, "System"))
		pkgLabel := fmt.Sprintf("%s/%s@%s", pkgEco, pkgName, pkgVer)

		origin := stringField(c, "Origin")
		packageProps := func() map[string]any {
			if origin == "" {
				return nil
			}
			return map[string]any{"origin": origin}
		}

		if mal := c.FieldByName("Malware"); mal.IsValid() && mal.FieldByName("Found").Bool() {
			id := stringField(mal, "ID")
			if id == "" {
				id = "WOLFEE-MALWARE"
			}
			ref := stringField(mal, "Reference")
			if _, ok := rulesByID[id]; !ok {
				rulesByID[id] = sarifRule{
					ID:               id,
					Name:             "MaliciousPackage",
					ShortDescription: sarifMessage{Text: "Malicious package - confirmed in OSV / OSSF malicious-packages"},
					HelpURI:          ref,
					Properties:       map[string]any{"security-severity": "10.0", "cwe": "CWE-506"},
				}
			}
			results = append(results, sarifResult{
				RuleID:     id,
				Level:      "error",
				Message:    sarifMessage{Text: fmt.Sprintf("Malicious package %s - %s", pkgLabel, stringField(mal, "Summary"))},
				Locations:  []sarifLocation{{LogicalLocations: []sarifLogicalLocation{{Name: pkgLabel, Kind: "package"}}}},
				Properties: packageProps(),
			})
		}

		vulns := c.FieldByName("Vulnerabilities")
		if !vulns.IsValid() {
			continue
		}
		for vi := 0; vi < vulns.Len(); vi++ {
			vv := vulns.Index(vi)
			id := stringField(vv, "ID")
			if id == "" {
				continue
			}
			if _, ok := rulesByID[id]; !ok {
				rulesByID[id] = buildRule(vv)
			}
			results = append(results, sarifResult{
				RuleID:     id,
				Level:      sarifLevel(stringField(vv, "Severity")),
				Message:    sarifMessage{Text: vulnMessage(id, pkgLabel, vv)},
				Locations:  buildLocations(pkgLabel, vv),
				CodeFlows:  buildCodeFlows(vv),
				Properties: mergeProperties(packageProps(), resultProps(vv)),
			})
		}
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}

	doc.Runs = []sarifRun{{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "wolfee",
			InformationURI: "https://github.com/ShinigamiKiko/wolfee-cli",
			Rules:          rules,
		}},
		Results: results,
	}}
	return encodeJSON(w, doc)
}

func resultProps(v reflect.Value) map[string]any {
	props := map[string]any{}
	if reachable := stringField(v, "Reachable"); reachable != "" {
		props["reachability"] = reachable
	}
	return props
}

func mergeProperties(groups ...map[string]any) map[string]any {
	merged := map[string]any{}
	for _, group := range groups {
		for key, value := range group {
			merged[key] = value
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func buildLocations(pkgLabel string, v reflect.Value) []sarifLocation {
	location := sarifLocation{
		LogicalLocations: []sarifLogicalLocation{{Name: pkgLabel, Kind: "package"}},
	}
	file, line := parseCallSite(stringField(v, "CallSite"))
	if file != "" && line > 0 {
		location.PhysicalLocation = &sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: file},
			Region:           sarifRegion{StartLine: line},
		}
	}
	return []sarifLocation{location}
}

func buildCodeFlows(v reflect.Value) []sarifCodeFlow {
	file, line := parseCallSite(stringField(v, "CallSite"))
	if file == "" || line <= 0 {
		return nil
	}
	message := stringField(v, "CallLine")
	if message == "" {
		message = fmt.Sprintf("vulnerable call site: %s:%d", file, line)
	}
	return []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{{Locations: []sarifThreadFlowLocation{{
		Location: sarifLocation{
			PhysicalLocation: &sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: file},
				Region:           sarifRegion{StartLine: line},
			},
			Message: &sarifMessage{Text: message},
		},
		Kinds: []string{"call-site"},
	}}}}}}
}

func parseCallSite(callSite string) (string, int) {
	callSite = strings.TrimSpace(callSite)
	separator := strings.LastIndex(callSite, ":")
	if separator <= 0 || separator == len(callSite)-1 {
		return "", 0
	}
	line, err := strconv.Atoi(callSite[separator+1:])
	if err != nil || line <= 0 {
		return "", 0
	}
	return callSite[:separator], line
}

func buildRule(v reflect.Value) sarifRule {
	id := stringField(v, "ID")
	summary := stringField(v, "Summary")
	if summary == "" {
		summary = id
	}
	props := map[string]any{}

	if f := v.FieldByName("CVSS"); f.IsValid() && f.Kind() == reflect.Float64 && f.Float() > 0 {
		props["security-severity"] = fmt.Sprintf("%.1f", f.Float())
	} else {
		props["security-severity"] = sevToScoreString(stringField(v, "Severity"))
	}

	if vec := stringField(v, "CVSSVector"); vec != "" {
		props["cvss-vector"] = vec
	}
	if src := stringField(v, "SeveritySource"); src != "" {
		props["severity-source"] = src
	}
	if k := v.FieldByName("InKEV"); k.IsValid() && k.Kind() == reflect.Bool && k.Bool() {
		props["kev"] = true
	}
	if ds := distroStatusProps(v); len(ds) > 0 {
		props["distro-status"] = ds
	}
	return sarifRule{
		ID:               id,
		Name:             "Vulnerability",
		ShortDescription: sarifMessage{Text: truncate(summary, 200)},
		HelpURI:          stringField(v, "Reference"),
		Properties:       props,
	}
}

func distroStatusProps(v reflect.Value) []string {
	f := v.FieldByName("DistroStatus")
	if !f.IsValid() || f.Kind() != reflect.Slice || f.Len() == 0 {
		return nil
	}
	out := make([]string, 0, f.Len())
	for i := 0; i < f.Len(); i++ {
		st := f.Index(i)
		distro := stringField(st, "Distro")
		release := stringField(st, "Release")
		status := stringField(st, "Status")
		fix := stringField(st, "FixVersion")
		key := distro
		if release != "" {
			key += ":" + release
		}
		row := key + "=" + status
		if fix != "" {
			row += "@" + fix
		}
		out = append(out, row)
	}
	return out
}

func vulnMessage(id, pkg string, v reflect.Value) string {
	sev := stringField(v, "Severity")
	cve := stringField(v, "CVE")
	parts := []string{fmt.Sprintf("%s in %s", id, pkg)}
	if sev != "" {
		parts = append(parts, fmt.Sprintf("severity=%s", sev))
	}
	if cve != "" && cve != id {
		parts = append(parts, fmt.Sprintf("cve=%s", cve))
	}
	if k := v.FieldByName("InKEV"); k.IsValid() && k.Kind() == reflect.Bool && k.Bool() {
		parts = append(parts, "KEV")
	}
	if fixed := v.FieldByName("Fixed"); fixed.IsValid() && fixed.Kind() == reflect.Slice && fixed.Len() > 0 {
		parts = append(parts, fmt.Sprintf("fixed=%s", fixed.Index(0).String()))
	}
	return strings.Join(parts, " - ")
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "note"
	}
}

func sevToScoreString(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "7.5"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "2.5"
	default:
		return "0.0"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
