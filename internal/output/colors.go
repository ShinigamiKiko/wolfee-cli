package output

import "strings"

type colors struct{ on bool }

func newColors(on bool) colors { return colors{on: on} }

func (c colors) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (c colors) bold(s string) string  { return c.wrap("1", s) }
func (c colors) crit(s string) string  { return c.wrap("1;31", s) }
func (c colors) high(s string) string  { return c.wrap("31", s) }
func (c colors) med(s string) string   { return c.wrap("33", s) }
func (c colors) low(s string) string   { return c.wrap("36", s) }
func (c colors) green(s string) string { return c.wrap("32", s) }

func (c colors) sev(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return c.crit("CRIT")
	case "HIGH":
		return c.high("HIGH")
	case "MEDIUM":
		return c.med("MED ")
	case "LOW":
		return c.low("LOW ")
	default:
		return "    "
	}
}

// license colours a license label by production risk: red for strong/network
// copyleft or non-commercial terms, yellow for weak copyleft.
func (c colors) license(label, risk string) string {
	if label == "" {
		return "-"
	}
	switch risk {
	case "high":
		return c.crit(label)
	case "medium":
		return c.med(label)
	case "unknown":
		return c.low(label)
	}
	return label
}

func (c colors) origin(label string) string {
	switch label {
	case "APP", "APP(T)":
		return c.med(label)
	case "", "-":
		return label
	default:
		return c.low(label)
	}
}

func (c colors) lang(label string, relevant, known bool) string {
	if label == "" {
		return label
	}
	if !known {
		return c.low(label)
	}
	if relevant {
		return c.green(label)
	}
	return c.high(label)
}
