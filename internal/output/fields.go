package output

import (
	"reflect"
	"strings"
)

func splitNameVer(s string) (name, version string) {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func stringField(v reflect.Value, n string) string {
	f := v.FieldByName(n)
	if !f.IsValid() {
		return ""
	}
	if f.Kind() == reflect.String {
		return f.String()
	}
	return ""
}

func intField(v reflect.Value, n string) int {
	f := v.FieldByName(n)
	if !f.IsValid() {
		return 0
	}
	if f.Kind() >= reflect.Int && f.Kind() <= reflect.Int64 {
		return int(f.Int())
	}
	return 0
}

func stringMatrixField(v reflect.Value, n string) [][]string {
	f := v.FieldByName(n)
	if !f.IsValid() || f.Kind() != reflect.Slice {
		return nil
	}
	out := make([][]string, 0, f.Len())
	for i := 0; i < f.Len(); i++ {
		inner := f.Index(i)
		if inner.Kind() != reflect.Slice {
			continue
		}
		row := make([]string, 0, inner.Len())
		for j := 0; j < inner.Len(); j++ {
			if e := inner.Index(j); e.Kind() == reflect.String {
				row = append(row, e.String())
			}
		}
		out = append(out, row)
	}
	return out
}

func relevantField(v reflect.Value, n string) (value bool, known bool) {
	f := v.FieldByName(n)
	if !f.IsValid() || f.Kind() != reflect.Ptr || f.IsNil() {
		return false, false
	}
	e := f.Elem()
	if e.Kind() != reflect.Bool {
		return false, false
	}
	return e.Bool(), true
}

func boolNested(v reflect.Value, parent, child string) bool {
	p := v.FieldByName(parent)
	if !p.IsValid() {
		return false
	}
	f := p.FieldByName(child)
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return false
	}
	return f.Bool()
}
