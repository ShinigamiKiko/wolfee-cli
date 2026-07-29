package onlinescan

import (
	"reflect"
	"testing"
)

func TestOrderFixesForVersion(t *testing.T) {
	tests := []struct {
		name      string
		fixes     []string
		installed string
		want      []string
	}{
		{
			name:      "selects current branch",
			fixes:     []string{"4.4.51", "5.4.31"},
			installed: "5.4.3",
			want:      []string{"5.4.31", "4.4.51"},
		},
		{
			name:      "selects wildcard branch",
			fixes:     []string{"1.44.8", "3.14.x"},
			installed: "3.5.1",
			want:      []string{"3.14.x", "1.44.8"},
		},
		{
			name:      "keeps unknown formats unchanged",
			fixes:     []string{"8.5.52", "9.6.x"},
			installed: "9.5.16+deb",
			want:      []string{"8.5.52", "9.6.x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orderFixesForVersion(tt.fixes, tt.installed); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("orderFixesForVersion(%v, %q) = %v; want %v", tt.fixes, tt.installed, got, tt.want)
			}
		})
	}
}

func TestPURLVersion(t *testing.T) {
	if got := purlVersion("pkg:composer/symfony/twig-bridge@v5.4.3?download_url=x"); got != "v5.4.3" {
		t.Fatalf("purlVersion() = %q; want v5.4.3", got)
	}
	if got := purlVersion("pkg:npm/lodash"); got != "" {
		t.Fatalf("purlVersion() = %q; want empty", got)
	}
}
