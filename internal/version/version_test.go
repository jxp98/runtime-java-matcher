package version

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		left  string
		right string
		want  int
	}{
		{"2.14.1", "2.15.0", -1},
		{"2.15.0", "2.15.0", 0},
		{"2.17.1", "2.16.0", 1},
		{"1.0.0-RC1", "1.0.0", -1},
		{"1.0.0", "1.0.0-sp1", -1},
	}

	for _, tc := range cases {
		got := Compare(tc.left, tc.right)
		if tc.want < 0 && got >= 0 {
			t.Fatalf("Compare(%q,%q)=%d, want negative", tc.left, tc.right, got)
		}
		if tc.want == 0 && got != 0 {
			t.Fatalf("Compare(%q,%q)=%d, want 0", tc.left, tc.right, got)
		}
		if tc.want > 0 && got <= 0 {
			t.Fatalf("Compare(%q,%q)=%d, want positive", tc.left, tc.right, got)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		version    string
		constraint string
		want       bool
	}{
		{"2.14.1", ">=2.0,<2.15.0", true},
		{"2.15.0", ">=2.0,<2.15.0", false},
		{"5.3.17", ">=5.3.0,<5.3.18", true},
		{"5.3.18", ">=5.3.0,<5.3.18", false},
		{"1.2.3", "1.2.3||2.0.0", true},
	}

	for _, tc := range cases {
		if got := Match(tc.version, tc.constraint); got != tc.want {
			t.Fatalf("Match(%q,%q)=%v, want %v", tc.version, tc.constraint, got, tc.want)
		}
	}
}
