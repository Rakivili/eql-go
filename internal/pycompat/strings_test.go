package pycompat

import "testing"

func TestLowerPythonSpecialCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "CMD", want: "cmd"},
		{in: "\u0130", want: "i\u0307"},
		{in: "I", want: "i"},
		{in: "\u039f\u03a3", want: "\u03bf\u03c2"},
		{in: "\u03a3\u03a3", want: "\u03c3\u03c2"},
		{in: "\u03a3", want: "\u03c3"},
		{in: "\u039f\u0301\u03a3", want: "\u03bf\u0301\u03c2"},
	}
	for _, tc := range cases {
		if got := Lower(tc.in); got != tc.want {
			t.Fatalf("Lower(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}
