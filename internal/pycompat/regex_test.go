package pycompat

import "testing"

func TestCompileRegexPythonFeatures(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		source  string
		want    bool
	}{
		{name: "numeric backreference", pattern: `(a)\1`, source: "aa", want: true},
		{name: "lookahead", pattern: `(?=a)a`, source: "abc", want: true},
		{name: "fixed lookbehind", pattern: `a(?<=a)b`, source: "ab", want: true},
		{name: "named backreference", pattern: `(?P<word>a)(?P=word)`, source: "aa", want: true},
		{name: "absolute end anchor matches end", pattern: `a\Z`, source: "a", want: true},
		{name: "absolute end anchor rejects trailing newline", pattern: `a\Z`, source: "a\n", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			re, err := CompileRegex(tc.pattern, true)
			if err != nil {
				t.Fatal(err)
			}
			match, err := re.FindStringMatchStartingAt(tc.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			got := match != nil && match.Index == 0
			if got != tc.want {
				t.Fatalf("match=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompileRegexRejectsPythonInvalidPatterns(t *testing.T) {
	tests := []string{
		`(?<=a+)b`,
		`(?<=a|bc)d`,
		`(?>a)`,
		`\z`,
		`(?-i)i`,
	}
	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			if _, err := CompileRegex(pattern, true); err == nil {
				t.Fatalf("CompileRegex(%q) unexpectedly succeeded", pattern)
			}
		})
	}
}
