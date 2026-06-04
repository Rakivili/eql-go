package conformance

import (
	"context"
	"fmt"
	"strings"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestFoldingTOMLOracle(t *testing.T) {
	pythonRepo := foldingPythonRepo(t)
	cases, err := conf.LoadTOMLCases(context.Background(), pythonRepo, "test_folding.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases.Fold) == 0 {
		t.Fatal("no folding TOML cases loaded")
	}
	for i, tc := range cases.Fold {
		tc := tc
		t.Run(tomlCaseName(tc.File, tc.Group, i, tc.Expression), func(t *testing.T) {
			result, err := conf.CompareExpression(context.Background(), pythonRepo, tc.Expression, tc.CaseSensitive)
			if err != nil {
				t.Fatal(err)
			}
			if result.Python.Runtime != tc.Expected || result.Python.Folded != tc.Expected {
				t.Fatalf(
					"python fixture mismatch for %q\nexpected=%s\nruntime=%s\nfolded=%s",
					tc.Expression,
					tc.Expected,
					result.Python.Runtime,
					result.Python.Folded,
				)
			}
			if !result.Equal() {
				t.Fatalf(
					"expression mismatch for %q\npython runtime=%s folded=%s\ngo     runtime=%s folded=%s",
					tc.Expression,
					result.Python.Runtime,
					result.Python.Folded,
					result.Go.Runtime,
					result.Go.Folded,
				)
			}
		})
	}
}

func tomlCaseName(file string, group string, index int, expression string) string {
	name := fmt.Sprintf("%s/%s/%03d/%s", file, group, index, expression)
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '"', '\'', '\n', '\r', '\t':
			return '_'
		default:
			return r
		}
	}, name)
}
