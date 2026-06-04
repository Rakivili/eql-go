package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestStringFunctionsTOMLOracle(t *testing.T) {
	pythonRepo := stringFunctionsPythonRepo(t)
	cases, err := conf.LoadTOMLCases(context.Background(), pythonRepo, "test_string_functions.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases.Fold) == 0 {
		t.Fatal("no string function TOML cases loaded")
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
					"string function mismatch for %q\npython runtime=%s folded=%s\ngo     runtime=%s folded=%s",
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

func TestStringFunctionsVerifierTOMLOracle(t *testing.T) {
	pythonRepo := stringFunctionsPythonRepo(t)
	cases, err := conf.LoadTOMLCases(context.Background(), pythonRepo, "test_string_functions.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases.Verifier) == 0 {
		t.Fatal("no string function verifier TOML cases loaded")
	}
	for i, tc := range cases.Verifier {
		tc := tc
		t.Run(tomlCaseName(tc.File, tc.Group, i, tc.Expression), func(t *testing.T) {
			pythonErr, err := conf.PythonExpressionParseError(context.Background(), pythonRepo, tc.Expression)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr == "" {
				t.Fatalf("python accepted verifier failure expression %q", tc.Expression)
			}
			goErr := conf.GoExpressionParseError(tc.Expression)
			if goErr == "" {
				t.Fatalf("go accepted verifier failure expression %q; python error=%q", tc.Expression, pythonErr)
			}
		})
	}
}

func TestStringFloatFormattingOracle(t *testing.T) {
	pythonRepo := stringFunctionsPythonRepo(t)
	cases := []string{
		`string(1.0) == "1.0"`,
		`concat(divide(10.0, 2.0), "x") == "5.0x"`,
		`string(10000000000.0) == "10000000000.0"`,
	}
	for _, expression := range cases {
		t.Run(expression, func(t *testing.T) {
			result, err := conf.CompareExpression(context.Background(), pythonRepo, expression, false)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf(
					"string float formatting mismatch for %q\npython runtime=%s folded=%s\ngo     runtime=%s folded=%s",
					expression,
					result.Python.Runtime,
					result.Python.Folded,
					result.Go.Runtime,
					result.Go.Folded,
				)
			}
			if result.Go.Runtime != "true" || result.Go.Folded != "true" {
				t.Fatalf("expected expression to evaluate true, got runtime=%s folded=%s", result.Go.Runtime, result.Go.Folded)
			}
		})
	}
}

func stringFunctionsPythonRepo(t *testing.T) string {
	t.Helper()
	return foldingPythonRepo(t)
}
