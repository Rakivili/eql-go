package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestOptimizerTOMLOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases, err := conf.LoadTOMLCases(context.Background(), pythonRepo, "test_optimizer.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases.Optimizer) == 0 {
		t.Fatal("no optimizer TOML cases loaded")
	}
	for i, tc := range cases.Optimizer {
		tc := tc
		t.Run(tomlCaseName(tc.File, tc.Group, i, tc.Expression), func(t *testing.T) {
			result, err := conf.CompareExpressionOptimized(context.Background(), pythonRepo, tc.Expression, tc.Optimized)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Python {
				t.Fatalf("python fixture mismatch for %q optimized to %q", tc.Expression, tc.Optimized)
			}
			if !result.Equal() {
				t.Fatalf(
					"optimizer mismatch for %q\noptimized %q\npython=%v go=%v",
					tc.Expression,
					tc.Optimized,
					result.Python,
					result.Go,
				)
			}
		})
	}
}

func TestOptimizerEquivalentTOMLOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases, err := conf.LoadTOMLCases(context.Background(), pythonRepo, "test_optimizer.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases.Equivalent) == 0 {
		t.Fatal("no equivalent TOML cases loaded")
	}
	for i, tc := range cases.Equivalent {
		tc := tc
		t.Run(tomlCaseName(tc.File, tc.Group, i, tc.Expression), func(t *testing.T) {
			result, err := conf.CompareExpressionEquivalent(context.Background(), pythonRepo, tc.Expression, tc.Alternate)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Python {
				t.Fatalf("python fixture mismatch for %q equivalent to %q", tc.Expression, tc.Alternate)
			}
			if !result.Equal() {
				t.Fatalf(
					"equivalence mismatch for %q\nalternate %q\npython=%v go=%v",
					tc.Expression,
					tc.Alternate,
					result.Python,
					result.Go,
				)
			}
		})
	}
}
