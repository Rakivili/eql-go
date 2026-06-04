package conformance

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestQueryTOMLSmokeOracle(t *testing.T) {
	pythonRepo := foldingPythonRepo(t)
	cases, err := conf.LoadTOMLQueries(context.Background(), pythonRepo, "test_queries.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no query TOML cases loaded")
	}
	events, err := conf.ReadJSONArray(filepath.Join(pythonRepo, "eql", "etc", "test_data.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Cover all current Python test_queries.toml entries.
	const maxOriginalIndex = 241
	ran := 0
	for _, tc := range cases {
		tc := tc
		if tc.Index >= maxOriginalIndex {
			continue
		}
		ran++
		t.Run(tomlQueryCaseName(tc), func(t *testing.T) {
			result, err := conf.CompareWithOptions(context.Background(), pythonRepo, tc.Query, events, conf.CompareOptions{
				CaseSensitive: tc.CaseSensitive,
				DataSource:    "endgame",
			})
			if err != nil {
				t.Fatal(err)
			}

			pythonIDs, err := conf.SerialEventIDs(result.PythonRows)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pythonIDs, tc.ExpectedEventIDs) {
				t.Fatalf(
					"python fixture mismatch for query %q\nexpected ids=%v\npython ids=%v",
					tc.Query,
					tc.ExpectedEventIDs,
					pythonIDs,
				)
			}

			if !result.Equal() {
				t.Fatalf(
					"query TOML row mismatch for query %q\npython rows=%v\ngo rows=%v",
					tc.Query,
					result.PythonRows,
					result.GoRows,
				)
			}

			goIDs, err := conf.SerialEventIDs(result.GoRows)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(goIDs, pythonIDs) {
				t.Fatalf(
					"query TOML id mismatch for query %q\npython ids=%v\ngo ids=%v",
					tc.Query,
					pythonIDs,
					goIDs,
				)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no query TOML smoke cases selected")
	}
}

func tomlQueryCaseName(tc conf.TOMLQueryCase) string {
	mode := "insensitive"
	if tc.CaseSensitive {
		mode = "sensitive"
	}
	return tomlCaseName(tc.File, mode, tc.Index, tc.Query)
}
