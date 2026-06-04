package conformance

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestUnicodeLowerOracle(t *testing.T) {
	pythonRepo := foldingPythonRepo(t)
	cases := []struct {
		name       string
		expression string
		want       string
	}{
		{name: "capital dotted i does not fold to plain i", expression: `"\u{0130}" == "i"`, want: "false"},
		{name: "capital dotted i folds to i plus combining dot", expression: `"\u{0130}" == "i\u{0307}"`, want: "true"},
		{name: "greek sigma final lower differs from simple lower", expression: `"ΟΣ" == "ος"`, want: "true"},
		{name: "greek sigma final does not fold to medial sigma", expression: `"ΟΣ" == "οσ"`, want: "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpression(context.Background(), pythonRepo, tc.expression, false)
			if err != nil {
				t.Fatal(err)
			}
			if result.Python.Runtime != tc.want {
				t.Fatalf("python runtime for %q = %s, want %s", tc.expression, result.Python.Runtime, tc.want)
			}
			if result.Go.Runtime != result.Python.Runtime {
				t.Fatalf(
					"unicode runtime lower mismatch for %q\npython runtime=%s folded=%s\ngo     runtime=%s folded=%s",
					tc.expression,
					result.Python.Runtime,
					result.Python.Folded,
					result.Go.Runtime,
					result.Go.Folded,
				)
			}
		})
	}
}

func TestUnicodeLowerCountKeyOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "process_name": "\u0130"},
		{"event_type": "process", "serial_event_id": 2, "process_name": "i\u0307"},
		{"event_type": "process", "serial_event_id": 3, "process_name": "i"},
	}
	query := `process where true | count process_name`

	pythonRows, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	goRows, err := conf.GoOutputRows(query, events)
	if err != nil {
		t.Fatal(err)
	}
	pythonCounts, err := countRowsByKey(pythonRows)
	if err != nil {
		t.Fatal(err)
	}
	goCounts, err := countRowsByKey(goRows)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(goCounts, pythonCounts) {
		t.Fatalf("count key grouping mismatch\npython=%v\ngo=%v\npython rows=%v\ngo rows=%v", pythonCounts, goCounts, pythonRows, goRows)
	}
}

func TestDynamicStringRepresentationOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	cases := []struct {
		name  string
		query string
		event map[string]any
	}{
		{
			name:  "json number exponent",
			query: `process where string(value) == "10000000000.0" | count`,
			event: map[string]any{"event_type": "process", "serial_event_id": 1, "value": json.Number("1e10")},
		},
		{
			name:  "array string",
			query: `process where string(arr) == "['a', 'b']" | count`,
			event: map[string]any{"event_type": "process", "serial_event_id": 1, "arr": []any{"a", "b"}},
		},
		{
			name:  "object string",
			query: `process where string(obj) == "{'k': 'v'}" | count`,
			event: map[string]any{"event_type": "process", "serial_event_id": 1, "obj": map[string]any{"k": "v"}},
		},
		{
			name:  "array concat",
			query: `process where concat(arr, "") == "['a', 'b']" | count`,
			event: map[string]any{"event_type": "process", "serial_event_id": 1, "arr": []any{"a", "b"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, tc.query, []map[string]any{tc.event})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
			if len(result.GoRows) != 1 {
				t.Fatalf("expected one count row, got %d rows", len(result.GoRows))
			}
		})
	}
}

func TestLargeIntegerComparisonOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": json.Number("9007199254740993")},
	}
	cases := []struct {
		name  string
		query string
		want  []int64
	}{
		{
			name:  "large int equality keeps precision",
			query: `process where pid == 9007199254740992`,
			want:  []int64{},
		},
		{
			name:  "large int ordered comparison keeps precision",
			query: `process where pid > 9007199254740992`,
			want:  []int64{1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, tc.query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
			got, err := conf.SerialEventIDs(result.GoRows)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("serial_event_ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func countRowsByKey(rows []string) (map[string]int64, error) {
	counts := map[string]int64{}
	for _, row := range rows {
		var data struct {
			Key   string      `json:"key"`
			Count json.Number `json:"count"`
		}
		if err := json.Unmarshal([]byte(row), &data); err != nil {
			return nil, err
		}
		count, err := data.Count.Int64()
		if err != nil {
			return nil, err
		}
		counts[data.Key] = count
	}
	return counts, nil
}
