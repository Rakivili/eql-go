package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestElasticEndpointDollarVariableOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	events := []map[string]any{
		{
			"event_type":      "process",
			"serial_event_id": 1,
			"process_name":    "cmd.exe",
			"items":           []any{"a", "b"},
			"objects":         []any{map[string]any{"trusted": true}, map[string]any{"trusted": false}},
		},
		{
			"event_type":      "process",
			"serial_event_id": 2,
			"items":           []any{"missing"},
			"objects":         []any{map[string]any{"trusted": false}},
		},
	}
	queries := []string{
		`process where arraySearch(items, $item, $item == "a")`,
		`process where arraySearch(objects, $sig, $sig.trusted == true)`,
		`process where arraySearch(items, $item, item == "a")`,
		`process where arraySearch(items, item, $item == "a")`,
		`process where process_name : "cmd*"`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.CompareWithOptions(context.Background(), pythonRepo, query, events, conf.CompareOptions{
				ElasticEndpointSyntax: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}
