package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestElasticEndpointSequenceAliasOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "alias syntax preserves Python no-schema runtime behavior",
			query: `sequence [process where pid == 10] as p0 [network where p0.pid == pid]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "network", "serial_event_id": 2, "pid": 10, "p0": map[string]any{"pid": 10}},
			},
		},
		{
			name:  "alias does not bind previous event at runtime without schema translation",
			query: `sequence [process where pid == 10] as p0 [network where p0.pid == pid]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "network", "serial_event_id": 2, "pid": 10},
			},
		},
		{
			name:  "final stage alias parses and runs as ordinary sequence",
			query: `sequence [process where pid == 10] [network where pid == 10] as n0`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "network", "serial_event_id": 2, "pid": 10},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareWithOptions(context.Background(), pythonRepo, tc.query, tc.events, conf.CompareOptions{
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
