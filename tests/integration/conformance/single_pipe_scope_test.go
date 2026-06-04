package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestSingleEventPipeEventsFieldOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "missing events field is null",
			query: `process where true | filter events[0].pid == pid`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "pid": 20},
			},
		},
		{
			name:  "real events field is not shadowed",
			query: `process where true | filter events[0].pid == 99`,
			events: []map[string]any{
				{
					"event_type":      "process",
					"serial_event_id": 1,
					"pid":             10,
					"events":          []any{map[string]any{"pid": 99}},
				},
				{
					"event_type":      "process",
					"serial_event_id": 2,
					"pid":             99,
					"events":          []any{map[string]any{"pid": 10}},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, tc.query, tc.events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}
