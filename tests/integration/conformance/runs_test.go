package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestSequenceRunsOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "first stage runs emit sliding windows",
			query: `sequence [file where true] with runs=3`,
			events: []map[string]any{
				{"event_type": "file", "serial_event_id": 1, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 2, "file_name": "two.txt"},
				{"event_type": "file", "serial_event_id": 3, "file_name": "three.txt"},
				{"event_type": "file", "serial_event_id": 4, "file_name": "four.txt"},
			},
		},
		{
			name:  "later stage runs repeat the target step",
			query: `sequence [process where true] [file where true] with runs=2`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 3, "file_name": "two.txt"},
			},
		},
		{
			name:  "runs preserve global keys",
			query: `sequence by pid [file where true] with runs=2`,
			events: []map[string]any{
				{"event_type": "file", "serial_event_id": 1, "pid": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 2, "pid": 20, "file_name": "wrong.txt"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "two.txt"},
			},
		},
		{
			name:  "runs preserve stage keys",
			query: `sequence [process where true] by pid [file where true] by process_id with runs=2`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "process_id": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 3, "process_id": 20, "file_name": "wrong.txt"},
				{"event_type": "file", "serial_event_id": 4, "process_id": 10, "file_name": "two.txt"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareWithOptions(context.Background(), pythonRepo, tc.query, tc.events, conf.CompareOptions{
				AllowRuns:           true,
				ElasticsearchSyntax: true,
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
