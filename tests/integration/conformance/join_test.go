package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestMinimalJoinOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "unkeyed join is unordered and emits query slot order",
			query: `join [process where true] [file where true]`,
			events: []map[string]any{
				{"event_type": "file", "serial_event_id": 1, "file_name": "first.txt"},
				{"event_type": "process", "serial_event_id": 2, "process_name": "second.exe"},
			},
		},
		{
			name:  "join slot keeps first event and does not overwrite",
			query: `join [process where true] [file where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "process_name": "first.exe"},
				{"event_type": "process", "serial_event_id": 2, "process_name": "ignored.exe"},
				{"event_type": "file", "serial_event_id": 3, "file_name": "done.txt"},
			},
		},
		{
			name:  "same event can fill multiple same-type slots",
			query: `join [process where true] [process where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "process_name": "same.exe"},
			},
		},
		{
			name:  "global keyed join",
			query: `join by pid [process where true] [file where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "right.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 20, "file_name": "wrong.txt"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "right.txt"},
			},
		},
		{
			name:  "stage keyed join",
			query: `join [process where true] by pid [file where true] by process_id`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "right.exe"},
				{"event_type": "file", "serial_event_id": 2, "process_id": 20, "file_name": "wrong.txt"},
				{"event_type": "file", "serial_event_id": 3, "process_id": 10, "file_name": "right.txt"},
			},
		},
		{
			name:  "join until clears matching key",
			query: `join by pid [process where opcode == 1] [file where true] until [process where opcode == 2]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "opcode": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "opcode": 2, "pid": 10},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "closed.txt"},
				{"event_type": "process", "serial_event_id": 4, "opcode": 1, "pid": 20},
				{"event_type": "file", "serial_event_id": 5, "pid": 20, "file_name": "matched.txt"},
			},
		},
		{
			name:  "join close callback runs before term callbacks",
			query: `join by pid [process where true] [file where true] until [process where opcode == 2]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "opcode": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "opcode": 2, "pid": 10},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "matched-after-close.txt"},
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

func TestJoinPipesOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "head counts join matches before flattening",
			query: `join by pid [process where true] [file where true] | head 1`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "tail counts join matches before flattening",
			query: `join by pid [process where true] [file where true] | tail 1`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "count counts join matches",
			query: `join by pid [process where true] [file where true] | count`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "filter can inspect explicit events index",
			query: `join by pid [process where true] [file where true] | filter events[0].pid == 10`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
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
