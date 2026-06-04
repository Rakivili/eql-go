package conformance

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestMinimalSequenceOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe"},
		{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "cmd.exe"},
		{"event_type": "registry", "serial_event_id": 3, "key": "HKCU"},
	}
	queries := []string{
		`sequence [process where pid == 10] [file where pid == 10]`,
		`sequence [process where process_name == "CMD.EXE"] [file where file_name == "cmd.exe"]`,
		`sequence [process where pid == 10] [file where pid == 10] [registry where true]`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestMinimalSequenceLatestPendingOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "process_name": "first.exe"},
		{"event_type": "process", "serial_event_id": 2, "process_name": "second.exe"},
		{"event_type": "file", "serial_event_id": 3, "file_name": "out.txt"},
	}
	query := `sequence [process where true] [file where true]`
	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
}

func TestKeyedSequenceOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10, "user": "Alice", "process_name": "first.exe"},
		{"event_type": "file", "serial_event_id": 2, "pid": 20, "user": "alice", "file_name": "wrong.txt"},
		{"event_type": "process", "serial_event_id": 3, "pid": 10, "user": "ALICE", "process_name": "second.exe"},
		{"event_type": "file", "serial_event_id": 4, "pid": 10, "user": "alice", "file_name": "right.txt"},
		{"event_type": "process", "serial_event_id": 5, "process_name": "missing-key.exe"},
		{"event_type": "file", "serial_event_id": 6, "file_name": "missing-key.txt"},
	}
	queries := []string{
		`sequence by pid [process where true] [file where true]`,
		`sequence by user [process where true] [file where true]`,
		`sequence by pid, user [process where true] [file where true]`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestStageKeyedSequenceOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "host": "A", "pid": 10, "user": "Alice", "process_name": "first.exe"},
		{"event_type": "file", "serial_event_id": 2, "host": "B", "process_id": 10, "owner": "alice", "file_name": "wrong-host.txt"},
		{"event_type": "process", "serial_event_id": 3, "host": "a", "pid": 10, "user": "ALICE", "process_name": "second.exe"},
		{"event_type": "file", "serial_event_id": 4, "host": "a", "process_id": 10, "owner": "alice", "file_name": "right.txt"},
		{"event_type": "process", "serial_event_id": 5, "process_name": "missing-key.exe"},
		{"event_type": "file", "serial_event_id": 6, "file_name": "missing-key.txt"},
	}
	queries := []string{
		`sequence [process where true] by pid [file where true] by process_id`,
		`sequence [process where true] by pid, user [file where true] by process_id, owner`,
		`sequence by host [process where true] by pid [file where true] by process_id`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestSequenceMaxSpanOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	base := int64(116444736000000000)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "first.exe"},
		{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 50_000_000, "file_name": "ok.txt"},
		{"event_type": "process", "serial_event_id": 3, "pid": 20, "timestamp": base + 100_000_000, "process_name": "late.exe"},
		{"event_type": "file", "serial_event_id": 4, "pid": 20, "timestamp": base + 160_000_000, "file_name": "late.txt"},
		{"event_type": "process", "serial_event_id": 5, "pid": 30, "timestamp": base + 200_000_000, "process_name": "ms.exe"},
		{"event_type": "file", "serial_event_id": 6, "pid": 30, "timestamp": base + 250_000_000, "file_name": "ms.txt"},
		{"event_type": "process", "serial_event_id": 7, "pid": 40, "timestamp": base + 300_000_000, "process_name": "same-time.exe"},
		{"event_type": "file", "serial_event_id": 8, "pid": 40, "timestamp": base + 300_000_000, "file_name": "same-time.txt"},
		{"event_type": "process", "serial_event_id": 9, "pid": 50, "timestamp": base + 400_000_000, "process_name": "subsecond.exe"},
		{"event_type": "file", "serial_event_id": 10, "pid": 50, "timestamp": base + 404_000_000, "file_name": "subsecond.txt"},
	}
	queries := []string{
		`sequence with maxspan=5s [process where pid == 10] [file where pid == 10]`,
		`sequence with maxspan=5s [process where pid == 20] [file where pid == 20]`,
		`sequence by pid with maxspan=5s [process where true] [file where true]`,
		`sequence with maxspan=5s by pid [process where true] [file where true]`,
		`sequence with maxspan=5000ms by pid [process where true] [file where true]`,
		`sequence with maxspan=500ms by pid [process where true] [file where true]`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestSequenceMaxSpanFractionalTimestampOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": json.Number("10.1"), "process_name": "fractional.exe"},
		{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": json.Number("10.9"), "file_name": "late-fraction.txt"},
		{"event_type": "process", "serial_event_id": 3, "pid": 20, "timestamp": json.Number("20.9"), "process_name": "reverse-fraction.exe"},
		{"event_type": "file", "serial_event_id": 4, "pid": 20, "timestamp": json.Number("20.1"), "file_name": "within-fraction.txt"},
	}
	queries := []string{
		`sequence with maxspan=0s [process where pid == 10] [file where pid == 10]`,
		`sequence by pid with maxspan=0s [process where true] [file where true]`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestSequenceMaxSpanIgnoresUnrelatedEventOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	base := int64(116444736000000000)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base},
		{"event_type": "registry", "serial_event_id": 2, "timestamp": base + 60_000_000},
		{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 50_000_000},
	}
	query := `sequence with maxspan=5s by pid [process where true] [file where true]`
	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
}

func TestSequenceUntilOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "unkeyed close clears all pending state",
			query: `sequence [process where subtype == "start"] [file where true] until [process where subtype == "stop"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "subtype": "start", "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "subtype": "stop", "pid": 10},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "closed.txt"},
				{"event_type": "process", "serial_event_id": 4, "subtype": "start", "pid": 20},
				{"event_type": "file", "serial_event_id": 5, "pid": 20, "file_name": "matched.txt"},
			},
		},
		{
			name:  "global key close only clears matching key",
			query: `sequence by pid [process where opcode == 1] [file where true] until [process where opcode == 2]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "opcode": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "opcode": 2, "pid": 20},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "matched.txt"},
				{"event_type": "process", "serial_event_id": 4, "opcode": 1, "pid": 30},
				{"event_type": "process", "serial_event_id": 5, "opcode": 2, "pid": 30},
				{"event_type": "file", "serial_event_id": 6, "pid": 30, "file_name": "closed.txt"},
			},
		},
		{
			name:  "close callback runs before stage callbacks",
			query: `sequence by pid [process where true] [file where true] until [process where opcode == 2]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "opcode": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "opcode": 2, "pid": 10},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "matched-after-close.txt"},
			},
		},
		{
			name:  "stage key close uses until by",
			query: `sequence [process where opcode == 1] by pid [file where true] by process_id until [process where opcode == 2] by pid`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "opcode": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "opcode": 2, "pid": 20},
				{"event_type": "file", "serial_event_id": 3, "process_id": 10, "file_name": "matched.txt"},
				{"event_type": "process", "serial_event_id": 4, "opcode": 1, "pid": 30},
				{"event_type": "process", "serial_event_id": 5, "opcode": 2, "pid": 30},
				{"event_type": "file", "serial_event_id": 6, "process_id": 30, "file_name": "closed.txt"},
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

func TestSequenceForkOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "final stage fork keeps previous pending prefix",
			query: `sequence [process where true] [file where true] fork`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "two.txt"},
			},
		},
		{
			name:  "fork false matches default pop behavior",
			query: `sequence [process where true] [file where true] fork=false`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "two.txt"},
			},
		},
		{
			name:  "middle stage fork can produce multiple later matches",
			query: `sequence [process where true] [file where true] fork [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "one.txt"},
				{"event_type": "registry", "serial_event_id": 3, "key": "one"},
				{"event_type": "file", "serial_event_id": 4, "pid": 10, "file_name": "two.txt"},
				{"event_type": "registry", "serial_event_id": 5, "key": "two"},
			},
		},
		{
			name:  "keyed fork preserves pending for the same key only",
			query: `sequence by pid [process where true] [file where true] fork`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "pid": 20},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "other.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 10, "file_name": "two.txt"},
			},
		},
		{
			name:  "stage keyed fork uses target stage key",
			query: `sequence [process where true] by pid [file where true] fork by process_id`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "process", "serial_event_id": 2, "pid": 20},
				{"event_type": "file", "serial_event_id": 3, "process_id": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 4, "process_id": 20, "file_name": "other.txt"},
				{"event_type": "file", "serial_event_id": 5, "process_id": 10, "file_name": "two.txt"},
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

func TestSequencePipesOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "head counts sequence matches before flattening",
			query: `sequence by pid [process where true] [file where true] | head 1`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "tail counts sequence matches before flattening",
			query: `sequence by pid [process where true] [file where true] | tail 1`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "count counts sequence matches",
			query: `sequence by pid [process where true] [file where true] | count`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "filter can inspect explicit events index",
			query: `sequence by pid [process where true] [file where true] | filter events[0].pid == 10`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20},
			},
		},
		{
			name:  "sort orders sequence matches by explicit event index",
			query: `sequence by pid [process where true] [file where true] | sort events[1].file_name`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "z.txt"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "a.txt"},
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

func sequencePythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
