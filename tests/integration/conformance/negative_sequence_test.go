package conformance

import (
	"context"
	"reflect"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestNegativeSequenceOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	base := int64(116444736000000000)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   []int64
	}{
		{
			name:  "middle negative stage advances on nonmatching predicate",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "missing.txt"] [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "registry", "serial_event_id": 3, "pid": 10, "timestamp": base + 20_000_000},
			},
		},
		{
			name:  "middle negative stage discards pending on matching predicate",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "cmd.exe"] [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 20_000_000, "file_name": "other.txt"},
				{"event_type": "registry", "serial_event_id": 4, "pid": 10, "timestamp": base + 30_000_000},
			},
		},
		{
			name:  "final negative stage excludes the triggering event",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "missing.txt"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
		},
		{
			name:  "final negative stage discards pending on matching predicate",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 20_000_000, "file_name": "other.txt"},
			},
		},
		{
			name:  "first negative stage starts with empty pending sequence",
			query: `sequence with maxspan=5s ![process where process_name == "missing.exe"] [file where file_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
		},
		{
			name:  "keyed final negative stage preserves existing key state",
			query: `sequence by pid with maxspan=5s [process where true] ![file where file_name == "missing.txt"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
		},
		{
			name:  "keyed final negative stage discards matching key only",
			query: `sequence by pid with maxspan=5s [process where true] ![file where file_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "timestamp": base, "process_name": "powershell.exe"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 4, "pid": 10, "timestamp": base + 20_000_000, "file_name": "other.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 20, "timestamp": base + 30_000_000, "file_name": "other.txt"},
			},
		},
		{
			name:  "keyed middle negative fork keeps pending after matching predicate",
			query: `sequence by pid with maxspan=5s [process where pid == 1] ![file where file_name == "bad"] fork=true [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 1, "timestamp": base},
				{"event_type": "file", "serial_event_id": 2, "pid": 1, "timestamp": base + 10_000_000, "file_name": "bad"},
				{"event_type": "file", "serial_event_id": 3, "pid": 1, "timestamp": base + 20_000_000, "file_name": "good"},
				{"event_type": "registry", "serial_event_id": 4, "pid": 1, "timestamp": base + 30_000_000},
			},
			want: []int64{1, 4},
		},
		{
			name:  "unkeyed middle negative fork keeps pending after matching predicate",
			query: `sequence with maxspan=5s [process where pid == 1] ![file where file_name == "bad"] fork=true [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 1, "timestamp": base},
				{"event_type": "file", "serial_event_id": 2, "pid": 1, "timestamp": base + 10_000_000, "file_name": "bad"},
				{"event_type": "file", "serial_event_id": 3, "pid": 1, "timestamp": base + 20_000_000, "file_name": "good"},
				{"event_type": "registry", "serial_event_id": 4, "pid": 1, "timestamp": base + 30_000_000},
			},
			want: []int64{1, 4},
		},
		{
			name:  "keyed final negative fork keeps pending after matching predicate",
			query: `sequence by pid with maxspan=5s [process where pid == 1] ![file where file_name == "bad"] fork=true`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 1, "timestamp": base},
				{"event_type": "file", "serial_event_id": 2, "pid": 1, "timestamp": base + 10_000_000, "file_name": "bad"},
				{"event_type": "file", "serial_event_id": 3, "pid": 1, "timestamp": base + 20_000_000, "file_name": "good"},
			},
			want: []int64{1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareWithOptions(context.Background(), pythonRepo, tc.query, tc.events, conf.CompareOptions{
				AllowNegation:       true,
				ElasticsearchSyntax: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
			if tc.want != nil {
				got, err := conf.SerialEventIDs(result.GoRows)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("serial_event_ids=%v, want %v", got, tc.want)
				}
			}
		})
	}
}
