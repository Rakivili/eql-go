package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestEventOfNamedSubqueryOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "file event of process records matching pid",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "a.txt"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "b.txt"},
			},
		},
		{
			name:  "process event of sees state from same event",
			query: `process where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "process_name": "cmd.exe", "subtype": "create"},
			},
		},
		{
			name:  "terminate purges on next process event",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "python.exe", "subtype": "terminate"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "still-pending.txt"},
				{"event_type": "process", "serial_event_id": 4, "pid": 20, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 5, "pid": 10, "file_name": "purged.txt"},
			},
		},
		{
			name:  "system create resets state",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 4, "process_name": "System", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "reset.txt"},
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

func TestChildOfNamedSubqueryOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "process child of records direct child only",
			query: `process where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
			},
		},
		{
			name:  "file event for child process matches",
			query: `file where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 3, "pid": 20, "file_name": "child.txt"},
				{"event_type": "file", "serial_event_id": 4, "pid": 10, "file_name": "parent.txt"},
			},
		},
		{
			name:  "terminate purges child on next process event",
			query: `file where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "terminate"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "still-pending.txt"},
				{"event_type": "process", "serial_event_id": 5, "pid": 30, "ppid": 4, "process_name": "other.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 6, "pid": 20, "file_name": "purged.txt"},
			},
		},
		{
			name:  "system create resets child state",
			query: `file where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 4, "ppid": 0, "process_name": "System", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "reset.txt"},
			},
		},
		{
			name:  "nested child of tracks next generation",
			query: `file where child of [process where child of [process where process_name == "cmd.exe"]]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 30, "file_name": "grandchild.txt"},
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

func TestDescendantOfNamedSubqueryOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "process descendant of records all generations",
			query: `process where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 4, "pid": 40, "ppid": 4, "process_name": "other.exe", "subtype": "create"},
			},
		},
		{
			name:  "file event for descendant process matches",
			query: `file where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 30, "file_name": "grandchild.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 10, "file_name": "source.txt"},
			},
		},
		{
			name:  "terminate purges descendant on next process event",
			query: `file where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "terminate"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "still-pending.txt"},
				{"event_type": "process", "serial_event_id": 5, "pid": 40, "ppid": 4, "process_name": "other.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 6, "pid": 20, "file_name": "purged.txt"},
			},
		},
		{
			name:  "system create resets descendant state",
			query: `file where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 4, "ppid": 0, "process_name": "System", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "reset.txt"},
			},
		},
		{
			name:  "nested descendant of tracks deeper generation",
			query: `file where descendant of [process where descendant of [process where process_name == "cmd.exe"]]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 30, "file_name": "nested-descendant.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 20, "file_name": "inner-source.txt"},
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
