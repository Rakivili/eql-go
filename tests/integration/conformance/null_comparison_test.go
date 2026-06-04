package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestNullComparisonOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 1, "process_name": "powershell.exe", "timestamp": 100},
		{"event_type": "process", "serial_event_id": 2, "pid": 2, "field": nil, "process_name": "powershell.exe", "timestamp": 200},
		{"event_type": "process", "serial_event_id": 3, "pid": 3, "field": "x", "process_name": "powershell.exe", "timestamp": 300},
	}
	cases := []struct {
		query string
		rows  int
	}{
		{query: `process where field == null`, rows: 2},
		{query: `process where field != null`, rows: 1},
		{query: `process where field in (null)`, rows: 0},
		{query: `process where field not in (null)`, rows: 0},
		{query: `process where process_name not in (parent_process_name, "cmd.exe")`, rows: 0},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, tc.query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
			if len(result.GoRows) != tc.rows {
				t.Fatalf("matched rows=%d, want %d: %v", len(result.GoRows), tc.rows, result.GoRows)
			}
		})
	}
}
