package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestUniqueCountFloatCountOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{
		{"event_type": "generic", "serial_event_id": 1, "process_name": "cmd.exe", "count": 1.5},
		{"event_type": "generic", "serial_event_id": 2, "process_name": "cmd.exe", "count": 2.25},
		{"event_type": "generic", "serial_event_id": 3, "process_name": "powershell.exe", "count": 2.5},
	}
	query := `generic where true | unique_count process_name`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
	if len(result.GoRows) != 2 {
		t.Fatalf("expected two unique_count rows, got %d", len(result.GoRows))
	}
}
