package conformance

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestCaseSensitiveCountPipeOracle(t *testing.T) {
	pythonRepo := caseSensitivePipePythonRepo(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe", "parent_process_name": "explorer.exe"},
		{"event_type": "process", "serial_event_id": 2, "process_name": "CMD.EXE", "parent_process_name": "explorer.exe"},
		{"event_type": "process", "serial_event_id": 3, "process_name": "cmd.exe", "parent_process_name": "Explorer.exe"},
	}
	cases := []string{
		`process where true | count process_name`,
		`process where true | count process_name, parent_process_name`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			result, err := conf.CompareCaseSensitive(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf(
					"case-sensitive count mismatch for %q\npython=%v\ngo=%v",
					query,
					result.PythonRows,
					result.GoRows,
				)
			}
		})
	}
}

func caseSensitivePipePythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
