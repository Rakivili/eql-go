package conformance

import (
	"context"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestSampleOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe"},
		{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "payload.txt"},
		{"event_type": "process", "serial_event_id": 3, "pid": 20, "process_name": "powershell.exe"},
		{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "payload.txt"},
	}
	cases := []string{
		`sample [process where process_name == "cmd.exe"] [file where file_name == "payload.txt"]`,
		`sample by pid [process where true] [file where true]`,
		`sample [process where process_name == "cmd.exe"] [process where process_name == "cmd.exe"]`,
		`sample [process where true] [file where true] | head 1`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			result, err := conf.CompareWithOptions(context.Background(), pythonRepo, query, events, conf.CompareOptions{
				AllowSample:         true,
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
