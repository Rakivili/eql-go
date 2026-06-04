package conformance

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestOracle(t *testing.T) {
	events, _, pythonRepo := loadMVPFixture(t)
	got, err := conf.PythonOutputRows(context.Background(), pythonRepo, `process where true`, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("oracle returned no process events")
	}
}

func TestMVPSingleEvent(t *testing.T) {
	events, queries, pythonRepo := loadMVPFixture(t)
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

func loadMVPFixture(t *testing.T) ([]map[string]any, []string, string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pyRepo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
	base := filepath.Join(filepath.Dir(file), "testdata", "mvp")
	events, err := conf.ReadJSONL(filepath.Join(base, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	queries, err := conf.ReadQueries(filepath.Join(base, "queries.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return events, queries, pyRepo
}
