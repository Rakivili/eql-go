package conformance

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	eql "github.com/Rakivili/eql-go"
	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestElasticsearchOptionalFieldOracle(t *testing.T) {
	pythonRepo := esOptionalFieldPythonRepo(t)
	events, err := conf.ReadJSONL(filepath.Join("testdata", "mvp", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{
		`process where ?process_name == "cmd.exe"`,
		`process where ?process_name : "cmd*"`,
		`process where ?missing_field == null`,
		`process where ?missing_field : "cmd*"`,
		`process where ?nested.value == 7`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.CompareWithOptions(
				context.Background(),
				pythonRepo,
				query,
				events,
				conf.CompareOptions{ElasticsearchSyntax: true},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf(
					"ES optional field mismatch for %q\npython=%v\ngo=%v",
					query,
					result.PythonRows,
					result.GoRows,
				)
			}
		})
	}
}

func TestElasticsearchOptionalFieldDefaultCompileError(t *testing.T) {
	for _, query := range []string{
		`process where ?process_name == "cmd.exe"`,
		`process where ?process_name : "cmd*"`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := eql.Compile(query); err == nil {
				t.Fatal("expected default compile to reject optional field")
			}
		})
	}
}

func esOptionalFieldPythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
