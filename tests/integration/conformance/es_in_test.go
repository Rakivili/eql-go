package conformance

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	eql "github.com/Rakivili/eql-go"
	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestElasticsearchInsensitiveInOracle(t *testing.T) {
	pythonRepo := esInPythonRepo(t)
	events, err := conf.ReadJSONL(filepath.Join("testdata", "mvp", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		query         string
		caseSensitive bool
	}{
		{
			name:  "default insensitive in tilde",
			query: `process where process_name in~ ("cmd.exe", "powershell.exe")`,
		},
		{
			name:  "default insensitive not in tilde",
			query: `process where process_name not in~ ("cmd.exe", "powershell.exe")`,
		},
		{
			name:          "case sensitive in tilde follows global mode",
			query:         `process where process_name in~ ("cmd.exe", "powershell.exe")`,
			caseSensitive: true,
		},
		{
			name:          "case sensitive not in tilde follows global mode",
			query:         `process where process_name not in~ ("cmd.exe", "powershell.exe")`,
			caseSensitive: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareWithOptions(
				context.Background(),
				pythonRepo,
				tc.query,
				events,
				conf.CompareOptions{
					CaseSensitive:       tc.caseSensitive,
					ElasticsearchSyntax: true,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf(
					"ES in~ mismatch for %q\npython=%v\ngo=%v",
					tc.query,
					result.PythonRows,
					result.GoRows,
				)
			}
		})
	}
}

func TestElasticsearchInsensitiveInDefaultCompileError(t *testing.T) {
	for _, query := range []string{
		`process where process_name in~ ("cmd.exe")`,
		`process where process_name not in~ ("cmd.exe")`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := eql.Compile(query); err == nil {
				t.Fatal("expected default compile to reject in~")
			}
		})
	}
}

func esInPythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
