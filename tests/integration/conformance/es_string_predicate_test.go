package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestElasticsearchStringPredicateOracle(t *testing.T) {
	pythonRepo := esStringPredicatePythonRepo(t)
	events, err := conf.ReadJSONL(filepath.Join("testdata", "mvp", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{
		`process where process_name : "cmd*"`,
		`process where process_name : """cmd*"""`,
		`process where process_name : """""cmd*"""""`,
		`process where process_name : ("cmd*", "powershell*")`,
		`process where process_name : ("cmd*", """powershell*""")`,
		`process where process_name like "cmd*"`,
		`process where process_name like ("cmd*", "power*")`,
		`process where process_name like~ ("cmd*", "power*")`,
		`process where process_name regex "cmd.*"`,
		`process where process_name regex ("cmd.*", "power.*")`,
		`process where process_name regex~ ("cmd.*", "power.*")`,
		`process where wildcard~(process_name, "cmd*")`,
		`process where wildcard~ (process_name, "cmd*")`,
		`process where process_name == "cmd*"`,
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
					"ES string predicate mismatch for %q\npython=%v\ngo=%v",
					query,
					result.PythonRows,
					result.GoRows,
				)
			}
		})
	}
}

func TestElasticsearchStringSyntaxOracleRejects(t *testing.T) {
	pythonRepo := esStringPredicatePythonRepo(t)
	queries := []string{
		`process where process_name : ("cmd*",)`,
		`process where process_name:stringContains~("cmd")`,
		`process where process_name == 'cmd.exe'`,
		`process where process_name == ?'cmd.exe'`,
		`process where process_name == ?"cmd.exe"`,
		`process where process_name == "cmd.exe`,
		`process where process_name == """cmd.exe`,
		"process where process_name == \"cmd\n.exe\"",
		"process where process_name == \"\"\"cmd\n.exe\"\"\"",
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			pythonErr, err := pythonElasticsearchParseError(context.Background(), pythonRepo, query)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr == "" {
				t.Fatalf("python accepted %q; update this test before changing Go behavior", query)
			}
			if _, err := eql.Compile(query, eql.ElasticsearchSyntax()); err == nil {
				t.Fatal("expected Go compile error")
			}
		})
	}
}

func TestElasticsearchStringPredicateDefaultCompileError(t *testing.T) {
	if _, err := eql.Compile(`process where process_name : "cmd*"`); err == nil {
		t.Fatal("expected default compile to reject Elasticsearch string predicate")
	}
}

func TestElasticsearchStringPredicateInvalidPatternCompileError(t *testing.T) {
	_, err := eql.Compile(`process where process_name regex "["`, eql.ElasticsearchSyntax())
	if err == nil {
		t.Fatal("expected invalid regex compile error")
	}
	if !strings.Contains(err.Error(), "not a valid regular expression") {
		t.Fatalf("compile error=%v, want regex validation error", err)
	}
}

func esStringPredicatePythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}

func pythonElasticsearchParseError(ctx context.Context, pythonRepo string, query string) (string, error) {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return "", err
	}
	script := `
import json, sys
from eql import parse_query
from eql.parser import elasticsearch_syntax

payload = json.load(sys.stdin)
try:
    with elasticsearch_syntax:
        parse_query(payload["query"])
    error = ""
except Exception as e:
    error = str(e)
print(json.dumps({"error": error}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	var result struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return "", err
	}
	return result.Error, nil
}
