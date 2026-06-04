package conformance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Rakivili/eql-go/internal/ast"
)

func TestDefaultPythonRepo(t *testing.T) {
	t.Setenv("EQL_PYTHON_REPO", "/tmp/eql-python")
	if got := DefaultPythonRepo(); got != "/tmp/eql-python" {
		t.Fatalf("DefaultPythonRepo with env=%q", got)
	}
	t.Setenv("EQL_PYTHON_REPO", "")
	if got := DefaultPythonRepo(); got == "" {
		t.Fatal("expected fallback Python repo")
	}
}

func TestReadJSONLAndQueries(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	queriesPath := filepath.Join(dir, "queries.txt")
	if err := os.WriteFile(eventsPath, []byte("{\"pid\":10}\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queriesPath, []byte("# comment\nprocess where true\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := ReadJSONL(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	queries, err := ReadQueries(queriesPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || queries[0] != "process where true" {
		t.Fatalf("unexpected queries %#v", queries)
	}
}

func TestReadJSONArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, []byte(`[{"serial_event_id":1},{"serial_event_id":2}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := ReadJSONArray(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected two events, got %d", len(events))
	}
	if _, ok := events[0]["serial_event_id"].(json.Number); !ok {
		t.Fatalf("expected json.Number, got %T", events[0]["serial_event_id"])
	}
}

func TestReadJSONLError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte("{bad}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJSONL(path); err == nil {
		t.Fatal("expected json decode error")
	}
}

func TestSerialEventIDs(t *testing.T) {
	ids, err := SerialEventIDs([]string{
		`{"serial_event_id":1}`,
		`{"event_type":"process","serial_event_id":2}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("unexpected ids %#v", ids)
	}
	if _, err := SerialEventIDs([]string{`{"event_type":"process"}`}); err == nil {
		t.Fatal("expected missing serial_event_id error")
	}
}

func TestGoOutputRows(t *testing.T) {
	rows, err := GoOutputRows("process where pid == 10", []map[string]any{
		{"event_type": "process", "pid": 10},
		{"event_type": "file", "pid": 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0] != `{"event_type":"process","pid":10}` {
		t.Fatalf("unexpected rows %#v", rows)
	}

	rows, err = GoOutputRows("process where true | tail 1", []map[string]any{
		{"event_type": "process", "serial_event_id": 1},
		{"event_type": "process", "serial_event_id": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0] != `{"event_type":"process","serial_event_id":2}` {
		t.Fatalf("unexpected tail rows %#v", rows)
	}

	rows, err = GoOutputRows("process where true | sort pid", []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 2},
		{"event_type": "process", "serial_event_id": 2, "pid": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0] != `{"event_type":"process","pid":1,"serial_event_id":2}` || rows[1] != `{"event_type":"process","pid":2,"serial_event_id":1}` {
		t.Fatalf("unexpected sort rows %#v", rows)
	}

	rows, err = GoOutputRows("process where true | count", []map[string]any{
		{"event_type": "process", "serial_event_id": 1},
		{"event_type": "process", "serial_event_id": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0] != `{"count":2,"key":"totals"}` {
		t.Fatalf("unexpected count rows %#v", rows)
	}

	rows, err = GoOutputRows("process where true | unique_count process_name", []map[string]any{
		{"event_type": "process", "process_name": "cmd.exe", "serial_event_id": 1},
		{"event_type": "process", "process_name": "CMD.EXE", "serial_event_id": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0] != `{"count":2,"event_type":"process","percent":1.0,"process_name":"cmd.exe","serial_event_id":1}` {
		t.Fatalf("unexpected unique_count rows %#v", rows)
	}

	rows, err = GoOutputRowsCaseSensitive("process where true | count process_name", []map[string]any{
		{"event_type": "process", "process_name": "cmd.exe", "serial_event_id": 1},
		{"event_type": "process", "process_name": "CMD.EXE", "serial_event_id": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0] != `{"count":1,"key":"CMD.EXE","percent":0.5}` || rows[1] != `{"count":1,"key":"cmd.exe","percent":0.5}` {
		t.Fatalf("unexpected case-sensitive count rows %#v", rows)
	}
}

func TestCanonicalJSONEscapesNonASCII(t *testing.T) {
	row, err := canonicalJSON(map[string]any{
		"emoji": "😀",
		"name":  "İ",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"emoji":"\ud83d\ude00","name":"\u0130"}`
	if row != want {
		t.Fatalf("canonicalJSON=%s, want %s", row, want)
	}
}

func TestResultEqual(t *testing.T) {
	result := Result{PythonRows: []string{"a"}, GoRows: []string{"a"}}
	if !result.Equal() {
		t.Fatal("expected equal result")
	}
	result.GoRows = []string{"b"}
	if result.Equal() {
		t.Fatal("expected unequal result")
	}
}

func TestCompare(t *testing.T) {
	pythonRepo := filepath.Clean(filepath.Join("..", "..", "..", "eql"))
	if _, err := os.Stat(filepath.Join(pythonRepo, "eql")); err != nil {
		t.Skipf("python EQL repo not available: %v", err)
	}
	result, err := Compare(context.Background(), pythonRepo, "process where true", []map[string]any{
		{"event_type": "process", "serial_event_id": 1},
		{"event_type": "file", "serial_event_id": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("expected equal output: %#v", result)
	}

	result, err = CompareCaseSensitive(context.Background(), pythonRepo, "process where true | count process_name", []map[string]any{
		{"event_type": "process", "process_name": "cmd.exe", "serial_event_id": 1},
		{"event_type": "process", "process_name": "CMD.EXE", "serial_event_id": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("expected case-sensitive equal output: %#v", result)
	}
}

func TestCompareExpression(t *testing.T) {
	pythonRepo := filepath.Clean(filepath.Join("..", "..", "..", "eql"))
	if _, err := os.Stat(filepath.Join(pythonRepo, "eql")); err != nil {
		t.Skipf("python EQL repo not available: %v", err)
	}
	result, err := CompareExpression(context.Background(), pythonRepo, `7 / 3`, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("expected equal expression output: %#v", result)
	}
}

func TestCompareExpressionEquivalent(t *testing.T) {
	pythonRepo := filepath.Clean(filepath.Join("..", "..", "..", "eql"))
	if _, err := os.Stat(filepath.Join(pythonRepo, "eql")); err != nil {
		t.Skipf("python EQL repo not available: %v", err)
	}
	result, err := CompareExpressionEquivalent(context.Background(), pythonRepo, `field == "a*b"`, `wildcard(field, "a*b")`)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() || !result.Python {
		t.Fatalf("expected equal expression equivalence: %#v", result)
	}
}

func TestCompareExpressionOptimized(t *testing.T) {
	pythonRepo := filepath.Clean(filepath.Join("..", "..", "..", "eql"))
	if _, err := os.Stat(filepath.Join(pythonRepo, "eql")); err != nil {
		t.Skipf("python EQL repo not available: %v", err)
	}
	result, err := CompareExpressionOptimized(context.Background(), pythonRepo, `a == 1 or false`, `a == 1`)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() || !result.Python {
		t.Fatalf("expected equal optimized expression: %#v", result)
	}
}

func TestGoExpressionValues(t *testing.T) {
	result, err := GoExpressionValues(`7 * 3.0`, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Runtime != "21.0" || result.Folded != "21.0" {
		t.Fatalf("unexpected expression values %#v", result)
	}
	result, err = GoExpressionValues(`"Foo" == "foo"`, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Runtime != "false" || result.Folded != "false" {
		t.Fatalf("unexpected case-sensitive expression values %#v", result)
	}
	if _, err := GoExpressionValues(`unknownFunc()`, false); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := GoExpressionValues(`7 +`, false); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestGoExpressionEquivalent(t *testing.T) {
	equal, err := GoExpressionEquivalent(`field == "a*b"`, `wildcard(field, "a*b")`)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("expected wildcard expressions to be equivalent")
	}
	equal, err = GoExpressionEquivalent(`field == "abc"`, `wildcard(field, "abc")`)
	if err != nil {
		t.Fatal(err)
	}
	if equal {
		t.Fatal("expected exact equality to differ from wildcard call")
	}
	if _, err := GoExpressionEquivalent(`field ==`, `field == "x"`); err == nil {
		t.Fatal("expected source parse error")
	}
	if _, err := GoExpressionEquivalent(`field == "x"`, `field ==`); err == nil {
		t.Fatal("expected alternate parse error")
	}
	if _, err := GoExpressionEquivalent(`length(1)`, `length(1)`); err == nil {
		t.Fatal("expected source validation error")
	}
	if _, err := GoExpressionEquivalent(`field == "x"`, `length(1)`); err == nil {
		t.Fatal("expected alternate validation error")
	}
}

func TestGoExpressionOptimized(t *testing.T) {
	equal, err := GoExpressionOptimized(`a == 1 or false`, `a == 1`)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("expected optimized expressions to match")
	}
	equal, err = GoExpressionOptimized(`a == 1 or false`, `false`)
	if err != nil {
		t.Fatal(err)
	}
	if equal {
		t.Fatal("expected different optimized expression")
	}
}

func TestCanonicalExpressionJSON(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{value: ast.Int(7), want: "7"},
		{value: ast.Float(21), want: "21.0"},
		{value: ast.Float(2.5), want: "2.5"},
		{value: nil, want: "null"},
	}
	for _, tc := range cases {
		got, err := canonicalExpressionJSON(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("canonicalExpressionJSON(%v)=%s, want %s", tc.value, got, tc.want)
		}
	}
	if _, err := canonicalExpressionJSON(func() {}); err == nil {
		t.Fatal("expected json marshal error")
	}
	if _, err := canonicalJSON(func() {}); err == nil {
		t.Fatal("expected canonical json marshal error")
	}
}

func TestExpressionCompareEqual(t *testing.T) {
	result := ExpressionCompareResult{
		Python: ExpressionResult{Runtime: "1", Folded: "1"},
		Go:     ExpressionResult{Runtime: "1", Folded: "1"},
	}
	if !result.Equal() {
		t.Fatal("expected equal expression result")
	}
	result.Go.Folded = "2"
	if result.Equal() {
		t.Fatal("expected unequal expression result")
	}

	equiv := ExpressionEquivalentResult{Python: true, Go: true}
	if !equiv.Equal() {
		t.Fatal("expected equal expression equivalence")
	}
	equiv.Go = false
	if equiv.Equal() {
		t.Fatal("expected unequal expression equivalence")
	}

	optimized := ExpressionOptimizedResult{Python: true, Go: true}
	if !optimized.Equal() {
		t.Fatal("expected equal optimized result")
	}
	optimized.Go = false
	if optimized.Equal() {
		t.Fatal("expected unequal optimized result")
	}
}

func TestPythonOutputRowsBadRepo(t *testing.T) {
	_, err := PythonOutputRows(context.Background(), filepath.Join(t.TempDir(), "missing"), "process where true", nil)
	if err == nil {
		t.Fatal("expected python import error")
	}
}

func TestPythonExpressionValuesBadRepo(t *testing.T) {
	_, err := PythonExpressionValues(context.Background(), filepath.Join(t.TempDir(), "missing"), "7 + 3", false)
	if err == nil {
		t.Fatal("expected python import error")
	}
}

func TestPythonExpressionEquivalentBadRepo(t *testing.T) {
	_, err := PythonExpressionEquivalent(context.Background(), filepath.Join(t.TempDir(), "missing"), `field == "a*"`, `wildcard(field, "a*")`)
	if err == nil {
		t.Fatal("expected python import error")
	}
}

func TestPythonExpressionOptimizedBadRepo(t *testing.T) {
	_, err := PythonExpressionOptimized(context.Background(), filepath.Join(t.TempDir(), "missing"), `a == 1 or false`, `a == 1`)
	if err == nil {
		t.Fatal("expected python import error")
	}
}

func TestSplitRows(t *testing.T) {
	if rows := splitRows(nil); rows != nil {
		t.Fatalf("expected nil rows, got %#v", rows)
	}
	rows := splitRows([]byte("a\nb\n"))
	if len(rows) != 2 || rows[0] != "a" || rows[1] != "b" {
		t.Fatalf("unexpected rows %#v", rows)
	}
}
