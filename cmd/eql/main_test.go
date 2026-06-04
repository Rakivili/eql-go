package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
)

func TestRunQueryFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	input := strings.Join([]string{
		`{"event_type":"process","process_name":"cmd.exe","serial_event_id":1}`,
		`{"event_type":"file","file_name":"cmd.exe","serial_event_id":2}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runQuery([]string{"-f", path, `process where process_name == "CMD.EXE"`}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"serial_event_id":1`) {
		t.Fatalf("expected process event output, got %s", out.String())
	}
	if strings.Contains(out.String(), `"serial_event_id":2`) {
		t.Fatalf("unexpected file event output, got %s", out.String())
	}
}

func TestRunQueryErrors(t *testing.T) {
	if err := runQuery(nil, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("expected missing query error")
	}
	if err := runQuery([]string{"process where 0"}, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("expected parse error")
	}
	if err := runQuery([]string{"-f", filepath.Join(t.TempDir(), "missing.jsonl"), "process where true"}, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("expected file error")
	}
}

func TestRunMain(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runMain([]string{"--version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("version exit code=%d stderr=%q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "eql 1.0.0" {
		t.Fatalf("expected version output, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no version stderr, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-V"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("short version exit code=%d stderr=%q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "eql 1.0.0" {
		t.Fatalf("expected short version output, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runMain(nil, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("usage exit code=%d", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("expected usage message, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	input := strings.NewReader(`{"event_type":"process"}` + "\n")
	if code := runMain([]string{"query", "process where true"}, input, &stdout, &stderr); code != 0 {
		t.Fatalf("query exit code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"event_type":"process"`) {
		t.Fatalf("expected query output, got %q", stdout.String())
	}
}

func TestStreamJSONL(t *testing.T) {
	rule, err := eql.Compile(`process where pid == 10`)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader(`{"event_type":"process","pid":10}` + "\n")
	var out bytes.Buffer
	if err := streamJSONL(input, &out, rule); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"event_type":"process","pid":10}` {
		t.Fatalf("unexpected output %q", out.String())
	}

	rule, err = eql.Compile(`process where true | tail 1`)
	if err != nil {
		t.Fatal(err)
	}
	input = strings.NewReader(strings.Join([]string{
		`{"event_type":"process","serial_event_id":1}`,
		`{"event_type":"process","serial_event_id":2}`,
	}, "\n") + "\n")
	out.Reset()
	if err := streamJSONL(input, &out, rule); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"event_type":"process","serial_event_id":2}` {
		t.Fatalf("unexpected tail output %q", out.String())
	}

	rule, err = eql.Compile(`process where true | sort pid`)
	if err != nil {
		t.Fatal(err)
	}
	input = strings.NewReader(strings.Join([]string{
		`{"event_type":"process","pid":2,"serial_event_id":1}`,
		`{"event_type":"process","pid":1,"serial_event_id":2}`,
	}, "\n") + "\n")
	out.Reset()
	if err := streamJSONL(input, &out, rule); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != strings.Join([]string{
		`{"event_type":"process","pid":1,"serial_event_id":2}`,
		`{"event_type":"process","pid":2,"serial_event_id":1}`,
	}, "\n") {
		t.Fatalf("unexpected sort output %q", out.String())
	}

	rule, err = eql.Compile(`process where true | count`)
	if err != nil {
		t.Fatal(err)
	}
	input = strings.NewReader(strings.Join([]string{
		`{"event_type":"process","serial_event_id":1}`,
		`{"event_type":"process","serial_event_id":2}`,
	}, "\n") + "\n")
	out.Reset()
	if err := streamJSONL(input, &out, rule); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"count":2,"key":"totals"}` {
		t.Fatalf("unexpected count output %q", out.String())
	}

	rule, err = eql.Compile(`process where true | unique_count process_name`)
	if err != nil {
		t.Fatal(err)
	}
	input = strings.NewReader(strings.Join([]string{
		`{"event_type":"process","process_name":"cmd.exe","serial_event_id":1}`,
		`{"event_type":"process","process_name":"CMD.EXE","serial_event_id":2}`,
	}, "\n") + "\n")
	out.Reset()
	if err := streamJSONL(input, &out, rule); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"count":2,"event_type":"process","percent":1.0,"process_name":"cmd.exe","serial_event_id":1}` {
		t.Fatalf("unexpected unique_count output %q", out.String())
	}
}

func TestStreamJSONLError(t *testing.T) {
	rule, err := eql.Compile(`process where true`)
	if err != nil {
		t.Fatal(err)
	}
	if err := streamJSONL(strings.NewReader(`{bad json}`+"\n"), io.Discard, rule); err == nil {
		t.Fatal("expected json decode error")
	}
}

func TestRunQueryImpliedAny(t *testing.T) {
	// A bare boolean expression should be compiled as "any where <expr>" by the CLI.
	input := strings.NewReader(`{"event_type":"process","serial_event_id":1}` + "\n" +
		`{"event_type":"file","serial_event_id":2}` + "\n")
	var out bytes.Buffer
	if err := runQuery([]string{`true`}, input, &out); err != nil {
		t.Fatalf("ImpliedAny in CLI: %v", err)
	}
	if !strings.Contains(out.String(), `"serial_event_id":1`) {
		t.Fatalf("expected process event, got %s", out.String())
	}
	if !strings.Contains(out.String(), `"serial_event_id":2`) {
		t.Fatalf("expected file event, got %s", out.String())
	}
}

func TestRunQueryImpliedBase(t *testing.T) {
	// A pipe-only query should be compiled as "any where true | ..." by the CLI.
	input := strings.NewReader(`{"event_type":"process","serial_event_id":1}` + "\n" +
		`{"event_type":"process","serial_event_id":2}` + "\n")
	var out bytes.Buffer
	if err := runQuery([]string{`| tail 1`}, input, &out); err != nil {
		t.Fatalf("ImpliedBase in CLI: %v", err)
	}
	if strings.Contains(out.String(), `"serial_event_id":1`) {
		t.Fatalf("expected only last event, got %s", out.String())
	}
	if !strings.Contains(out.String(), `"serial_event_id":2`) {
		t.Fatalf("expected last event, got %s", out.String())
	}
}

func TestRunQueryJSONFile(t *testing.T) {
	// JSON array file input via --format json.
	path := filepath.Join(t.TempDir(), "events.json")
	input := `[{"event_type":"process","serial_event_id":1},{"event_type":"file","serial_event_id":2}]`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runQuery([]string{"-f", path, "--format", "json", `process where true`}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("JSON file: %v", err)
	}
	if !strings.Contains(out.String(), `"serial_event_id":1`) {
		t.Fatalf("expected process event output, got %s", out.String())
	}
	if strings.Contains(out.String(), `"serial_event_id":2`) {
		t.Fatalf("unexpected file event output, got %s", out.String())
	}
}

func TestRunQueryJSONFileAutoDetect(t *testing.T) {
	// JSON array file auto-detected from .json extension.
	path := filepath.Join(t.TempDir(), "events.json")
	input := `[{"event_type":"process","serial_event_id":3}]`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runQuery([]string{"-f", path, `process where true`}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("JSON auto-detect: %v", err)
	}
	if !strings.Contains(out.String(), `"serial_event_id":3`) {
		t.Fatalf("expected process event output, got %s", out.String())
	}
}

func TestStreamJSONError(t *testing.T) {
	rule, err := eql.Compile(`process where true`)
	if err != nil {
		t.Fatal(err)
	}
	// Not a JSON array.
	if err := streamJSON(strings.NewReader(`{"event_type":"process"}`), io.Discard, rule); err == nil {
		t.Fatal("expected error for non-array JSON")
	}
	// Malformed JSON.
	if err := streamJSON(strings.NewReader(`[{bad}]`), io.Discard, rule); err == nil {
		t.Fatal("expected error for bad JSON")
	}
}
