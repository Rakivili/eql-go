package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Rakivili/eql-go/internal/conformance"
)

func TestRunCompare(t *testing.T) {
	var out bytes.Buffer
	events := filepath.Join("..", "..", "tests", "integration", "conformance", "testdata", "mvp", "events.jsonl")
	if err := runCompare([]string{
		"-events", events,
		"-query", `process where process_name == "CMD.EXE"`,
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected equality, got %s", text)
	}
	if !strings.Contains(text, `"serial_event_id":1`) {
		t.Fatalf("expected event output, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `process where true | count process_name`,
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
		"-case-sensitive",
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected case-sensitive equality, got %s", text)
	}
	if !strings.Contains(text, `"key":"PowerShell.EXE"`) {
		t.Fatalf("expected case-sensitive count output, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `process where process_name == TARGET`,
		"-definitions", `const TARGET = "cmd.exe"`,
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected definitions equality, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `sample [process where true] [file where true] | head 1`,
		"-allow-sample",
		"-elasticsearch-syntax",
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected sample equality, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `process where process_name : "cmd*"`,
		"-elasticsearch-syntax",
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected Elasticsearch syntax equality, got %s", text)
	}
	if !strings.Contains(text, `"serial_event_id":1`) {
		t.Fatalf("expected Elasticsearch syntax event output, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "missing.txt"] [registry where true]`,
		"-elasticsearch-syntax",
		"-allow-negation",
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected negative sequence equality, got %s", text)
	}
	if !strings.Contains(text, `"serial_event_id":6`) {
		t.Fatalf("expected negative sequence output, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `sequence [file where true] with runs=2`,
		"-elasticsearch-syntax",
		"-allow-runs",
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected runs equality, got %s", text)
	}
	if !strings.Contains(text, `"serial_event_id":3`) || !strings.Contains(text, `"serial_event_id":8`) {
		t.Fatalf("expected runs output, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `process where arraySearch(items, $item, $item == "a")`,
		"-elastic-endpoint-syntax",
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected endpoint dollar variable equality, got %s", text)
	}
	if !strings.Contains(text, `"serial_event_id":1`) {
		t.Fatalf("expected endpoint dollar variable output, got %s", text)
	}

	out.Reset()
	if err := runCompare([]string{
		"-events", events,
		"-query", `sequence [process where pid == 10] as p0 [file where pid == 10]`,
		"-elastic-endpoint-syntax",
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &out); err != nil {
		t.Fatal(err)
	}
	text = out.String()
	if !strings.Contains(text, "EQUAL true") {
		t.Fatalf("expected endpoint alias equality, got %s", text)
	}
	if !strings.Contains(text, `"serial_event_id":1`) || !strings.Contains(text, `"serial_event_id":3`) {
		t.Fatalf("expected endpoint alias output, got %s", text)
	}
}

func TestRunMain(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runMain(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("expected error exit code, got %d", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("expected stderr output")
	}

	stdout.Reset()
	stderr.Reset()
	events := filepath.Join("..", "..", "tests", "integration", "conformance", "testdata", "mvp", "events.jsonl")
	code := runMain([]string{
		"-events", events,
		"-query", `process where false`,
		"-python-repo", filepath.Clean(filepath.Join("..", "..", "..", "eql")),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected success code, got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "EQUAL true") {
		t.Fatalf("expected equality output, got %s", stdout.String())
	}
}

func TestRunCompareErrors(t *testing.T) {
	if err := runCompare(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("expected missing events error")
	}
	if err := runCompare([]string{"-events", "missing.jsonl", "-query", "process where true"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected missing events file error")
	}
	events := filepath.Join("..", "..", "tests", "integration", "conformance", "testdata", "mvp", "events.jsonl")
	if err := runCompare([]string{"-events", events, "-query", "process where true", "-queries", "queries.txt"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected query mode error")
	}
	if err := runCompare([]string{"-events", events, "-query", "process where true", "-definitions", "const A = 1", "-definitions-file", "defs.eql"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected definitions mode error")
	}
}

func TestPrintResult(t *testing.T) {
	var out bytes.Buffer
	printResult(&out, conformance.Result{Query: "process where false"})
	text := out.String()
	if !strings.Contains(text, "<empty>") || !strings.Contains(text, "EQUAL true") {
		t.Fatalf("unexpected output %q", text)
	}
}
