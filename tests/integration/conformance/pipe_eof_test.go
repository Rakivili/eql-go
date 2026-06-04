package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"

	eql "github.com/Rakivili/eql-go"
)

func TestHeadPipeEOFPropagationOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	processEvents := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 20, "process_name": "cmd.exe"},
		{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "powershell.exe"},
		{"event_type": "process", "serial_event_id": 3, "pid": 30, "process_name": "rundll32.exe"},
	}
	sequenceEvents := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10},
		{"event_type": "file", "serial_event_id": 2, "pid": 10},
		{"event_type": "process", "serial_event_id": 3, "pid": 20},
		{"event_type": "file", "serial_event_id": 4, "pid": 20},
	}
	joinEvents := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10},
		{"event_type": "file", "serial_event_id": 2, "pid": 10},
		{"event_type": "process", "serial_event_id": 3, "pid": 20},
		{"event_type": "file", "serial_event_id": 4, "pid": 20},
	}
	sampleEvents := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 10},
		{"event_type": "file", "serial_event_id": 2, "pid": 10},
		{"event_type": "process", "serial_event_id": 3, "pid": 20},
		{"event_type": "file", "serial_event_id": 4, "pid": 20},
	}
	cases := []struct {
		name        string
		query       string
		events      []map[string]any
		allowSample bool
	}{
		{name: "head tail", query: `process where true | head 2 | tail 1`, events: processEvents},
		{name: "head sort", query: `process where true | head 2 | sort pid`, events: processEvents},
		{name: "head count", query: `process where true | head 2 | count`, events: processEvents},
		{name: "head unique count", query: `process where true | head 2 | unique_count process_name`, events: processEvents},
		{name: "head streaming pipe count", query: `process where true | head 2 | unique process_name | count`, events: processEvents},
		{name: "sequence head tail", query: `sequence by pid [process where true] [file where true] | head 2 | tail 1`, events: sequenceEvents},
		{name: "sequence head count", query: `sequence by pid [process where true] [file where true] | head 2 | count`, events: sequenceEvents},
		{name: "join head tail", query: `join by pid [process where true] [file where true] | head 2 | tail 1`, events: joinEvents},
		{name: "join head count", query: `join by pid [process where true] [file where true] | head 2 | count`, events: joinEvents},
		{name: "sample head tail", query: `sample [process where true] [file where true] | head 2 | tail 1`, events: sampleEvents, allowSample: true},
		{name: "sample head count", query: `sample [process where true] [file where true] | head 2 | count`, events: sampleEvents, allowSample: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := frameOptions{AllowSample: tc.allowSample}
			pythonFrames, err := pythonOutputFrames(context.Background(), pythonRepo, tc.query, tc.events, opts)
			if err != nil {
				t.Fatal(err)
			}
			goFrames, err := goOutputFrames(tc.query, tc.events, opts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(goFrames, pythonFrames) {
				t.Fatalf("frame mismatch\npython %#v\ngo     %#v", pythonFrames, goFrames)
			}
			if len(goFrames) == 0 || len(goFrames[len(goFrames)-1]) != 0 {
				t.Fatalf("expected final frame to be empty after head EOF propagation, got %#v", goFrames)
			}
		})
	}
}

type frameOptions struct {
	AllowSample bool
}

func pythonOutputFrames(ctx context.Context, pythonRepo string, query string, events []map[string]any, opts frameOptions) ([][]string, error) {
	payload := map[string]any{"query": query, "events": events, "allow_sample": opts.AllowSample}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	script := `
import json, sys
import contextlib
from eql import PythonEngine, parse_query
from eql.parser import allow_sample, elasticsearch_syntax
payload = json.load(sys.stdin)
engine = PythonEngine({"flatten": True})
results = []
engine.add_output_hook(results.append)
with contextlib.ExitStack() as stack:
    if payload["allow_sample"]:
        stack.enter_context(allow_sample)
        stack.enter_context(elasticsearch_syntax)
    engine.add_query(parse_query(payload["query"]))

def rows_since(start):
    return [
        json.dumps(event.data, sort_keys=True, separators=(",", ":"))
        for event in results[start:]
    ]

frames = []
for event in payload["events"]:
    start = len(results)
    engine.stream_events([event], finalize=False)
    frames.append(rows_since(start))
start = len(results)
engine.finalize()
frames.append(rows_since(start))
print(json.dumps(frames, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var frames [][]string
	if err := json.Unmarshal(bytes.TrimSpace(out), &frames); err != nil {
		return nil, err
	}
	return frames, nil
}

func goOutputFrames(query string, events []map[string]any, opts frameOptions) ([][]string, error) {
	var ruleOpts []eql.RuleOption
	if opts.AllowSample {
		ruleOpts = append(ruleOpts, eql.AllowSample())
		ruleOpts = append(ruleOpts, eql.ElasticsearchSyntax())
	}
	rule, err := eql.Compile(query, ruleOpts...)
	if err != nil {
		return nil, err
	}
	eng := eql.NewEngine(rule)
	frames := make([][]string, 0, len(events)+1)
	for _, data := range events {
		matches, err := eng.Feed(eql.EventFromData(data))
		if err != nil {
			return nil, err
		}
		rows, err := frameRows(matches)
		if err != nil {
			return nil, err
		}
		frames = append(frames, rows)
	}
	matches, err := eng.Finalize()
	if err != nil {
		return nil, err
	}
	rows, err := frameRows(matches)
	if err != nil {
		return nil, err
	}
	return append(frames, rows), nil
}

func frameRows(matches []eql.Match) ([]string, error) {
	rows := []string{}
	for _, match := range matches {
		for _, event := range match.Events {
			body, err := json.Marshal(event.Data)
			if err != nil {
				return nil, err
			}
			rows = append(rows, string(body))
		}
	}
	return rows, nil
}
