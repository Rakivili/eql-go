package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
)

func TestRepeatedFinalizeOracle(t *testing.T) {
	pythonRepo := sequencePythonRepo(t)
	hostEvents := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 20, "process_name": "cmd.exe", "hostname": "h1"},
		{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "powershell.exe", "hostname": "h2"},
		{"event_type": "process", "serial_event_id": 3, "pid": 30, "process_name": "CMD.EXE", "hostname": "h1"},
	}
	hostlessEvents := []map[string]any{
		{"event_type": "process", "serial_event_id": 1, "pid": 20, "process_name": "cmd.exe"},
		{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "powershell.exe"},
		{"event_type": "process", "serial_event_id": 3, "pid": 30, "process_name": "CMD.EXE"},
	}
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{name: "tail replay", query: `process where true | tail 2`, events: hostlessEvents},
		{name: "sort replay", query: `process where true | sort pid`, events: hostlessEvents},
		{name: "plain count replay", query: `process where true | count`, events: hostlessEvents},
		{name: "keyed count hostful replay", query: `process where true | count process_name`, events: hostEvents},
		{name: "keyed count hostless second eof error", query: `process where true | count process_name`, events: hostlessEvents},
		{name: "unique count hostful replay", query: `process where true | unique_count process_name`, events: hostEvents},
		{name: "unique count hostless second eof error", query: `process where true | unique_count process_name`, events: hostlessEvents},
		{name: "sort keyed count second eof error", query: `process where true | sort pid | count process_name`, events: hostEvents},
		{name: "sort unique count second eof error", query: `process where true | sort pid | unique_count process_name`, events: hostEvents},
		{name: "count unique count second eof error", query: `process where true | count process_name | unique_count key`, events: hostEvents},
		{name: "head tail stays closed", query: `process where true | head 2 | tail 1`, events: hostlessEvents},
		{name: "head count stays closed", query: `process where true | head 2 | count`, events: hostlessEvents},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonFrames, err := pythonRepeatedFinalizeFrames(context.Background(), pythonRepo, tc.query, tc.events, 2)
			if err != nil {
				t.Fatal(err)
			}
			goFrames, err := goRepeatedFinalizeFrames(tc.query, tc.events, 2)
			if err != nil {
				t.Fatal(err)
			}
			assertFinalizeFramesMatch(t, pythonFrames, goFrames)
		})
	}
}

type repeatedFinalizeFrame struct {
	Rows []string `json:"rows"`
	Err  string   `json:"err,omitempty"`
}

func pythonRepeatedFinalizeFrames(ctx context.Context, pythonRepo string, query string, events []map[string]any, finalizes int) ([]repeatedFinalizeFrame, error) {
	payload := map[string]any{"query": query, "events": events, "finalizes": finalizes}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	script := `
import json, sys
from eql import PythonEngine, parse_query
payload = json.load(sys.stdin)
engine = PythonEngine({"flatten": True})
results = []
engine.add_output_hook(results.append)
engine.add_query(parse_query(payload["query"]))

def rows_since(start):
    return [
        json.dumps(event.data, sort_keys=True, separators=(",", ":"))
        for event in results[start:]
    ]

engine.stream_events(payload["events"], finalize=False)
frames = []
for _ in range(payload["finalizes"]):
    start = len(results)
    try:
        engine.finalize()
    except Exception as exc:
        frames.append({"rows": rows_since(start), "err": type(exc).__name__ + ": " + str(exc)})
    else:
        frames.append({"rows": rows_since(start)})
print(json.dumps(frames, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var frames []repeatedFinalizeFrame
	if err := json.Unmarshal(bytes.TrimSpace(out), &frames); err != nil {
		return nil, err
	}
	return frames, nil
}

func goRepeatedFinalizeFrames(query string, events []map[string]any, finalizes int) ([]repeatedFinalizeFrame, error) {
	rule, err := eql.Compile(query)
	if err != nil {
		return nil, err
	}
	eng := eql.NewEngine(rule)
	for _, data := range events {
		if _, err := eng.Feed(eql.EventFromData(data)); err != nil {
			return nil, err
		}
	}
	frames := make([]repeatedFinalizeFrame, 0, finalizes)
	for i := 0; i < finalizes; i++ {
		matches, err := eng.Finalize()
		if err != nil {
			frames = append(frames, repeatedFinalizeFrame{Err: err.Error()})
			continue
		}
		rows, err := frameRows(matches)
		if err != nil {
			return nil, err
		}
		frames = append(frames, repeatedFinalizeFrame{Rows: rows})
	}
	return frames, nil
}

func assertFinalizeFramesMatch(t *testing.T, pythonFrames []repeatedFinalizeFrame, goFrames []repeatedFinalizeFrame) {
	t.Helper()
	if len(goFrames) != len(pythonFrames) {
		t.Fatalf("frame count mismatch\npython %#v\ngo     %#v", pythonFrames, goFrames)
	}
	for i := range pythonFrames {
		pythonFrame := pythonFrames[i]
		goFrame := goFrames[i]
		if pythonFrame.Err != "" {
			if goFrame.Err == "" {
				t.Fatalf("frame %d expected Go error containing %q, got rows %#v", i, pythonFrame.Err, goFrame.Rows)
			}
			if !strings.Contains(goFrame.Err, pythonFrame.Err) {
				t.Fatalf("frame %d error mismatch\npython %q\ngo     %q", i, pythonFrame.Err, goFrame.Err)
			}
			continue
		}
		if goFrame.Err != "" {
			t.Fatalf("frame %d unexpected Go error %q; python rows %#v", i, goFrame.Err, pythonFrame.Rows)
		}
		if !reflect.DeepEqual(goFrame.Rows, pythonFrame.Rows) {
			t.Fatalf("frame %d row mismatch\npython %#v\ngo     %#v", i, pythonFrame.Rows, goFrame.Rows)
		}
	}
}
