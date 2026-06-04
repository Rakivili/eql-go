package schema

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Rakivili/eql-go/internal/types"
)

func TestNewValidateSchema(t *testing.T) {
	if _, err := New(sampleSchema()); err != nil {
		t.Fatalf("valid schema: %v", err)
	}
	invalid := []map[string]map[string]any{
		{"process": {"pid": ""}},
		{"process": {"pid": "bad"}},
		{"process": {"bad": map[string]any{"1bad": "string"}}},
		{"process": {"bad": []any{"string", 1}}},
		{"process": nil},
	}
	for _, schema := range invalid {
		if _, err := New(schema); err == nil {
			t.Fatalf("expected invalid schema error for %#v", schema)
		}
	}
}

func TestConvertToType(t *testing.T) {
	cases := []struct {
		value any
		hint  types.TypeHint
		ok    bool
	}{
		{value: "string", hint: types.TypeString, ok: true},
		{value: "number", hint: types.TypeNumeric, ok: true},
		{value: "mixed", hint: types.TypeUnknown, ok: true},
		{value: map[string]any{}, hint: types.TypeUnknown, ok: true},
		{value: map[string]any{"a": "string"}, hint: types.TypeObject, ok: true},
		{value: []any{"string"}, hint: types.TypeArray, ok: true},
		{value: "bad", hint: types.TypeUnknown},
	}
	for _, tc := range cases {
		got, _, ok := ConvertToType(tc.value)
		if got != tc.hint || ok != tc.ok {
			t.Fatalf("ConvertToType(%#v)=(%s,%v), want (%s,%v)", tc.value, got, ok, tc.hint, tc.ok)
		}
	}
}

func TestGetEventTypeHint(t *testing.T) {
	s, err := New(sampleSchema())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		eventType string
		path      []PathPart
		hint      types.TypeHint
		ok        bool
	}{
		{name: "process name", eventType: "process", path: path(Field("process_name")), hint: types.TypeString, ok: true},
		{name: "array index", eventType: "complex", path: path(Field("string_arr"), Index(3)), hint: types.TypeString, ok: true},
		{name: "wide open", eventType: "complex", path: path(Field("wideopen"), Field("a"), Field("b")), hint: types.TypeUnknown, ok: true},
		{name: "nested bool", eventType: "complex", path: path(Field("nested"), Field("double_nested"), Field("triplenest"), Field("b")), hint: types.TypeBoolean, ok: true},
		{name: "object array", eventType: "complex", path: path(Field("array_array"), Index(0), Field("s"), Index(0)), hint: types.TypeString, ok: true},
		{name: "missing field", eventType: "process", path: path(Field("missing")), hint: types.TypeUnknown},
		{name: "generic", eventType: EventTypeGeneric, path: path(Field("anything")), hint: types.TypeUnknown, ok: true},
		{name: "any", eventType: EventTypeAny, path: path(Field("file_name")), hint: types.TypeString, ok: true},
		{name: "any conflicting field follows python fixture order", eventType: EventTypeAny, path: path(Field("process_name")), hint: types.TypeString, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hint, _, ok := s.GetEventTypeHint(tc.eventType, tc.path)
			if hint != tc.hint || ok != tc.ok {
				t.Fatalf("GetEventTypeHint()=(%s,%v), want (%s,%v)", hint, ok, tc.hint, tc.ok)
			}
		})
	}

	missing, err := New(sampleSchema(), WithAllowMissing(true))
	if err != nil {
		t.Fatal(err)
	}
	hint, _, ok := missing.GetEventTypeHint("process", path(Field("missing")))
	if hint != types.TypeUnknown || !ok {
		t.Fatalf("allow-missing lookup=(%s,%v)", hint, ok)
	}
}

func TestValidateEventType(t *testing.T) {
	s, err := New(sampleSchema(), WithAllowGeneric(false), WithAllowAny(false))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"process":        true,
		"file":           true,
		EventTypeGeneric: false,
		EventTypeAny:     false,
		"network":        false,
	}
	for eventType, want := range cases {
		if got := s.ValidateEventType(eventType); got != want {
			t.Fatalf("ValidateEventType(%s)=%v, want %v", eventType, got, want)
		}
	}
	empty, err := New(map[string]map[string]any{}, WithAllowGeneric(true), WithAllowAny(true))
	if err != nil {
		t.Fatal(err)
	}
	if !empty.ValidateEventType("network") {
		t.Fatal("empty schema should allow unknown event types")
	}
}

func TestMergeFlattenLearnPythonOracle(t *testing.T) {
	payload := schemaOraclePayload{
		A: map[string]map[string]any{
			"process": {"a": "string", "b": "number", "c": map[string]any{}},
		},
		B: map[string]map[string]any{
			"process": {"c": "mixed"},
			"file":    {"path": "string"},
		},
		Learn: []map[string]any{
			{"event_type": "process", "a": map[string]any{"b": 1, "c": 2}, "d": "e"},
			{"event_type": "file", "a": "b", "cd": []any{"ef", 123}},
			{"event_type": "process", "a": map[string]any{"b": 1, "c": "e"}},
		},
	}
	python := pythonSchemaOracle(t, payload)

	a := mustSchema(t, payload.A)
	b := mustSchema(t, payload.B)
	merged, err := a.Merge(b)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(merged.Events, python.Merge) {
		t.Fatalf("merge schema mismatch\ngo=%s\npython=%s", jsonText(t, merged.Events), jsonText(t, python.Merge))
	}

	flattened, err := mustSchema(t, sampleSchema()).Flatten()
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(flattened.Events, python.Flatten) {
		t.Fatalf("flatten schema mismatch\ngo=%s\npython=%s", jsonText(t, flattened.Events), jsonText(t, python.Flatten))
	}

	learned, err := LearnFromData(payload.Learn)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(learned.Events, python.LearnSchema) {
		t.Fatalf("learn schema mismatch\ngo=%s\npython=%s", jsonText(t, learned.Events), jsonText(t, python.LearnSchema))
	}
	if learned.AllowGeneric != python.LearnAllowGeneric {
		t.Fatalf("learn allow_generic=%v, want %v", learned.AllowGeneric, python.LearnAllowGeneric)
	}

	genericLearned, err := Learn([]Event{{Type: EventTypeGeneric, Data: map[string]any{"a": "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(genericLearned.Events, python.LearnGenericSchema) {
		t.Fatalf("generic learn schema mismatch\ngo=%s\npython=%s", jsonText(t, genericLearned.Events), jsonText(t, python.LearnGenericSchema))
	}
	if genericLearned.AllowGeneric != python.LearnGenericAllow {
		t.Fatalf("generic learn allow_generic=%v, want %v", genericLearned.AllowGeneric, python.LearnGenericAllow)
	}
}

func sampleSchema() map[string]map[string]any {
	return map[string]map[string]any{
		"process": {
			"command_line": "string",
			"process_name": "string",
			"pid":          "number",
			"elevated":     "boolean",
		},
		"file": {
			"file_path":    "string",
			"file_name":    "string",
			"process_name": "number",
			"pid":          "number",
			"data":         "mixed",
		},
		"complex": {
			"string_arr": []any{"string"},
			"wideopen":   map[string]any{},
			"nested": map[string]any{
				"arr": []any{"mixed"},
				"double_nested": map[string]any{
					"nn":         "number",
					"triplenest": map[string]any{"m": "mixed", "b": "boolean"},
				},
				"num": "number",
			},
			"objarray": []any{map[string]any{}},
			"array_array": []any{
				map[string]any{"s": []any{"string"}},
			},
		},
	}
}

type schemaOraclePayload struct {
	A     map[string]map[string]any `json:"a"`
	B     map[string]map[string]any `json:"b"`
	Learn []map[string]any          `json:"learn"`
}

type schemaOracleResult struct {
	Merge              map[string]map[string]any `json:"merge"`
	Flatten            map[string]map[string]any `json:"flatten"`
	LearnSchema        map[string]map[string]any `json:"learn_schema"`
	LearnAllowGeneric  bool                      `json:"learn_allow_generic"`
	LearnGenericSchema map[string]map[string]any `json:"learn_generic_schema"`
	LearnGenericAllow  bool                      `json:"learn_generic_allow"`
}

func pythonSchemaOracle(t *testing.T, payload schemaOraclePayload) schemaOracleResult {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	script := `
import json, sys
from eql.events import Event
from eql.schema import Schema

payload = json.load(sys.stdin)
a = Schema(payload["a"])
b = Schema(payload["b"])
merged = a.merge(b)
flattened = Schema({
    "process": {
        "command_line": "string",
        "process_name": "string",
        "pid": "number",
        "elevated": "boolean",
    },
    "file": {
        "file_path": "string",
        "file_name": "string",
        "process_name": "number",
        "pid": "number",
        "data": "mixed",
    },
    "complex": {
        "string_arr": ["string"],
        "wideopen": {},
        "nested": {
            "arr": ["mixed"],
            "double_nested": {"nn": "number", "triplenest": {"m": "mixed", "b": "boolean"}},
            "num": "number",
        },
        "objarray": [{}],
        "array_array": [{"s": ["string"]}],
    },
}).flatten()
learned = Schema.learn(Event.from_data(d) for d in payload["learn"])
generic_learned = Schema.learn([Event("generic", 0, {"a": "b"})])
print(json.dumps({
    "merge": merged.schema,
    "flatten": flattened.schema,
    "learn_schema": learned.schema,
    "learn_allow_generic": learned.allow_generic,
    "learn_generic_schema": generic_learned.schema,
    "learn_generic_allow": generic_learned.allow_generic,
}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(context.Background(), "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+schemaPythonRepo(t))
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python schema oracle: %v: %s", err, bytes.TrimSpace(out))
	}
	var result schemaOracleResult
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func mustSchema(t *testing.T, events map[string]map[string]any) *Schema {
	t.Helper()
	s, err := New(events)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func path(parts ...PathPart) []PathPart {
	return parts
}

func sameJSON(left any, right any) bool {
	leftBody, leftErr := json.Marshal(left)
	rightBody, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBody, rightBody)
}

func jsonText(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func schemaPythonRepo(t *testing.T) string {
	t.Helper()
	if repo := os.Getenv("EQL_PYTHON_REPO"); repo != "" {
		return repo
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "eql"))
}
