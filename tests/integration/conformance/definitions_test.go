package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestDefinitionsOracle(t *testing.T) {
	events, _, pythonRepo := loadMVPFixture(t)
	definitions := `
		// Python-style line comments are ignored.
		const TARGET = "cmd.exe"
		const ALT_TARGET == "powershell.exe"
		const GOOD_PID = 10
		const ENABLED = true
		const LIMIT = 1
		macro PROCESS_IS(name) process_name == name
		macro TARGET_PROCESS() PROCESS_IS(TARGET)
		macro PID_IS(value) pid == value
		macro PARENT_IS(name) parent_process_name == name
		macro VALUE_OF(obj) obj.value
		macro IN_GRAYLIST(proc)
			proc in (
				"msbuild.exe",
				"powershell.exe",
				"cmd.exe"
			)
		macro COMMENTED_TARGET()
			pid == GOOD_PID and /* ignored */ process_name == TARGET
	`
	queries := []string{
		`process where process_name == TARGET and pid == GOOD_PID and ENABLED`,
		`process where process_name == ALT_TARGET`,
		`process where ENABLED | head LIMIT`,
		`process where parent_process_name == TARGET`,
		`file where TARGET.name == "cmd.exe"`,
		`process where TARGET_PROCESS()`,
		`process where PROCESS_IS("powershell.exe")`,
		`process where PID_IS(GOOD_PID)`,
		`process where PARENT_IS(TARGET)`,
		`process where VALUE_OF(nested) == 7`,
		`process where IN_GRAYLIST(process_name)`,
		`process where COMMENTED_TARGET()`,
		`process where true | filter TARGET_PROCESS()`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.CompareWithDefinitions(context.Background(), pythonRepo, query, definitions, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestMacroPathExpansionOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{
		{
			"event_type":       "process",
			"serial_event_id":  1,
			"object":           map[string]any{"name": []any{"alpha"}},
			"object_array":     []any{map[string]any{"name": "alpha"}},
			"nested_container": map[string]any{"child": map[string]any{"name": []any{"alpha"}}},
		},
		{
			"event_type":      "process",
			"serial_event_id": 2,
			"object":          map[string]any{"name": []any{"beta"}},
			"object_array":    []any{map[string]any{"name": "beta"}},
		},
	}
	definitions := `
		macro NAME(dictfield) dictfield.name
		macro ZERO(arrayfield) arrayfield[0]
		macro ZNAME(objarray) objarray[0].name
		macro NAMEZ(arrayobj) arrayobj.name[0]
		macro ZNAME2(objarray) NAME(ZERO(objarray))
		macro NAMEZ2(arrayobj) ZERO(NAME(arrayobj))
	`
	queries := []string{
		`process where arrayContains(NAME(object), "alpha")`,
		`process where ZNAME(object_array) == "alpha"`,
		`process where ZNAME2(object_array) == "alpha"`,
		`process where NAMEZ(object) == "alpha"`,
		`process where NAMEZ2(object) == "alpha"`,
		`process where NAMEZ(nested_container.child) == "alpha"`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			result, err := conf.CompareWithDefinitions(context.Background(), pythonRepo, query, definitions, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestDefinitionsCompileErrorOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	cases := []struct {
		name             string
		definitions      string
		query            string
		pythonSubstrings []string
		goSubstring      string
	}{
		{
			name:             "hash comment",
			definitions:      `# comment` + "\n" + `const TARGET = "cmd.exe"`,
			query:            `process where process_name == TARGET`,
			pythonSubstrings: []string{"Error at line:1,column:1"},
			goSubstring:      "expected const or macro definition",
		},
		{
			name:             "duplicate const",
			definitions:      `const TARGET = "cmd.exe"` + "\n" + `const TARGET = "powershell.exe"`,
			query:            `process where process_name == TARGET`,
			pythonSubstrings: []string{"Constant TARGET already defined"},
			goSubstring:      "constant TARGET already defined",
		},
		{
			name:             "non literal const",
			definitions:      `const TARGET = process_name`,
			query:            `process where process_name == TARGET`,
			pythonSubstrings: []string{"Invalid syntax"},
			goSubstring:      "must be a literal",
		},
		{
			name:             "reserved const name",
			definitions:      `const sequence = 1`,
			query:            `process where true`,
			pythonSubstrings: []string{"Invalid use of keyword"},
			goSubstring:      "invalid const name",
		},
		{
			name:             "escaped const name",
			definitions:      "const `and` = 1",
			query:            `process where true`,
			pythonSubstrings: []string{"Error at line:1,column:7"},
			goSubstring:      "invalid const name",
		},
		{
			name:             "reserved macro name",
			definitions:      `macro join() true`,
			query:            `process where true`,
			pythonSubstrings: []string{"Invalid use of keyword"},
			goSubstring:      "invalid macro name",
		},
		{
			name:             "reserved macro parameter",
			definitions:      `macro X(by) true`,
			query:            `process where true`,
			pythonSubstrings: []string{"Invalid use of keyword"},
			goSubstring:      "invalid macro parameter",
		},
		{
			name:             "non boolean where root",
			definitions:      `const COUNT = 1`,
			query:            `process where COUNT`,
			pythonSubstrings: []string{"Expected boolean not number"},
			goSubstring:      "expected boolean not number",
		},
		{
			name:             "macro unknown function",
			definitions:      `macro BAD() wildcrad(process_name, "x")`,
			query:            `process where BAD()`,
			pythonSubstrings: []string{"Unknown function wildcrad"},
			goSubstring:      "unknown function wildcrad",
		},
		{
			name:             "macro child arity",
			definitions:      `macro BAD() length()`,
			query:            `process where BAD()`,
			pythonSubstrings: []string{"Expected at least 1 argument"},
			goSubstring:      "length expects 1 argument",
		},
		{
			name:             "macro arity mismatch",
			definitions:      `macro PROCESS_IS(name) process_name == name`,
			query:            `process where PROCESS_IS()`,
			pythonSubstrings: []string{"expected 1 arguments but received 0"},
			goSubstring:      "expected 1 arguments but received 0",
		},
		{
			name:             "macro invalid path expansion",
			definitions:      `macro VALUE_OF(obj) obj.value`,
			query:            `process where VALUE_OF("x") == "x"`,
			pythonSubstrings: []string{"Invalid expansion"},
			goSubstring:      "invalid expansion",
		},
		{
			name:             "macro references later macro",
			definitions:      `macro FIRST() SECOND()` + "\n" + `macro SECOND() true`,
			query:            `process where FIRST()`,
			pythonSubstrings: []string{"Unknown function SECOND"},
			goSubstring:      "unknown function SECOND",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonErr, err := pythonParseWithDefinitionsError(context.Background(), pythonRepo, tc.query, tc.definitions)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr == "" {
				t.Fatalf("python accepted invalid definitions/query: %q %q", tc.definitions, tc.query)
			}
			for _, want := range tc.pythonSubstrings {
				if !strings.Contains(pythonErr, want) {
					t.Fatalf("python error %q does not contain %q", pythonErr, want)
				}
			}

			_, err = eql.Compile(tc.query, eql.WithDefinitions(tc.definitions))
			if err == nil {
				t.Fatalf("go accepted invalid definitions/query; python error: %s", pythonErr)
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
			if !strings.Contains(err.Error(), tc.goSubstring) {
				t.Fatalf("go error %q does not contain %q", err, tc.goSubstring)
			}
		})
	}
}

func pythonParseWithDefinitionsError(ctx context.Context, pythonRepo string, query string, definitions string) (string, error) {
	payload, err := json.Marshal(map[string]string{"query": query, "definitions": definitions})
	if err != nil {
		return "", err
	}
	script := `
import json
import sys
from eql import get_preprocessor, parse_query
payload = json.load(sys.stdin)
try:
    preprocessor = get_preprocessor(payload["definitions"])
    parse_query(payload["query"], preprocessor=preprocessor)
except Exception as exc:
    print(json.dumps({"ok": False, "error": type(exc).__name__ + ": " + str(exc)}))
else:
    print(json.dumps({"ok": True, "error": ""}))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("python oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var result struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return "", fmt.Errorf("decode python oracle output: %w: %s", err, bytes.TrimSpace(out))
	}
	return result.Error, nil
}
