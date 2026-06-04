package eql_test

import (
	"errors"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
)

func TestPublicAPI(t *testing.T) {
	rule, err := eql.Compile(`process where process_name == "cmd.exe"`)
	if err != nil {
		t.Fatal(err)
	}
	eng := eql.NewEngine(rule)
	matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":   "process",
		"process_name": "CMD.EXE",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %d", len(matches))
	}
}

func TestPublicCaseSensitiveOption(t *testing.T) {
	rule, err := eql.Compile(`process where process_name == "cmd.exe"`, eql.CaseSensitive())
	if err != nil {
		t.Fatal(err)
	}
	matches, err := eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{
		"event_type":   "process",
		"process_name": "CMD.EXE",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no case-sensitive match, got %d", len(matches))
	}
}

func TestPublicDefinitionsOption(t *testing.T) {
	defs := `
		const TARGET = "cmd.exe"
		const GOOD_PID = 10
		const ENABLED = true
		macro PROCESS_IS(name) process_name == name
		macro TARGET_PROCESS() PROCESS_IS(TARGET)
	`
	rule, err := eql.Compile(`process where TARGET_PROCESS() and pid == GOOD_PID and ENABLED`, eql.WithDefinitions(defs))
	if err != nil {
		t.Fatal(err)
	}
	matches, err := eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{
		"event_type":   "process",
		"process_name": "CMD.EXE",
		"pid":          10,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one definitions-backed match, got %d", len(matches))
	}
}

func TestPublicAllowSampleOption(t *testing.T) {
	if _, err := eql.Compile(`sample [process where true] [file where true]`); err == nil {
		t.Fatal("expected sample to require AllowSample")
	}
	rule, err := eql.Compile(`sample [process where true] [file where true]`, eql.AllowSample(), eql.ElasticsearchSyntax())
	if err != nil {
		t.Fatal(err)
	}
	eng := eql.NewEngine(rule)
	if matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "process",
		"serial_event_id": 1,
	})); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("expected no sample match after first event, got %#v", matches)
	}
	matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "file",
		"serial_event_id": 2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches[0].Events) != 2 {
		t.Fatalf("expected one two-event sample match, got %#v", matches)
	}
}

func TestPublicSequence(t *testing.T) {
	rule, err := eql.Compile(`sequence [process where pid == 10] [file where pid == 10]`)
	if err != nil {
		t.Fatal(err)
	}
	eng := eql.NewEngine(rule)
	if matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "process",
		"serial_event_id": 1,
		"pid":             10,
	})); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("expected no match after first sequence event, got %d", len(matches))
	}
	matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "file",
		"serial_event_id": 2,
		"pid":             10,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches[0].Events) != 2 {
		t.Fatalf("expected one two-event sequence match, got %#v", matches)
	}
}

func TestPublicKeyedSequence(t *testing.T) {
	rule, err := eql.Compile(`sequence by pid [process where true] [file where true]`)
	if err != nil {
		t.Fatal(err)
	}
	eng := eql.NewEngine(rule)
	for _, event := range []map[string]any{
		{"event_type": "process", "pid": 10, "serial_event_id": 1},
		{"event_type": "file", "pid": 20, "serial_event_id": 2},
	} {
		matches, err := eng.Feed(eql.EventFromData(event))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("expected no mismatched-key sequence match, got %#v", matches)
		}
	}
	matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "file",
		"pid":             10,
		"serial_event_id": 3,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches[0].Events) != 2 {
		t.Fatalf("expected one keyed sequence match, got %#v", matches)
	}
}

func TestPublicStageKeyedSequence(t *testing.T) {
	rule, err := eql.Compile(`sequence [process where true] by pid [file where true] by process_id`)
	if err != nil {
		t.Fatal(err)
	}
	eng := eql.NewEngine(rule)
	if matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "process",
		"pid":             10,
		"serial_event_id": 1,
	})); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("expected no first-stage output, got %#v", matches)
	}
	matches, err := eng.Feed(eql.EventFromData(map[string]any{
		"event_type":      "file",
		"process_id":      10,
		"serial_event_id": 2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches[0].Events) != 2 {
		t.Fatalf("expected one stage-keyed sequence match, got %#v", matches)
	}
}

func TestPublicDefinitionsCompileValidation(t *testing.T) {
	cases := []struct {
		name  string
		query string
		defs  string
	}{
		{
			name:  "duplicate const",
			query: `process where TARGET == "cmd.exe"`,
			defs:  `const TARGET = "cmd.exe"` + "\n" + `const TARGET = "powershell.exe"`,
		},
		{
			name:  "non literal const",
			query: `process where TARGET == "cmd.exe"`,
			defs:  `const TARGET = process_name`,
		},
		{
			name:  "macro unknown function",
			query: `process where X()`,
			defs:  `macro X() wildcrad(process_name, "x")`,
		},
		{
			name:  "macro arity mismatch",
			query: `process where X()`,
			defs:  `macro X(name) process_name == name`,
		},
		{
			name:  "macro path extension requires field",
			query: `process where X("name") == "cmd.exe"`,
			defs:  `macro X(obj) obj.name`,
		},
		{
			name:  "expanded non boolean where root",
			query: `process where COUNT`,
			defs:  `const COUNT = 1`,
		},
		{
			name:  "sequence partial stage by unsupported",
			query: `sequence [process where true] by pid [file where true]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := eql.Compile(tc.query, eql.WithDefinitions(tc.defs))
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
}

func TestPublicCompileSequencePipes(t *testing.T) {
	if _, err := eql.Compile(`sequence [process where true] [file where true] | head 1`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicCompileOptimizesConstants(t *testing.T) {
	rule, err := eql.Compile(`process where true and 7 / 3 == 2 and "Foo" == "foo"`)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{"event_type": "process"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected optimized constant query to match, got %d", len(matches))
	}

	rule, err = eql.Compile(`process where "Foo" == "foo"`, eql.CaseSensitive())
	if err != nil {
		t.Fatal(err)
	}
	matches, err = eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{"event_type": "process"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected case-sensitive optimized constant query not to match, got %d", len(matches))
	}
}

func TestPublicEventNormalizer(t *testing.T) {
	ev := eql.EventFromDataWithNormalizer(map[string]any{"kind": "process"}, func(data map[string]any) *eql.Event {
		return &eql.Event{Type: data["kind"].(string), Data: data}
	})
	if ev.Type != "process" {
		t.Fatalf("unexpected normalized type %q", ev.Type)
	}
}

func TestPublicCompileErrorType(t *testing.T) {
	_, err := eql.Compile(`sequence [process where true]`)
	if err == nil {
		t.Fatal("expected compile error")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeParse {
		t.Fatalf("expected CodeParse, got %d", appErr.Code)
	}
}

func TestPublicCompileSyntaxErrorDiagnostic(t *testing.T) {
	query := `process where and`
	_, err := eql.Compile(query)
	if err == nil {
		t.Fatal("expected compile error")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeParse {
		t.Fatalf("expected CodeParse, got %d", appErr.Code)
	}
	diagnostic, ok := appErr.Diagnostic()
	if !ok {
		t.Fatal("expected parser diagnostic")
	}
	if diagnostic.Class != eql.DiagnosticClassSyntax {
		t.Fatalf("Class=%q, want %q", diagnostic.Class, eql.DiagnosticClassSyntax)
	}
	if diagnostic.Message != "expected expression" {
		t.Fatalf("Message=%q, want %q", diagnostic.Message, "expected expression")
	}
	if want := strings.Index(query, "and"); diagnostic.Pos != want {
		t.Fatalf("Pos=%d, want %d", diagnostic.Pos, want)
	}
	if diagnostic.Line != 1 || diagnostic.Column != 15 {
		t.Fatalf("Line/Column=%d/%d, want 1/15", diagnostic.Line, diagnostic.Column)
	}
	if diagnostic.Source != query {
		t.Fatalf("Source=%q, want %q", diagnostic.Source, query)
	}
	if diagnostic.Width != len("and") {
		t.Fatalf("Width=%d, want %d", diagnostic.Width, len("and"))
	}
	if !strings.Contains(diagnostic.Caret, "^^^") {
		t.Fatalf("Caret=%q, want caret marker", diagnostic.Caret)
	}
	text := err.Error()
	for _, want := range []string{
		"parse query",
		"Error at line:1,column:15",
		"process where and",
		"^^^",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("compile error %q does not contain %q", text, want)
		}
	}
}

func TestPublicCompileSemanticDiagnostic(t *testing.T) {
	cases := []struct {
		query       string
		function    string
		messageText string
	}{
		{
			query:       `process where length()`,
			function:    "length",
			messageText: "length expects 1 argument",
		},
		{
			query:       `process where wildcrad(process_name, "x")`,
			function:    "wildcrad",
			messageText: "unknown function wildcrad",
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			_, err := eql.Compile(tc.query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
			diagnostic, ok := appErr.Diagnostic()
			if !ok {
				t.Fatal("expected semantic diagnostic")
			}
			if diagnostic.Class != eql.DiagnosticClassSemantic {
				t.Fatalf("Class=%q, want %q", diagnostic.Class, eql.DiagnosticClassSemantic)
			}
			if !strings.Contains(diagnostic.Message, tc.messageText) {
				t.Fatalf("Message=%q, want %q", diagnostic.Message, tc.messageText)
			}
			assertSourceDiagnostic(t, diagnostic, tc.query, tc.function)
		})
	}
}

func TestPublicSchemaDiagnostic(t *testing.T) {
	schema := map[string]map[string]any{"process": {"pid": "number"}}
	cases := []struct {
		query string
		token string
	}{
		{query: `process where missing == 1`, token: "missing"},
		{query: `process where nested.path == 1`, token: "nested.path"},
		{query: `process where arr[0] == 1`, token: "arr[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			_, err := eql.Compile(tc.query, eql.WithSchema(schema))
			if err == nil {
				t.Fatal("expected schema compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
			d, ok := appErr.Diagnostic()
			if !ok {
				t.Fatal("expected schema diagnostic")
			}
			if d.Class != eql.DiagnosticClassSchema {
				t.Fatalf("Class=%q, want %q", d.Class, eql.DiagnosticClassSchema)
			}
			assertSourceDiagnostic(t, d, tc.query, tc.token)
		})
	}
}

func TestPublicTypeMismatchDiagnostic(t *testing.T) {
	schema := map[string]map[string]any{"process": {"pid": "number", "process_name": "string"}}
	cases := []struct {
		query   string
		token   string
		message string
		schema  bool
	}{
		{
			query:   `process where length(1)`,
			token:   "1",
			message: "length argument 1 must be string literal",
		},
		{
			query:   `process where pid == "1"`,
			token:   "==",
			message: "invalid comparison of number to string",
			schema:  true,
		},
		{
			query:   `process where 1 + process_name == 2`,
			token:   "process_name",
			message: "math right operand expected number not string",
			schema:  true,
		},
		{
			query:   `process where length(pid) == 3`,
			token:   "pid",
			message: "expected compatible type not number",
			schema:  true,
		},
		{
			query:   "process where true | head \"x\"",
			token:   "\"x\"",
			message: "head argument must be a positive integer literal",
		},
		{
			query:   `process where true | unique 1`,
			token:   "1",
			message: "unique argument 1 must be dynamic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			var opts []eql.RuleOption
			if tc.schema {
				opts = append(opts, eql.WithSchema(schema))
			}
			_, err := eql.Compile(tc.query, opts...)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
			d, ok := appErr.Diagnostic()
			if !ok {
				t.Fatal("expected type mismatch diagnostic")
			}
			if d.Class != eql.DiagnosticClassTypeMismatch {
				t.Fatalf("Class=%q, want %q", d.Class, eql.DiagnosticClassTypeMismatch)
			}
			if !strings.Contains(d.Message, tc.message) {
				t.Fatalf("Message=%q, want %q", d.Message, tc.message)
			}
			assertSourceDiagnostic(t, d, tc.query, tc.token)
		})
	}
}

func TestPublicRuntimeDiagnosticFalse(t *testing.T) {
	rule, err := eql.Compile(`network where cidrMatch(source_address, "0.0.0.0/0")`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{
		"event_type":     "network",
		"source_address": "bad-ip",
	}))
	if err == nil {
		t.Fatal("expected runtime error")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if diagnostic, ok := appErr.Diagnostic(); ok {
		t.Fatalf("expected no parser diagnostic, got %#v", diagnostic)
	}
}

func assertNoSourceDiagnostic(t *testing.T, diagnostic eql.ErrorDiagnostic) {
	t.Helper()
	if diagnostic.Pos != 0 || diagnostic.Line != 0 || diagnostic.Column != 0 || diagnostic.Width != 0 ||
		diagnostic.Source != "" || diagnostic.Caret != "" {
		t.Fatalf("expected no source span, got %#v", diagnostic)
	}
}

func assertSourceDiagnostic(t *testing.T, diagnostic eql.ErrorDiagnostic, query string, token string) {
	t.Helper()
	pos := strings.Index(query, token)
	if pos < 0 {
		t.Fatalf("test bug: %q not in %q", token, query)
	}
	if diagnostic.Pos != pos {
		t.Fatalf("Pos=%d, want %d", diagnostic.Pos, pos)
	}
	if diagnostic.Line != 1 || diagnostic.Column != pos+1 {
		t.Fatalf("Line/Column=%d/%d, want 1/%d", diagnostic.Line, diagnostic.Column, pos+1)
	}
	if diagnostic.Source != query {
		t.Fatalf("Source=%q, want %q", diagnostic.Source, query)
	}
	if diagnostic.Width != len(token) {
		t.Fatalf("Width=%d, want %d", diagnostic.Width, len(token))
	}
	if !strings.Contains(diagnostic.Caret, strings.Repeat("^", len(token))) {
		t.Fatalf("Caret=%q, want marker for %q", diagnostic.Caret, token)
	}
}

func TestPublicCidrCompileValidation(t *testing.T) {
	cases := []string{
		`network where cidrMatch(source_address)`,
		`network where cidrMatch(source_address, cidr_field)`,
		`network where cidrMatch(source_address, "not-cidr")`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`network where cidrMatch(source_address, "10.6.48.157/8")`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicDynamicArrayCompileValidation(t *testing.T) {
	cases := []string{
		`registry where arraySearch(bytes_written_string_list, s)`,
		`registry where arraySearch(bytes_written_string_list, s.name, s == "en-US")`,
		`registry where arrayCount(bytes_written_string_list, "s", s == "en-US") == 1`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`registry where arraySearch(bytes_written_string_list, s, s == "en-US")`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicSafeCompileValidation(t *testing.T) {
	cases := []string{
		`process where safe()`,
		`process where safe(pid == 10, true)`,
		`process where safe(wildcrad(process_name, "x"))`,
		`process where safe(length())`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`process where safe(pid == 10)`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicFunctionCompileValidation(t *testing.T) {
	cases := []string{
		`process where wildcrad(process_name, "x")`,
		`process where length()`,
		`process where startsWith(process_name)`,
		`process where number("1", 10, 10) == 1`,
		`process where concat()`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`process where length(process_name) == 7`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicFunctionLiteralTypeValidation(t *testing.T) {
	cases := []string{
		`process where length(1) == null`,
		`process where startsWith(1, "x")`,
		`process where startsWith("x", 1)`,
		`process where match(1, "*")`,
		`process where match("eql", 1)`,
		`process where number(1) == null`,
		`process where number("1", true) == null`,
		`process where indexOf("x", "x", 1.5) == null`,
		`process where substring("x", 1.5) == null`,
		`process where between("abc", "a", "b", 1) == null`,
		`process where safe(length(1)) == null`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`process where substring("hello world", null, 5) == "hello"`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicComparisonLiteralTypeValidation(t *testing.T) {
	cases := []string{
		`process where true < false`,
		`process where true > null`,
		`process where null < true`,
		`process where "x" < 1`,
		`process where 1 < "x"`,
		`process where "x" == 1`,
		`process where true == 1`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`process where true == null`); err != nil {
		t.Fatal(err)
	}
	if _, err := eql.Compile(`process where process_name == 10`); err != nil {
		t.Fatal(err)
	}
}

func TestPublicPipeCompileValidation(t *testing.T) {
	cases := []string{
		`process where true | head 0`,
		`process where true | head 1.5`,
		`process where true | tail 0`,
		`process where true | tail -1`,
		`process where true | tail 1.5`,
		`process where true | sort`,
		`process where true | unique`,
		`process where true | unique_count`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := eql.Compile(query)
			if err == nil {
				t.Fatal("expected compile error")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
		})
	}
	if _, err := eql.Compile(`process where true | filter serial_event_id >= 1 | head 2 | sort pid | tail 1 | unique process_name | count process_name | unique_count key`); err != nil {
		t.Fatal(err)
	}
}

func TestAppErrorMethods(t *testing.T) {
	base := errors.New("base")
	err := eql.WrapError(eql.CodeRuntime, "runtime", base)
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if !errors.Is(err, base) {
		t.Fatal("expected wrapped base error")
	}
	if appErr.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
	if eql.WrapError(eql.CodeRuntime, "noop", nil) != nil {
		t.Fatal("nil error should stay nil")
	}
	if eql.WrapError(eql.CodeRuntime, "again", err) != err {
		t.Fatal("AppError should not be wrapped twice")
	}
	if diagnostic, ok := appErr.Diagnostic(); ok {
		t.Fatalf("expected no runtime diagnostic, got %#v", diagnostic)
	}
}

func TestAppErrorDiagnosticEdgeCases(t *testing.T) {
	var nilErr *eql.AppError
	if diagnostic, ok := nilErr.Diagnostic(); ok {
		t.Fatalf("expected no nil diagnostic, got %#v", diagnostic)
	}
	manualErr := &eql.AppError{Code: eql.CodeParse, Msg: "x"}
	if diagnostic, ok := manualErr.Diagnostic(); ok {
		t.Fatalf("expected no manual diagnostic, got %#v", diagnostic)
	}
	wrapped := eql.WrapError(eql.CodeRuntime, "runtime", errors.New("base"))
	var appErr *eql.AppError
	if !errors.As(wrapped, &appErr) {
		t.Fatalf("expected AppError, got %T", wrapped)
	}
	if diagnostic, ok := appErr.Diagnostic(); ok {
		t.Fatalf("expected no wrapped runtime diagnostic, got %#v", diagnostic)
	}
}

func TestZeroValueEngine(t *testing.T) {
	var eng eql.Engine
	matches, err := eng.Feed(eql.EventFromData(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
	matches, err = eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no finalized matches, got %d", len(matches))
	}
}

func TestPublicFinalize(t *testing.T) {
	eng := eql.NewEngine()
	matches, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no finalized matches, got %d", len(matches))
	}
}

func TestAppErrorNilMethods(t *testing.T) {
	var appErr *eql.AppError
	if appErr.Unwrap() != nil {
		t.Fatal("nil AppError should unwrap to nil")
	}
	if appErr.Error() == "" {
		t.Fatal("nil AppError should have an error string")
	}
	err := (&eql.AppError{Code: eql.CodeRuntime, Msg: "runtime"}).Error()
	if err == "" {
		t.Fatal("expected error string")
	}
}

func TestImpliedAnyOption(t *testing.T) {
	// A bare boolean expression should fail without ImpliedAny.
	if _, err := eql.Compile(`true`); err == nil {
		t.Fatal("expected parse error for bare expression without ImpliedAny")
	}

	// With ImpliedAny, a bare expression is compiled as "any where <expr>".
	rule, err := eql.Compile(`true`, eql.ImpliedAny())
	if err != nil {
		t.Fatalf("ImpliedAny: %v", err)
	}
	matches, err := eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{
		"event_type": "process",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one match from implied-any query, got %d", len(matches))
	}

	// Bare expression with a pipe.
	rule, err = eql.Compile(`true | unique event_type`, eql.ImpliedAny())
	if err != nil {
		t.Fatalf("ImpliedAny with pipe: %v", err)
	}
	eng := eql.NewEngine(rule)
	var allImpliedAnyMatches []eql.Match
	for _, et := range []string{"process", "process", "file"} {
		m, err := eng.Feed(eql.EventFromData(map[string]any{"event_type": et}))
		if err != nil {
			t.Fatal(err)
		}
		allImpliedAnyMatches = append(allImpliedAnyMatches, m...)
	}
	final, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	allImpliedAnyMatches = append(allImpliedAnyMatches, final...)
	if len(allImpliedAnyMatches) != 2 {
		t.Fatalf("expected 2 unique event_type matches, got %d", len(allImpliedAnyMatches))
	}
}

func TestImpliedBaseOption(t *testing.T) {
	// A pipe-only query should fail without ImpliedBase.
	if _, err := eql.Compile(`| unique event_type`); err == nil {
		t.Fatal("expected parse error for pipe-only query without ImpliedBase")
	}

	// With ImpliedBase, "|..." is compiled as "any where true | ...".
	rule, err := eql.Compile(`| unique event_type`, eql.ImpliedBase())
	if err != nil {
		t.Fatalf("ImpliedBase: %v", err)
	}
	eng := eql.NewEngine(rule)
	var allImpliedBaseMatches []eql.Match
	for _, et := range []string{"process", "process", "file"} {
		m, err := eng.Feed(eql.EventFromData(map[string]any{"event_type": et}))
		if err != nil {
			t.Fatal(err)
		}
		allImpliedBaseMatches = append(allImpliedBaseMatches, m...)
	}
	final, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	allImpliedBaseMatches = append(allImpliedBaseMatches, final...)
	if len(allImpliedBaseMatches) != 2 {
		t.Fatalf("expected 2 unique event_type matches from implied-base, got %d", len(allImpliedBaseMatches))
	}
}

func TestImpliedAnyDoesNotAffectNormalQuery(t *testing.T) {
	// A normal event-type query must still work when ImpliedAny is set.
	rule, err := eql.Compile(`process where true`, eql.ImpliedAny(), eql.ImpliedBase())
	if err != nil {
		t.Fatalf("normal query with implied options: %v", err)
	}
	matches, err := eql.NewEngine(rule).Feed(eql.EventFromData(map[string]any{
		"event_type": "process",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %d", len(matches))
	}
}
