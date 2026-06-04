package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestCidrMatchInvalidSourceRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "network",
		"source_address":  "bad-ip",
		"serial_event_id": 1,
	}}
	query := `network where cidrMatch(source_address, "0.0.0.0/0")`

	_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err == nil {
		t.Fatal("expected Python runtime error for invalid source IP")
	}
	if !strings.Contains(err.Error(), "does not appear to be an IPv4 or IPv6 address") {
		t.Fatalf("unexpected Python error: %v", err)
	}

	_, err = conf.GoOutputRows(query, events)
	if err == nil {
		t.Fatal("expected Go runtime error for invalid source IP")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "bad-ip") {
		t.Fatalf("Go error %q does not mention invalid source", err)
	}
}

func TestSafeCidrMatchInvalidSourceOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "network",
		"source_address":  "bad-ip",
		"serial_event_id": 1,
	}}
	query := `network where safe(cidrMatch(source_address, "0.0.0.0/0")) == null`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
	if len(result.GoRows) != 1 {
		t.Fatalf("expected safe() to catch invalid source IP and match one event, got %d rows", len(result.GoRows))
	}
}

func TestNumberInvalidStringRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"command_line":    "++314",
		"serial_event_id": 1,
	}}
	query := `process where number(command_line) == null`

	_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err == nil {
		t.Fatal("expected Python runtime error for invalid number string")
	}
	if !strings.Contains(err.Error(), "invalid literal for int()") {
		t.Fatalf("unexpected Python error: %v", err)
	}

	_, err = conf.GoOutputRows(query, events)
	if err == nil {
		t.Fatal("expected Go runtime error for invalid number string")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "++314") {
		t.Fatalf("Go error %q does not mention invalid number string", err)
	}
}

func TestSafeNumberInvalidStringOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"command_line":    "++314",
		"serial_event_id": 1,
	}}
	query := `process where safe(number(command_line)) == null`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
	if len(result.GoRows) != 1 {
		t.Fatalf("expected safe() to catch invalid number string and match one event, got %d rows", len(result.GoRows))
	}
}

func TestNumberInvalidBaseRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"command_line":    "5",
		"base":            1,
		"serial_event_id": 1,
	}}
	query := `process where number(command_line, base) == null`

	_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err == nil {
		t.Fatal("expected Python runtime error for invalid number base")
	}
	if !strings.Contains(err.Error(), "base must be") && !strings.Contains(err.Error(), "invalid base") {
		t.Fatalf("unexpected Python error: %v", err)
	}

	_, err = conf.GoOutputRows(query, events)
	if err == nil {
		t.Fatal("expected Go runtime error for invalid number base")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "base") {
		t.Fatalf("Go error %q does not mention base", err)
	}
}

func TestSafeNumberInvalidBaseOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"command_line":    "5",
		"base":            37,
		"serial_event_id": 1,
	}}
	query := `process where safe(number(command_line, base)) == null`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
	if len(result.GoRows) != 1 {
		t.Fatalf("expected safe() to catch invalid number base and match one event, got %d rows", len(result.GoRows))
	}
}

func TestArrayContainsScalarRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"pid":             10,
		"serial_event_id": 1,
	}}
	query := `process where arrayContains(pid, "x") == null`

	_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err == nil {
		t.Fatal("expected Python runtime error for scalar arrayContains source")
	}
	if !strings.Contains(err.Error(), "not iterable") {
		t.Fatalf("unexpected Python error: %v", err)
	}

	_, err = conf.GoOutputRows(query, events)
	if err == nil {
		t.Fatal("expected Go runtime error for scalar arrayContains source")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "not iterable") {
		t.Fatalf("Go error %q does not mention iterable", err)
	}
}

func TestSafeArrayContainsScalarRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"pid":             10,
		"serial_event_id": 1,
	}}
	query := `process where safe(arrayContains(pid, "x")) == null`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
	if len(result.GoRows) != 1 {
		t.Fatalf("expected safe() to catch scalar arrayContains source and match one event, got %d rows", len(result.GoRows))
	}
}

func TestDynamicNonIntegerFunctionArgumentRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"process_name":    "cmd.exe",
		"command_line":    "10",
		"start":           1.5,
		"serial_event_id": 1,
	}}
	cases := []string{
		`process where substring(process_name, start) == null`,
		`process where indexOf(process_name, "m", start) == null`,
		`process where number(command_line, start) == null`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
			if err == nil {
				t.Fatal("expected Python runtime error for non-integer argument")
			}

			_, err = conf.GoOutputRows(query, events)
			if err == nil {
				t.Fatal("expected Go runtime error for non-integer argument")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeRuntime {
				t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
			}
			if !strings.Contains(err.Error(), "integer") {
				t.Fatalf("Go error %q does not mention integer", err)
			}
		})
	}
}

func TestIndexOfEmptySubstringOutOfRangeStartRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"process_name":    "hello",
		"start":           6,
		"serial_event_id": 1,
	}}
	query := `process where indexOf(process_name, "", start) == null`

	_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err == nil {
		t.Fatal("expected Python runtime error for out-of-range indexOf start")
	}
	if !strings.Contains(err.Error(), "substring not found") {
		t.Fatalf("unexpected Python error: %v", err)
	}

	_, err = conf.GoOutputRows(query, events)
	if err == nil {
		t.Fatal("expected Go runtime error for out-of-range indexOf start")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "substring not found") {
		t.Fatalf("Go error %q does not mention substring not found", err)
	}
}

func TestPipeObjectAndArrayKeyRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	cases := []struct {
		name      string
		query     string
		event     map[string]any
		errorText string
	}{
		{
			name:  "dict key",
			query: `process where true | count nested`,
			event: map[string]any{
				"event_type":      "process",
				"nested":          map[string]any{"k": "A"},
				"serial_event_id": 1,
			},
			errorText: "unhashable type: 'dict'",
		},
		{
			name:  "list key",
			query: `process where true | count values`,
			event: map[string]any{
				"event_type":      "process",
				"values":          []any{"A"},
				"serial_event_id": 1,
			},
			errorText: "unhashable type: 'list'",
		},
		{
			name:  "unique dict key",
			query: `process where true | unique nested`,
			event: map[string]any{
				"event_type":      "process",
				"nested":          map[string]any{"k": "A"},
				"serial_event_id": 1,
			},
			errorText: "unhashable type: 'dict'",
		},
		{
			name:  "tuple containing list key",
			query: `process where true | count process_name, values`,
			event: map[string]any{
				"event_type":      "process",
				"process_name":    "cmd.exe",
				"values":          []any{"A"},
				"serial_event_id": 1,
			},
			errorText: "unhashable type: 'list'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := []map[string]any{tc.event}
			_, err := conf.PythonOutputRows(context.Background(), pythonRepo, tc.query, events)
			if err == nil {
				t.Fatal("expected Python runtime error for unhashable pipe key")
			}
			if !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("unexpected Python error: %v", err)
			}

			_, err = conf.GoOutputRows(tc.query, events)
			if err == nil {
				t.Fatal("expected Go runtime error for unhashable pipe key")
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeRuntime {
				t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
			}
			if !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("Go error %q does not mention %q", err, tc.errorText)
			}
		})
	}
}

func TestListRuntimeKeysMatchOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
	}{
		{
			name:  "unique list key",
			query: `process where true | unique values`,
			events: []map[string]any{{
				"event_type":      "process",
				"values":          []any{"A"},
				"serial_event_id": 1,
			}, {
				"event_type":      "process",
				"values":          []any{"A"},
				"serial_event_id": 2,
			}},
		},
		{
			name:  "unique_count list key",
			query: `process where true | unique_count values`,
			events: []map[string]any{{
				"event_type":      "process",
				"values":          []any{"A"},
				"serial_event_id": 1,
			}, {
				"event_type":      "process",
				"values":          []any{"A"},
				"serial_event_id": 2,
			}},
		},
		{
			name:  "sequence list key",
			query: `sequence by values [process where true] [file where true]`,
			events: []map[string]any{{
				"event_type":      "process",
				"values":          []any{"A"},
				"serial_event_id": 1,
			}, {
				"event_type":      "file",
				"values":          []any{"A"},
				"serial_event_id": 2,
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, tc.query, tc.events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
		})
	}
}

func TestSequenceObjectKeyRuntimeOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"nested":          map[string]any{"k": "A"},
		"serial_event_id": 1,
	}, {
		"event_type":      "file",
		"nested":          map[string]any{"k": "A"},
		"serial_event_id": 2,
	}}
	query := `sequence by nested [process where true] [file where true]`

	_, err := conf.PythonOutputRows(context.Background(), pythonRepo, query, events)
	if err == nil {
		t.Fatal("expected Python runtime error for unhashable sequence key")
	}
	if !strings.Contains(err.Error(), "unhashable type: 'dict'") {
		t.Fatalf("unexpected Python error: %v", err)
	}

	_, err = conf.GoOutputRows(query, events)
	if err == nil {
		t.Fatal("expected Go runtime error for unhashable sequence key")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeRuntime {
		t.Fatalf("expected CodeRuntime, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "unhashable type: 'dict'") {
		t.Fatalf("Go error %q does not mention unhashable dict", err)
	}
}

func TestMultiFieldPrimitiveKeyStillMatchesOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"process_name":    "cmd.exe",
		"pid":             10,
		"serial_event_id": 1,
	}, {
		"event_type":      "process",
		"process_name":    "cmd.exe",
		"pid":             10,
		"serial_event_id": 2,
	}, {
		"event_type":      "process",
		"process_name":    "powershell.exe",
		"pid":             20,
		"serial_event_id": 3,
	}}
	query := `process where true | count process_name, pid`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
}

func TestSafeDynamicNonIntegerFunctionArgumentOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"process_name":    "cmd.exe",
		"command_line":    "10",
		"start":           1.5,
		"serial_event_id": 1,
	}}
	cases := []string{
		`process where safe(substring(process_name, start)) == null`,
		`process where safe(indexOf(process_name, "m", start)) == null`,
		`process where safe(number(command_line, start)) == null`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			result, err := conf.Compare(context.Background(), pythonRepo, query, events)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
			}
			if len(result.GoRows) != 1 {
				t.Fatalf("expected safe() to catch non-integer argument and match one event, got %d rows", len(result.GoRows))
			}
		})
	}
}

func TestSafeIndexOfEmptySubstringOutOfRangeStartOracle(t *testing.T) {
	_, _, pythonRepo := loadMVPFixture(t)
	events := []map[string]any{{
		"event_type":      "process",
		"process_name":    "hello",
		"start":           6,
		"serial_event_id": 1,
	}}
	query := `process where safe(indexOf(process_name, "", start)) == null`

	result, err := conf.Compare(context.Background(), pythonRepo, query, events)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equal() {
		t.Fatalf("output mismatch\npython %v\ngo     %v", result.PythonRows, result.GoRows)
	}
	if len(result.GoRows) != 1 {
		t.Fatalf("expected safe() to catch out-of-range indexOf start and match one event, got %d rows", len(result.GoRows))
	}
}
