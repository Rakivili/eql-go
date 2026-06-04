package engine

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/parser"
)

func TestMVPEventFromData(t *testing.T) {
	ev := EventFromData(map[string]any{
		"data_buffer": map[string]any{
			"event_type_full": "process_event",
			"timestamp":       123,
			"process_name":    "cmd.exe",
		},
	})
	if ev.Type != "process" || ev.Timestamp != 123 {
		t.Fatalf("unexpected event normalization: %#v", ev)
	}
}

func TestMVPEventFromDataVariations(t *testing.T) {
	cases := []struct {
		name string
		data map[string]any
		typ  string
		ts   int64
	}{
		{name: "nil data", typ: EventTypeGeneric},
		{name: "event type", data: map[string]any{"event_type": "file"}, typ: "file"},
		{name: "json timestamp", data: map[string]any{"timestamp": json.Number("42")}, typ: EventTypeGeneric, ts: 42},
		{name: "float timestamp", data: map[string]any{"timestamp": 42.8}, typ: EventTypeGeneric, ts: 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EventFromData(tc.data)
			if ev.Type != tc.typ || ev.Timestamp != tc.ts {
				t.Fatalf("unexpected event: %#v", ev)
			}
		})
	}
}

func TestMVPEventNormalizer(t *testing.T) {
	ev := EventFromDataWithNormalizer(map[string]any{"kind": "process"}, func(data map[string]any) *Event {
		return &Event{Type: data["kind"].(string), Data: data}
	})
	if ev.Type != "process" {
		t.Fatalf("unexpected normalized type %q", ev.Type)
	}
}

func TestMVPMatch(t *testing.T) {
	q, err := parser.ParseQuery(`process where process_name == "cmd.exe" and pid == 10`)
	if err != nil {
		t.Fatal(err)
	}
	rule := NewRule(q)
	ev := EventFromData(map[string]any{
		"event_type":   "process",
		"process_name": "CMD.EXE",
		"pid":          10,
	})
	ok, err := rule.Match(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected match")
	}
}

func TestMVPNoMatchForNilAndWrongType(t *testing.T) {
	rule := compileRule(t, `process where true`)
	if ok, err := rule.Match(nil); err != nil || ok {
		t.Fatalf("nil event ok=%v err=%v", ok, err)
	}
	ev := EventFromData(map[string]any{"event_type": "file"})
	if ok, err := rule.Match(ev); err != nil || ok {
		t.Fatalf("wrong type ok=%v err=%v", ok, err)
	}
}

func TestMatchPythonRegexFeatures(t *testing.T) {
	tests := []struct {
		name  string
		query string
		value string
		want  bool
	}{
		{
			name:  "backreference",
			query: `process where match(command_line, ?'(a)\1')`,
			value: "aa",
			want:  true,
		},
		{
			name:  "lookahead",
			query: `process where matchLite(command_line, ?'(?=a)a')`,
			value: "abc",
			want:  true,
		},
		{
			name:  "fixed lookbehind",
			query: `process where match(command_line, ?'a(?<=a)b')`,
			value: "ab",
			want:  true,
		},
		{
			name:  "named backreference",
			query: `process where match(command_line, ?'(?P<word>a)(?P=word)')`,
			value: "aa",
			want:  true,
		},
		{
			name:  "anchored at start",
			query: `process where match(command_line, ?'(a)\1')`,
			value: "xaa",
			want:  false,
		},
		{
			name:  "variadic patterns OR together",
			query: `process where match(command_line, ?'z+', ?'(a)\1')`,
			value: "aa",
			want:  true,
		},
		{
			name:  "variadic patterns preserve joined captures",
			query: `process where match(command_line, ?'(b)', ?'(a)\1')`,
			value: "aa",
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := compileRule(t, tc.query)
			ev := EventFromData(map[string]any{
				"event_type":    "process",
				"command_line":  tc.value,
				"process_name":  "cmd.exe",
				"serial_number": 1,
			})
			got, err := rule.Match(ev)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Match()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnyEventTypeMatchesAllEvents(t *testing.T) {
	rule := compileRule(t, `any where true`)
	for _, data := range []map[string]any{
		{"event_type": "process"},
		{"event_type": "file"},
		{"event_type_full": "network_event"},
		{},
	} {
		ok, err := rule.Match(EventFromData(data))
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("expected any query to match %#v", data)
		}
	}
}

func TestMVPCaseSensitiveOption(t *testing.T) {
	rule := compileRule(t, `process where process_name == "cmd.exe"`, CaseSensitive())
	ev := EventFromData(map[string]any{"event_type": "process", "process_name": "CMD.EXE"})
	ok, err := rule.Match(ev)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected case-sensitive mismatch")
	}
}

func TestElasticsearchSyntaxDisablesWildcardEquality(t *testing.T) {
	rule := compileRule(t, `process where process_name == "cmd*"`, ElasticsearchSyntax())
	ev := EventFromData(map[string]any{"event_type": "process", "process_name": "cmd.exe"})
	ok, err := rule.Match(ev)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("Elasticsearch syntax should keep wildcard-looking equality exact")
	}
}

func TestMVPExpressionSemantics(t *testing.T) {
	data := map[string]any{
		"event_type":          "process",
		"process_name":        "CMD.EXE",
		"parent_process_name": "cmd.exe",
		"command_line":        "C:/Windows/System32/cmd.exe /c whoami",
		"pid":                 json.Number("10"),
		"zero":                0,
		"nested":              map[string]any{"value": 7},
		"items":               []any{"a"},
		"string_items":        []any{"a", "b"},
		"string_map":          map[string]any{"k": "v"},
		"numbers":             []any{1, 2},
		"mixed":               []any{nil, "x"},
		"empty_items":         []any{},
		"exp_number":          json.Number("1e10"),
		"large_number":        json.Number("9007199254740993"),
		"source_address":      "10.6.48.157",
		"mysterious_field": map[string]any{
			"outer_cross_match": "*",
			"subarray": []any{
				map[string]any{
					"a":           "s0-a",
					"cross_match": "s0-c1-x-z",
					"c": []any{
						map[string]any{"x": map[string]any{"y": "*"}, "z": "s0-c1-x-z"},
						map[string]any{"x": map[string]any{"y": "no"}, "z": "other"},
					},
				},
				map[string]any{
					"a":           "s1-a",
					"cross_match": "missing",
					"c":           []any{map[string]any{"x": map[string]any{"y": "none"}, "z": "none"}},
				},
			},
		},
	}
	cases := []struct {
		query string
		want  bool
	}{
		{query: `process where missing == null`, want: true},
		{query: `process where missing != null`},
		{query: `process where process_name == null`},
		{query: `process where process_name != null`, want: true},
		{query: `process where missing in (null)`},
		{query: `process where missing not in (null)`},
		{query: `process where process_name in (null)`},
		{query: `process where missing > 1`},
		{query: `process where pid == 10.0`, want: true},
		{query: `process where pid >= 10 and pid < 11`, want: true},
		{query: `process where process_name == "cmd.exe"`, want: true},
		{query: `process where process_name in ("cmd.exe", "powershell.exe")`, want: true},
		{query: `process where process_name not in ("cmd.exe", "powershell.exe")`},
		{query: `process where process_name in (parent_process_name, "powershell.exe")`, want: true},
		{query: `process where process_name not in (parent_process_name, "powershell.exe")`},
		{query: `process where length(process_name) == 7`, want: true},
		{query: `process where length(items) == 1`, want: true},
		{query: `process where length(nested) == 1`, want: true},
		{query: `process where length(missing) == null`, want: true},
		{query: `process where wildcard(process_name, "cmd*")`, want: true},
		{query: `process where wildcard(process_name, "powershell*", "cmd*")`, want: true},
		{query: `process where startsWith(process_name, "cmd")`, want: true},
		{query: `process where endsWith(process_name, ".exe")`, want: true},
		{query: `process where stringContains(command_line, "WHOAMI")`, want: true},
		{query: `process where match(command_line, ?'.*?whoami')`, want: true},
		{query: `process where matchLite(command_line, ?'.*?WHOAMI')`, want: true},
		{query: `process where match(command_line, ?'.*?missing')`},
		{query: `process where match(missing, ?'.*')`},
		{query: `process where string(null) == null`, want: true},
		{query: `process where string(1) == "1"`, want: true},
		{query: `process where string(true) == "true"`, want: true},
		{query: `process where string(exp_number) == "10000000000.0"`, want: true},
		{query: `process where string(string_items) == "['a', 'b']"`, want: true},
		{query: `process where string(string_map) == "{'k': 'v'}"`, want: true},
		{query: `process where number("314") == 314`, want: true},
		{query: `process where number("3.14") == 3.14`, want: true},
		{query: `process where number("0x32", 16) == 50`, want: true},
		{query: `process where number("32", 16) == 50`, want: true},
		{query: `process where number("bad") == null`, want: true},
		{query: `process where concat("a", "||", 1, "||", true, "||", "b") == "a||1||true||b"`, want: true},
		{query: `process where concat(string_items, "") == "['a', 'b']"`, want: true},
		{query: `process where concat(null) == null`, want: true},
		{query: `process where large_number == 9007199254740993`, want: true},
		{query: `process where large_number == 9007199254740992`},
		{query: `process where large_number > 9007199254740992`, want: true},
		{query: `process where add(pid, 5) == 15`, want: true},
		{query: `process where subtract(pid, -5) == 15`, want: true},
		{query: `process where multiply(6, pid) == 60`, want: true},
		{query: `process where divide(30, 4.0) == 7.5`, want: true},
		{query: `process where divide(pid, 3) == 3`, want: true},
		{query: `process where modulo(11, add(pid, 1)) == 0`, want: true},
		{query: `process where divide(pid, 0) == null`, want: true},
		{query: `process where pid + 1 == 11`, want: true},
		{query: `process where pid - 1 == 9`, want: true},
		{query: `process where pid * 2 == 20`, want: true},
		{query: `process where pid / 3 == 3`, want: true},
		{query: `process where pid / 2.0 == 5`, want: true},
		{query: `process where pid % 4 == 2`, want: true},
		{query: `process where pid + 2 * 3 == 16`, want: true},
		{query: `process where (pid + 2) * 3 == 36`, want: true},
		{query: `process where pid / 0 == null`, want: true},
		{query: `process where arrayContains(items, "A")`, want: true},
		{query: `process where arrayContains(items, "b")`},
		{query: `process where arrayContains(items, "b", "a")`, want: true},
		{query: `process where arrayContains(numbers, 2.0)`, want: true},
		{query: `process where arrayContains(mixed, null)`, want: true},
		{query: `process where arrayContains(process_name, "c")`, want: true},
		{query: `process where arrayContains(nested, "value")`, want: true},
		{query: `process where arrayContains(missing, "a")`},
		{query: `process where arrayContains(missing, "a") == null`, want: true},
		{query: `process where arraySearch(items, item, item == "A")`, want: true},
		{query: `process where arraySearch(items, item, item == "missing")`},
		{query: `process where arrayCount(items, item, item == "A") == 1`, want: true},
		{query: `process where arrayCount(missing, item, item == "A") == 0`, want: true},
		{query: `process where arraySearch(mysterious_field.subarray, s, s.a == "s0-*")`, want: true},
		{query: `process where arraySearch(mysterious_field.subarray, s, s.a != "s0-*")`, want: true},
		{query: `process where arraySearch(mysterious_field.subarray, sub1, arraySearch(sub1.c, nested, nested.x.y == "*"))`, want: true},
		{query: `process where arraySearch(mysterious_field.subarray, sub1, sub1.a == "s0-a" and arraySearch(sub1.c, nested, nested.z == sub1.cross_match))`, want: true},
		{query: `process where arraySearch(mysterious_field.subarray, sub1, arraySearch(sub1.c, nested, nested.x.y == mysterious_field.outer_cross_match))`, want: true},
		{query: `process where safe(pid == 10)`, want: true},
		{query: `process where safe(unknownFunc()) == null`, want: true},
		{query: `process where indexOf(process_name, "md") == 1`, want: true},
		{query: `process where indexOf(process_name, "missing") == null`, want: true},
		{query: `process where indexOf(process_name, "md", 2) == null`, want: true},
		{query: `process where substring(process_name, 1, 3) == "md"`, want: true},
		{query: `process where substring(process_name, -4) == ".exe"`, want: true},
		{query: `process where substring(process_name, -4, -1) == ".ex"`, want: true},
		{query: `process where between("System Idle Process", "s", "e") == "yst"`, want: true},
		{query: `process where between("System Idle Process", "s", "e", true) == "ystem Idle Proc"`, want: true},
		{query: `process where between(process_name, "g", "z") == null`, want: true},
		{query: `process where cidrMatch(source_address, "10.6.48.157/8")`, want: true},
		{query: `process where cidrMatch(source_address, "192.168.0.0/16")`},
		{query: `process where cidrMatch(source_address, "192.168.0.0/16", "10.6.48.157/8")`, want: true},
		{query: `process where process_name == "cmd*"`, want: true},
		{query: `process where process_name != "cmd*"`},
		{query: `process where "cmd*" == process_name`, want: true},
		{query: `process where "cmd*" != process_name`},
		{query: `process where process_name > "aaa"`, want: true},
		{query: `process where process_name == 10`},
		{query: `process where nested.value == 7`, want: true},
		{query: `process where items[0] == "a"`, want: true},
		{query: `process where items[2] == null`, want: true},
		{query: `process where false or pid == 10`, want: true},
		{query: `process where null or false`},
		{query: `process where null and true`},
		{query: `process where not null`},
		{query: `process where true in (true)`, want: true},
		{query: `process where true not in (true)`},
		{query: `process where missing in ("x")`},
		{query: `process where missing not in ("x")`},
		{query: `process where null in (null)`, want: true},
		{query: `process where null not in (null)`},
		{query: `process where pid`, want: true},
		{query: `process where zero`},
		{query: `process where items`, want: true},
		{query: `process where empty_items`},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			ok, err := compileRule(t, tc.query).Match(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Fatalf("match=%v, want %v", ok, tc.want)
			}
		})
	}
}

func TestRawNullComparisonPropagatesNull(t *testing.T) {
	ev := EventFromData(map[string]any{
		"event_type":   "process",
		"process_name": "cmd.exe",
	})
	expr := &ast.Comparison{
		Left:  &ast.Field{Base: "process_name"},
		Op:    "!=",
		Right: &ast.Literal{Kind: ast.LiteralNull},
	}
	got, err := eval(expr, ev, defaultRuleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("raw null comparison=%v, want nil", got)
	}
}

func TestInSetNullPropagation(t *testing.T) {
	cases := []struct {
		name  string
		query string
		data  map[string]any
	}{
		{
			name:  "dynamic null item",
			query: `process where process_name in (parent_process_name, "cmd.exe")`,
			data:  map[string]any{"event_type": "process", "process_name": "powershell.exe"},
		},
		{
			name:  "dynamic null item under not in",
			query: `process where process_name not in (parent_process_name, "cmd.exe")`,
			data:  map[string]any{"event_type": "process", "process_name": "powershell.exe"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := compileRule(t, tc.query)
			ev := EventFromData(tc.data)
			got, err := evalScoped(rule.query.Expr, ev, rule.config, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != nil {
				t.Fatalf("expression value=%v, want nil", got)
			}
			matched, err := rule.Match(ev)
			if err != nil {
				t.Fatal(err)
			}
			if matched {
				t.Fatal("null expression should not match")
			}
		})
	}
}

func TestInSetLiteralNullMatches(t *testing.T) {
	for _, query := range []string{
		`process where null in (null)`,
		`process where null in (null, "x")`,
	} {
		t.Run(query, func(t *testing.T) {
			rule := compileRule(t, query)
			matched, err := rule.Match(EventFromData(map[string]any{"event_type": "process"}))
			if err != nil {
				t.Fatal(err)
			}
			if !matched {
				t.Fatal("expected literal null membership to match")
			}
		})
	}
}

func TestNumericAndTruthHelpers(t *testing.T) {
	for _, v := range []any{
		ast.Int(1),
		json.Number("1"),
		1,
		int8(1),
		int16(1),
		int32(1),
		int64(1),
		uint(1),
		uint8(1),
		uint16(1),
		uint32(1),
		uint64(1),
		float32(1),
		float64(1),
	} {
		if n, ok := numberFloat(v); !ok || n != 1 {
			t.Fatalf("numberFloat(%T)=(%v,%v)", v, n, ok)
		}
		if ok, isNull := truthy(v); !ok || isNull {
			t.Fatalf("truthy(%T)=(%v,%v)", v, ok, isNull)
		}
	}
	if _, ok := numberFloat(json.Number("bad")); ok {
		t.Fatal("invalid json.Number should not parse")
	}
	if ok, isNull := truthy(json.Number("bad")); ok || !isNull {
		t.Fatalf("invalid json.Number truthy=(%v,%v)", ok, isNull)
	}
	for _, v := range []any{
		ast.Int(2),
		json.Number("2"),
		2,
		int32(2),
		float32(2),
		float64(2),
	} {
		if got := toInt64(v); got != 2 {
			t.Fatalf("toInt64(%T)=%d", v, got)
		}
	}
	if got := toInt64(json.Number("bad")); got != 0 {
		t.Fatalf("bad json.Number toInt64=%d", got)
	}
}

func TestConversionFunctionHelpers(t *testing.T) {
	stringCases := []struct {
		value any
		want  any
	}{
		{value: nil, want: nil},
		{value: false, want: "false"},
		{value: ast.Float(1.0), want: "1.0"},
		{value: ast.Float(2.5), want: "2.5"},
		{value: ast.Float(1e10), want: "10000000000.0"},
		{value: json.Number("3.14"), want: "3.14"},
		{value: json.Number("1e10"), want: "10000000000.0"},
		{value: json.Number("1.5e10"), want: "15000000000.0"},
		{value: json.Number("42"), want: "42"},
		{value: []any{"a", "b"}, want: "['a', 'b']"},
		{value: map[string]any{"k": "v"}, want: "{'k': 'v'}"},
		{value: int8(-1), want: "-1"},
		{value: int16(-2), want: "-2"},
		{value: int32(-3), want: "-3"},
		{value: int64(-4), want: "-4"},
		{value: uint(1), want: "1"},
		{value: uint8(2), want: "2"},
		{value: uint16(3), want: "3"},
		{value: uint32(4), want: "4"},
		{value: uint64(5), want: "5"},
		{value: float32(1), want: "1.0"},
		{value: float32(1.25), want: "1.25"},
		{value: float64(6), want: "6.0"},
		{value: float64(6.5), want: "6.5"},
		{value: float64(1e10), want: "10000000000.0"},
		{value: struct{ Name string }{Name: "x"}, want: "{x}"},
	}
	for _, tc := range stringCases {
		if got := stringValue(tc.value); got != tc.want {
			t.Fatalf("stringValue(%T)=%v, want %v", tc.value, got, tc.want)
		}
	}

	numberCases := []struct {
		source       string
		base         int64
		explicitBase bool
		want         any
	}{
		{source: "0x2a", base: 10, want: ast.Int(42)},
		{source: "-42", base: 10, want: ast.Int(-42)},
		{source: "+42", base: 10, want: ast.Int(42)},
		{source: "2.5", base: 10, want: ast.Float(2.5)},
		{source: "101", base: 2, explicitBase: true, want: ast.Int(5)},
		{source: "0X2a", base: 10, want: nil},
		{source: "010", base: 0, explicitBase: true, want: ast.Int(10)},
		{source: "0x10", base: 0, explicitBase: true, want: nil},
		{source: "bad", base: 10, want: nil},
		{source: "bad", base: 1, explicitBase: true, want: nil},
		{source: "1.2", base: 1, explicitBase: true, want: nil},
		{source: "2.5", base: 2, explicitBase: true, want: nil},
	}
	for _, tc := range numberCases {
		got, err := parseNumberFunction(tc.source, tc.base, tc.explicitBase)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("parseNumberFunction(%q,%d,%v)=%v, want %v", tc.source, tc.base, tc.explicitBase, got, tc.want)
		}
	}
	for _, tc := range []struct {
		source       string
		base         int64
		explicitBase bool
	}{
		{source: "0xzz", base: 10},
		{source: "89", base: 8, explicitBase: true},
		{source: "++314", base: 10},
		{source: "1", base: 1, explicitBase: true},
		{source: "1", base: -1, explicitBase: true},
		{source: "1", base: 37, explicitBase: true},
	} {
		if _, err := parseNumberFunction(tc.source, tc.base, tc.explicitBase); err == nil {
			t.Fatalf("parseNumberFunction(%q,%d,%v) expected error", tc.source, tc.base, tc.explicitBase)
		}
	}
	for _, source := range []string{"", "+", "-", "12x"} {
		if isSignedDigits(source) {
			t.Fatalf("isSignedDigits(%q)=true, want false", source)
		}
	}
}

func TestFunctionErrorAndEdgePaths(t *testing.T) {
	if _, err := fnString(nil); err == nil {
		t.Fatal("fnString should reject missing arguments")
	}
	if got, err := fnNumber([]any{true}); err != nil || got != nil {
		t.Fatalf("fnNumber(non-string)=(%v,%v), want nil,nil", got, err)
	}
	if got, err := fnNumber([]any{"10", ast.Float(2)}); err == nil || got != nil {
		t.Fatalf("fnNumber(float base)=(%v,%v), want nil,error", got, err)
	}
	if _, err := fnNumber(nil); err == nil {
		t.Fatal("fnNumber should reject missing arguments")
	}
	if _, err := fnConcat(nil); err == nil {
		t.Fatal("fnConcat should reject missing arguments")
	}
	if got, err := fnMath([]any{"x", ast.Int(1)}, "add"); err != nil || got != nil {
		t.Fatalf("fnMath(non-number)=(%v,%v), want nil,nil", got, err)
	}
	if _, err := fnMath([]any{ast.Int(1)}, "add"); err == nil {
		t.Fatal("fnMath should reject wrong arity")
	}
	if _, err := fnMath([]any{ast.Int(1), ast.Int(1)}, "unknown"); err == nil {
		t.Fatal("fnMath should reject unknown math function")
	}
	mathCases := []struct {
		name string
		op   string
		args []any
		want any
	}{
		{name: "subtract float", op: "subtract", args: []any{ast.Float(10.5), ast.Int(2)}, want: ast.Float(8.5)},
		{name: "multiply float", op: "multiply", args: []any{ast.Float(2.5), ast.Int(4)}, want: ast.Float(10)},
		{name: "divide ints", op: "divide", args: []any{ast.Int(5), ast.Int(2)}, want: ast.Int(2)},
		{name: "divide negative ints", op: "divide", args: []any{ast.Int(-5), ast.Int(2)}, want: ast.Int(-3)},
		{name: "divide zero", op: "divide", args: []any{ast.Int(1), ast.Int(0)}, want: nil},
		{name: "modulo negative ints", op: "modulo", args: []any{ast.Int(-5), ast.Int(2)}, want: ast.Int(1)},
		{name: "modulo float", op: "modulo", args: []any{ast.Float(5.5), ast.Int(2)}, want: ast.Float(1.5)},
	}
	for _, tc := range mathCases {
		got, err := fnMath(tc.args, tc.op)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("fnMath(%s)=%v, want %v", tc.name, got, tc.want)
		}
	}
	if _, err := fnMath([]any{ast.Int(1), ast.Int(0)}, "modulo"); err == nil {
		t.Fatal("fnMath modulo by zero should return error")
	}
}

func TestArrayContainsFunction(t *testing.T) {
	defaultCfg := defaultRuleConfig()
	got, err := fnArrayContains([]any{[]string{"Alpha"}, "alpha"}, defaultCfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("case-insensitive typed slice match=%v, want true", got)
	}
	got, err = fnArrayContains([]any{[]string{"Alpha"}, "alpha"}, ruleConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got != false {
		t.Fatalf("case-sensitive typed slice match=%v, want false", got)
	}
	got, err = fnArrayContains([]any{[]int{1, 2}, ast.Float(2)}, defaultCfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("numeric typed slice match=%v, want true", got)
	}
	got, err = fnArrayContains([]any{"not-array", "n"}, defaultCfg)
	if err != nil || got != true {
		t.Fatalf("string source=(%v,%v), want true,nil", got, err)
	}
	got, err = fnArrayContains([]any{map[string]any{"key": "value"}, "key"}, defaultCfg)
	if err != nil || got != true {
		t.Fatalf("map source=(%v,%v), want true,nil", got, err)
	}
	if got, err = fnArrayContains([]any{ast.Int(1), "x"}, defaultCfg); err == nil || got != nil {
		t.Fatalf("scalar source=(%v,%v), want nil,error", got, err)
	}
	if _, err := fnArrayContains([]any{[]any{"x"}}, defaultCfg); err == nil {
		t.Fatal("fnArrayContains should reject missing value arguments")
	}
	if !arrayValuesEqual(nil, nil, defaultCfg) {
		t.Fatal("nil array values should compare equal")
	}
}

func TestArrayContainsCaseSensitiveRule(t *testing.T) {
	rule := compileRule(t, `process where arrayContains(items, "A")`, CaseSensitive())
	ev := EventFromData(map[string]any{"event_type": "process", "items": []any{"a"}})
	ok, err := rule.Match(ev)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected case-sensitive arrayContains mismatch")
	}
}

func TestDynamicArrayFunctions(t *testing.T) {
	ev := EventFromData(map[string]any{
		"event_type": "process",
		"items":      []any{"a", "b"},
	})
	cfg := defaultRuleConfig()
	searchCall := &ast.FunctionCall{
		Name: "arraySearch",
		Args: []ast.Expr{
			&ast.Field{Base: "items"},
			&ast.Field{Base: "item"},
			&ast.Comparison{
				Left:  &ast.Field{Base: "item"},
				Op:    "==",
				Right: &ast.Literal{Kind: ast.LiteralString, Value: "A"},
			},
		},
	}
	got, err := evalFunction(searchCall, ev, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("arraySearch=%v, want true", got)
	}

	countCall := &ast.FunctionCall{
		Name: "arrayCount",
		Args: []ast.Expr{
			&ast.Field{Base: "items"},
			&ast.Field{Base: "item"},
			&ast.Comparison{
				Left:  &ast.Field{Base: "item"},
				Op:    "!=",
				Right: &ast.Literal{Kind: ast.LiteralString, Value: "missing"},
			},
		},
	}
	got, err = evalFunction(countCall, ev, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != ast.Int(2) {
		t.Fatalf("arrayCount=%v, want 2", got)
	}

	missingCall := &ast.FunctionCall{Name: "arrayCount", Args: []ast.Expr{
		&ast.Field{Base: "missing"},
		&ast.Field{Base: "item"},
		&ast.Literal{Kind: ast.LiteralBool, Value: true},
	}}
	got, err = evalFunction(missingCall, ev, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != ast.Int(0) {
		t.Fatalf("arrayCount missing=%v, want 0", got)
	}

	badCalls := []*ast.FunctionCall{
		{Name: "arraySearch", Args: []ast.Expr{&ast.Field{Base: "items"}}},
		{Name: "arraySearch", Args: []ast.Expr{&ast.Field{Base: "items"}, &ast.Literal{Kind: ast.LiteralString, Value: "item"}, &ast.Literal{Kind: ast.LiteralBool, Value: true}}},
		{Name: "arrayCount", Args: []ast.Expr{&ast.Field{Base: "items"}}},
	}
	for _, call := range badCalls {
		if _, err := evalFunction(call, ev, cfg, nil); err == nil {
			t.Fatalf("expected error for %#v", call)
		}
	}
	if name, ok := variableName(&ast.Field{Base: "item"}); !ok || name != "item" {
		t.Fatalf("variableName=(%q,%v), want item,true", name, ok)
	}
	if _, ok := variableName(&ast.Field{Base: "item", Path: []ast.PathPart{{Name: "x"}}}); ok {
		t.Fatal("field path should not be accepted as variable name")
	}
}

func TestDynamicArrayCaseSensitiveRule(t *testing.T) {
	rule := compileRule(t, `process where arraySearch(items, item, item == "A")`, CaseSensitive())
	ev := EventFromData(map[string]any{"event_type": "process", "items": []any{"a"}})
	ok, err := rule.Match(ev)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected case-sensitive arraySearch mismatch")
	}
}

func TestSafeFunction(t *testing.T) {
	ev := EventFromData(map[string]any{"event_type": "process", "pid": 10})
	cfg := defaultRuleConfig()
	call := &ast.FunctionCall{Name: "safe", Args: []ast.Expr{
		&ast.Comparison{
			Left:  &ast.Field{Base: "pid"},
			Op:    "==",
			Right: &ast.Literal{Kind: ast.LiteralNumber, Value: ast.Int(10)},
		},
	}}
	got, err := evalFunction(call, ev, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("safe comparison=%v, want true", got)
	}

	call = &ast.FunctionCall{Name: "safe", Args: []ast.Expr{
		&ast.FunctionCall{Name: "unknownFunc"},
	}}
	got, err = evalFunction(call, ev, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("safe unknown function=%v, want nil", got)
	}

	if _, err := evalFunction(&ast.FunctionCall{Name: "safe"}, ev, cfg, nil); err == nil {
		t.Fatal("expected safe arity error")
	}
}

func TestStringRangeFunctions(t *testing.T) {
	cfg := defaultRuleConfig()
	cases := []struct {
		name string
		call func() (any, error)
		want any
	}{
		{name: "index start", call: func() (any, error) {
			return fnIndexOf([]any{"Explorer.exe", "plorer.", ast.Int(2)}, cfg)
		}, want: ast.Int(2)},
		{name: "index negative start", call: func() (any, error) {
			return fnIndexOf([]any{"Explorer.exe", ".exe", ast.Int(-4)}, cfg)
		}, want: ast.Int(8)},
		{name: "index null start", call: func() (any, error) {
			return fnIndexOf([]any{"foobarbaz", "o", nil}, cfg)
		}, want: ast.Int(1)},
		{name: "index empty at end", call: func() (any, error) {
			return fnIndexOf([]any{"hello", "", ast.Int(5)}, cfg)
		}, want: ast.Int(5)},
		{name: "index missing", call: func() (any, error) {
			return fnIndexOf([]any{"Explorer.exe", ".pf"}, cfg)
		}, want: nil},
		{name: "substring null bounds", call: func() (any, error) {
			return fnSubstring([]any{"hello world", nil, nil})
		}, want: "hello world"},
		{name: "substring null start", call: func() (any, error) {
			return fnSubstring([]any{"hello world", nil, ast.Int(5)})
		}, want: "hello"},
		{name: "substring null end", call: func() (any, error) {
			return fnSubstring([]any{"hello world", ast.Int(6), nil})
		}, want: "world"},
		{name: "substring negative start", call: func() (any, error) {
			return fnSubstring([]any{"Explorer.exe", ast.Int(-4)})
		}, want: ".exe"},
		{name: "substring negative range", call: func() (any, error) {
			return fnSubstring([]any{"Explorer.exe", ast.Int(-4), ast.Int(-1)})
		}, want: ".ex"},
		{name: "substring clamps inverted range", call: func() (any, error) {
			return fnSubstring([]any{"Explorer.exe", ast.Int(4), ast.Int(1)})
		}, want: ""},
		{name: "between non-greedy", call: func() (any, error) {
			return fnBetween([]any{"System Idle Process", "s", "e"}, cfg)
		}, want: "yst"},
		{name: "between greedy", call: func() (any, error) {
			return fnBetween([]any{"System Idle Process", "s", "e", true}, cfg)
		}, want: "ystem Idle Proc"},
		{name: "between null greedy is false", call: func() (any, error) {
			return fnBetween([]any{"abcbd", "a", "b", nil}, cfg)
		}, want: ""},
		{name: "between dynamic truthy greedy", call: func() (any, error) {
			return fnBetween([]any{"abcbd", "a", "b", ast.Int(1)}, cfg)
		}, want: "bc"},
		{name: "between missing", call: func() (any, error) {
			return fnBetween([]any{"System Idle Process", "g", "z"}, cfg)
		}, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	errorCases := []struct {
		name string
		call func() (any, error)
	}{
		{name: "index arity", call: func() (any, error) { return fnIndexOf([]any{"x"}, cfg) }},
		{name: "substring arity", call: func() (any, error) { return fnSubstring([]any{"x"}) }},
		{name: "between arity", call: func() (any, error) { return fnBetween([]any{"x"}, cfg) }},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if got, err := fnIndexOf([]any{nil, "x"}, cfg); err != nil || got != nil {
		t.Fatalf("index non-string=(%v,%v), want nil,nil", got, err)
	}
	if got, err := fnIndexOf([]any{"x", nil}, cfg); err != nil || got != nil {
		t.Fatalf("index non-string substring=(%v,%v), want nil,nil", got, err)
	}
	if got, err := fnIndexOf([]any{"x", "x", ast.Float(0)}, cfg); err == nil || got != nil {
		t.Fatalf("index float start=(%v,%v), want nil,error", got, err)
	}
	if got, err := fnIndexOf([]any{"hello", "", ast.Int(6)}, cfg); err == nil || got != nil {
		t.Fatalf("index empty out-of-range start=(%v,%v), want nil,error", got, err)
	}
	if got, err := fnSubstring([]any{nil, ast.Int(0)}); err != nil || got != nil {
		t.Fatalf("substring non-string=(%v,%v), want nil,nil", got, err)
	}
	if got, err := fnSubstring([]any{"x", ast.Float(0)}); err == nil || got != nil {
		t.Fatalf("substring float start=(%v,%v), want nil,error", got, err)
	}
	if got, err := fnSubstring([]any{"x", ast.Int(0), ast.Float(1)}); err == nil || got != nil {
		t.Fatalf("substring float end=(%v,%v), want nil,error", got, err)
	}
	if got, err := fnBetween([]any{nil, "x", "y"}, cfg); err != nil || got != nil {
		t.Fatalf("between non-string source=(%v,%v), want nil,nil", got, err)
	}
	if got, err := fnBetween([]any{"x", nil, "y"}, cfg); err != nil || got != nil {
		t.Fatalf("between non-string left=(%v,%v), want nil,nil", got, err)
	}
	if got, err := fnBetween([]any{"x", "x", nil}, cfg); err != nil || got != nil {
		t.Fatalf("between non-string right=(%v,%v), want nil,nil", got, err)
	}
}

func TestStringRangeCaseSensitiveRule(t *testing.T) {
	ev := EventFromData(map[string]any{"event_type": "process", "process_name": "CMD.EXE"})
	cases := []string{
		`process where indexOf(process_name, "md") == 1`,
		`process where substring(process_name, 1, 3) == "md"`,
		`process where between("System Idle Process", "s", "e") == "yst"`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			ok, err := compileRule(t, query, CaseSensitive()).Match(ev)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				t.Fatal("expected case-sensitive mismatch")
			}
		})
	}
}

func TestCidrMatchFunction(t *testing.T) {
	cases := []struct {
		name    string
		args    []any
		want    any
		wantErr bool
	}{
		{name: "single match", args: []any{"10.6.48.157", "10.6.48.157/8"}, want: true},
		{name: "multi match", args: []any{"10.6.48.157", "192.168.0.0/16", "10.6.48.157/8"}, want: true},
		{name: "no match", args: []any{"10.6.48.157", "192.168.0.0/16"}, want: false},
		{name: "bad source", args: []any{"bad-ip", "0.0.0.0/0"}, wantErr: true},
		{name: "non-string source", args: []any{10, "0.0.0.0/0"}, want: false},
		{name: "non-string cidr", args: []any{"10.6.48.157", 10}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fnCidrMatch(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	if _, err := fnCidrMatch([]any{"10.6.48.157"}); err == nil {
		t.Fatal("expected arity error")
	}
	if _, err := fnCidrMatch([]any{"10.6.48.157", "not-cidr"}); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
	prefix, err := parseCIDRPrefix(" 10.6.48.157/8 ")
	if err != nil {
		t.Fatal(err)
	}
	if got := prefix.String(); got != "10.0.0.0/8" {
		t.Fatalf("masked prefix=%q, want 10.0.0.0/8", got)
	}
}

func TestCompareHelpers(t *testing.T) {
	cases := []struct {
		left  any
		op    string
		right any
		want  any
	}{
		{left: "CMD", op: "==", right: "cmd", want: true},
		{left: "\u0130", op: "==", right: "i", want: false},
		{left: "\u0130", op: "==", right: "i\u0307", want: true},
		{left: "b", op: ">=", right: "a", want: true},
		{left: 10, op: "!=", right: json.Number("11"), want: true},
		{left: json.Number("9007199254740993"), op: "==", right: json.Number("9007199254740993"), want: true},
		{left: json.Number("9007199254740993"), op: "==", right: json.Number("9007199254740992"), want: false},
		{left: json.Number("9007199254740993"), op: ">", right: json.Number("9007199254740992"), want: true},
		{left: json.Number("9007199254740993"), op: "==", right: json.Number("9007199254740992.0"), want: true},
		{left: true, op: "==", right: true, want: true},
		{left: []any{"a"}, op: "==", right: []any{"a"}, want: true},
		{left: true, op: "<", right: true, want: nil},
		{left: "a", op: "==", right: 1, want: nil},
	}
	for _, tc := range cases {
		got := compare(tc.left, tc.right, tc.op, true, true)
		if got != tc.want {
			t.Fatalf("compare(%v %s %v)=%v, want %v", tc.left, tc.op, tc.right, got, tc.want)
		}
	}
}

func TestJSONNumberStringFormat(t *testing.T) {
	// B-41: json.Number fields with scientific notation should format via
	// pythonFloatString (same as Python str(float)), not as raw tokens.
	cases := []struct {
		name  string
		query string
		data  map[string]any
		want  bool
	}{
		{
			name:  "json.Number 1e10 in string() matches Python formatted value",
			query: `process where string(x) == "10000000000.0"`,
			data:  map[string]any{"event_type": "process", "x": json.Number("1e10")},
			want:  true,
		},
		{
			name:  "json.Number 1e10 does not match raw token string",
			query: `process where string(x) == "1e10"`,
			data:  map[string]any{"event_type": "process", "x": json.Number("1e10")},
			want:  false,
		},
		{
			name:  "json.Number integer 42 formats as integer",
			query: `process where string(x) == "42"`,
			data:  map[string]any{"event_type": "process", "x": json.Number("42")},
			want:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			matches, err := eng.Feed(EventFromData(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			got := len(matches) > 0
			if got != tc.want {
				t.Fatalf("query matched=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestLargeIntegerComparison(t *testing.T) {
	// B-39: integers > 2^53 must not lose precision through float64 conversion.
	const bigInt = int64(9007199254740993) // 2^53 + 1
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   []int
	}{
		{
			name:  "exact equality matches large integer",
			query: `process where pid == 9007199254740993`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": json.Number("9007199254740993")},
				{"event_type": "process", "serial_event_id": 2, "pid": json.Number("9007199254740992")},
			},
			want: []int{1},
		},
		{
			name:  "greater-than distinguishes large integers",
			query: `process where pid > 9007199254740992`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": json.Number("9007199254740993")},
				{"event_type": "process", "serial_event_id": 2, "pid": json.Number("9007199254740992")},
			},
			want: []int{1},
		},
	}
	_ = bigInt
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var got []int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("matches=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestEngineFeedAndFinalize(t *testing.T) {
	eng := New(compileRule(t, `process where true`), nil)
	matches, err := eng.Feed(EventFromData(map[string]any{"event_type": "process"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %d", len(matches))
	}
	if out, err := eng.Finalize(); err != nil || len(out) != 0 {
		t.Fatalf("Finalize()=(%v,%v), want no output", out, err)
	}
}

func TestRepeatedFinalizeReplaysPlainReducers(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 20}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 10}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 30}),
	}
	cases := []struct {
		query string
		ids   []int
		data  []map[string]any
	}{
		{query: `process where true | tail 2`, ids: []int{2, 3}},
		{query: `process where true | sort pid`, ids: []int{2, 1, 3}},
		{query: `process where true | count`, data: []map[string]any{{"count": int64(3), "key": "totals"}}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			for _, ev := range events {
				if _, err := eng.Feed(ev); err != nil {
					t.Fatal(err)
				}
			}
			first, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			second, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			if tc.ids != nil {
				if got := appendMatchIDs(nil, first); !reflect.DeepEqual(got, tc.ids) {
					t.Fatalf("first ids=%v, want %v", got, tc.ids)
				}
				if got := appendMatchIDs(nil, second); !reflect.DeepEqual(got, tc.ids) {
					t.Fatalf("second ids=%v, want %v", got, tc.ids)
				}
				return
			}
			if got := matchData(first); !reflect.DeepEqual(got, tc.data) {
				t.Fatalf("first data=%#v, want %#v", got, tc.data)
			}
			if got := matchData(second); !reflect.DeepEqual(got, tc.data) {
				t.Fatalf("second data=%#v, want %#v", got, tc.data)
			}
		})
	}
}

func TestRepeatedFinalizeKeyedAggregateEOFState(t *testing.T) {
	hostEvents := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe", "hostname": "h1"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "process_name": "CMD.EXE", "hostname": "h1"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "process_name": "powershell.exe", "hostname": "h2"}),
	}
	hostlessEvents := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "process_name": "CMD.EXE"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "process_name": "powershell.exe"}),
	}
	for _, query := range []string{
		`process where true | count process_name`,
		`process where true | unique_count process_name`,
	} {
		t.Run(query+" hostful replay", func(t *testing.T) {
			eng := New(compileRule(t, query))
			for _, ev := range hostEvents {
				if _, err := eng.Feed(ev); err != nil {
					t.Fatal(err)
				}
			}
			first, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			second, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stripVolatileFields(matchData(second)), stripVolatileFields(matchData(first))) {
				t.Fatalf("second finalize did not replay first output\nfirst=%#v\nsecond=%#v", matchData(first), matchData(second))
			}
		})

		t.Run(query+" hostless second eof error", func(t *testing.T) {
			eng := New(compileRule(t, query))
			for _, ev := range hostlessEvents {
				if _, err := eng.Feed(ev); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := eng.Finalize(); err != nil {
				t.Fatal(err)
			}
			if _, err := eng.Finalize(); err == nil || !strings.Contains(err.Error(), "KeyError: 'hosts'") {
				t.Fatalf("second Finalize() err=%v, want KeyError for missing hosts", err)
			}
		})
	}
}

func TestRepeatedFinalizeAfterHeadEarlyEOFStaysClosed(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 20}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 10}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 30}),
	}
	cases := []struct {
		query   string
		feedIDs []int
		feed    []map[string]any
	}{
		{query: `process where true | head 2 | tail 1`, feedIDs: []int{2}},
		{query: `process where true | head 2 | count`, feed: []map[string]any{{"count": int64(2), "key": "totals"}}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var feedIDs []int
			var feedData []map[string]any
			for _, ev := range events {
				matches, err := eng.Feed(ev)
				if err != nil {
					t.Fatal(err)
				}
				feedIDs = appendMatchIDs(feedIDs, matches)
				feedData = append(feedData, matchData(matches)...)
			}
			if tc.feedIDs != nil && !reflect.DeepEqual(feedIDs, tc.feedIDs) {
				t.Fatalf("feed ids=%v, want %v", feedIDs, tc.feedIDs)
			}
			if tc.feed != nil && !reflect.DeepEqual(feedData, tc.feed) {
				t.Fatalf("feed data=%#v, want %#v", feedData, tc.feed)
			}
			for i := 0; i < 2; i++ {
				matches, err := eng.Finalize()
				if err != nil {
					t.Fatal(err)
				}
				if got := matchData(matches); len(got) != 0 {
					t.Fatalf("Finalize #%d data=%#v, want none", i+1, got)
				}
			}
		})
	}
}

func TestEngineFeedSkipsNilRules(t *testing.T) {
	eng := New(nil)
	matches, err := eng.Feed(EventFromData(map[string]any{"event_type": "process"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}

func TestEvalExpression(t *testing.T) {
	expr := &ast.MathOperation{
		Left:  &ast.Literal{Kind: ast.LiteralNumber, Value: ast.Int(7)},
		Op:    "/",
		Right: &ast.Literal{Kind: ast.LiteralNumber, Value: ast.Int(3)},
	}
	got, err := EvalExpression(expr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != ast.Int(2) {
		t.Fatalf("EvalExpression()=%v, want 2", got)
	}
}

func TestStreamingPipes(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 20, "process_name": "PowerShell.EXE"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 0, "process_name": "rundll32.exe"}),
		EventFromData(map[string]any{"event_type": "file", "serial_event_id": 4, "pid": 10}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 5, "pid": 4, "process_name": "CMD.EXE"}),
	}
	cases := []struct {
		query string
		want  []int
	}{
		{query: `process where true | head 2`, want: []int{1, 2}},
		{query: `process where true | filter serial_event_id >= 2 | head 2`, want: []int{2, 3}},
		{query: `process where true | filter events[0].pid == pid`, want: nil},
		{query: `process where true | unique pid > 0`, want: []int{1, 3}},
		{query: `process where true | unique process_name`, want: []int{1, 2, 3}},
		{query: `process where true | tail 2`, want: []int{3, 5}},
		{query: `process where true | head 2 | tail 1`, want: []int{2}},
		{query: `process where true | tail 2 | head 1`, want: []int{3}},
		{query: `process where true | filter serial_event_id >= 2 | tail 2`, want: []int{3, 5}},
		{query: `process where true | tail 3 | unique process_name | head 2`, want: []int{2, 3}},
		{query: `process where true | sort pid`, want: []int{3, 5, 1, 2}},
		{query: `process where true | sort process_name`, want: []int{1, 5, 2, 3}},
		{query: `process where true | sort pid | tail 2`, want: []int{1, 2}},
		{query: `process where true | tail 3 | sort pid | head 2`, want: []int{3, 5}},
		{query: `any where true | unique event_type`, want: []int{1, 4}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var got []int
			for _, ev := range events {
				matches, err := eng.Feed(ev)
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			matches, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestHeadPropagatesEOFToDownstreamPipes(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 20, "process_name": "cmd.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "powershell.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 30, "process_name": "rundll32.exe"}),
	}
	cases := []struct {
		query       string
		wantFeedIDs []int
		wantFinal   []int
	}{
		{query: `process where true | head 2 | tail 1`, wantFeedIDs: []int{2}},
		{query: `process where true | head 2 | sort pid`, wantFeedIDs: []int{2, 1}},
		{query: `process where true | head 2 | unique_count process_name`, wantFeedIDs: []int{1, 2}},
		{query: `process where true | head 2 | tail 1 | tail 1`, wantFeedIDs: []int{2}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var gotFeedIDs []int
			for _, ev := range events {
				matches, err := eng.Feed(ev)
				if err != nil {
					t.Fatal(err)
				}
				gotFeedIDs = appendMatchIDs(gotFeedIDs, matches)
			}
			if !reflect.DeepEqual(gotFeedIDs, tc.wantFeedIDs) {
				t.Fatalf("feed ids=%v, want %v", gotFeedIDs, tc.wantFeedIDs)
			}
			matches, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			gotFinal := appendMatchIDs(nil, matches)
			if !reflect.DeepEqual(gotFinal, tc.wantFinal) {
				t.Fatalf("final ids=%v, want %v", gotFinal, tc.wantFinal)
			}
		})
	}
}

func TestHeadPropagatesEOFToDownstreamCount(t *testing.T) {
	eng := New(compileRule(t, `process where true | head 2 | count`))
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 20, "process_name": "cmd.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "powershell.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 30, "process_name": "rundll32.exe"}),
	}
	var gotFeed []map[string]any
	for _, ev := range events {
		matches, err := eng.Feed(ev)
		if err != nil {
			t.Fatal(err)
		}
		gotFeed = append(gotFeed, matchData(matches)...)
	}
	wantFeed := []map[string]any{{"count": int64(2), "key": "totals"}}
	if !reflect.DeepEqual(gotFeed, wantFeed) {
		t.Fatalf("feed data=%#v, want %#v", gotFeed, wantFeed)
	}
	matches, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if gotFinal := matchData(matches); len(gotFinal) != 0 {
		t.Fatalf("final data=%#v, want none", gotFinal)
	}
}

func TestHeadPropagatesEOFToDownstreamGroupPipes(t *testing.T) {
	eng := New(compileRule(t, `sequence by pid [process where true] [file where true] | head 1 | tail 1`))
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 10}),
		EventFromData(map[string]any{"event_type": "file", "serial_event_id": 2, "pid": 10}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 20}),
		EventFromData(map[string]any{"event_type": "file", "serial_event_id": 4, "pid": 20}),
	}
	var gotFeedIDs []int
	for _, ev := range events {
		matches, err := eng.Feed(ev)
		if err != nil {
			t.Fatal(err)
		}
		gotFeedIDs = appendMatchIDs(gotFeedIDs, matches)
	}
	if want := []int{1, 2}; !reflect.DeepEqual(gotFeedIDs, want) {
		t.Fatalf("feed ids=%v, want %v", gotFeedIDs, want)
	}
	matches, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if gotFinal := appendMatchIDs(nil, matches); len(gotFinal) != 0 {
		t.Fatalf("final ids=%v, want none", gotFinal)
	}
}

func TestSortPipeErrorForAllNullSingleKey(t *testing.T) {
	eng := New(compileRule(t, `process where true | sort missing`))
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2}),
	}
	for _, ev := range events {
		if _, err := eng.Feed(ev); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := eng.Finalize(); err == nil {
		t.Fatal("expected sort error for all-null single key")
	}
}

func TestCountPipe(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe", "hostname": "Host-B"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 11, "process_name": "CMD.EXE", "hostname": "host-a"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 12, "process_name": "powershell.exe", "hostname": "host-a"}),
		EventFromData(map[string]any{"hostname": "host-a", "serial_event_id": 4}),
	}
	cases := []struct {
		query string
		want  []map[string]any
	}{
		{
			query: `process where true | count`,
			want: []map[string]any{{
				"count":       int64(3),
				"hosts":       []string{"Host-B", "host-a"},
				"key":         "totals",
				"total_hosts": int64(2),
			}},
		},
		{
			query: `process where false | count`,
			want:  []map[string]any{{"count": int64(0), "key": "totals"}},
		},
		{
			query: `process where true | count process_name`,
			want: []map[string]any{
				{"count": int64(1), "hosts": []string{"host-a"}, "key": "powershell.exe", "percent": json.Number("0.3333333333333333"), "total_hosts": int64(1)},
				{"count": int64(2), "hosts": []string{"Host-B", "host-a"}, "key": "cmd.exe", "percent": json.Number("0.6666666666666666"), "total_hosts": int64(2)},
			},
		},
		{
			query: `process where true | count process_name | tail 1`,
			want: []map[string]any{
				{"count": int64(2), "hosts": []string{"Host-B", "host-a"}, "key": "cmd.exe", "percent": json.Number("0.6666666666666666"), "total_hosts": int64(2)},
			},
		},
		{
			query: `generic where true | count hostname`,
			want: []map[string]any{
				{"count": int64(1), "hosts": []string{"host-a"}, "key": "host-a", "percent": json.Number("1.0"), "total_hosts": int64(1)},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			for _, ev := range events {
				if _, err := eng.Feed(ev); err != nil {
					t.Fatal(err)
				}
			}
			matches, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			got := matchData(matches)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("data=%#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestCountPipeCaseSensitiveKeys(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "process_name": "CMD.EXE"}),
	}
	eng := New(compileRule(t, `process where true | count process_name`, CaseSensitive()))
	for _, ev := range events {
		if _, err := eng.Feed(ev); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	got := matchData(matches)
	want := []map[string]any{
		{"count": int64(1), "key": "CMD.EXE", "percent": json.Number("0.5")},
		{"count": int64(1), "key": "cmd.exe", "percent": json.Number("0.5")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("data=%#v, want %#v", got, want)
	}
}

func TestUniqueCountPipe(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe", "hostname": "Host-B"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 2, "pid": 11, "process_name": "CMD.EXE", "hostname": "host-a"}),
		EventFromData(map[string]any{"event_type": "process", "serial_event_id": 3, "pid": 12, "process_name": "powershell.exe", "hostname": "host-a"}),
		EventFromData(map[string]any{"hostname": "host-a", "serial_event_id": 4}),
	}
	cases := []struct {
		query string
		want  []map[string]any
	}{
		{
			query: `process where true | unique_count process_name`,
			want: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe", "count": int64(2), "hosts": []string{"Host-B", "host-a"}, "percent": json.Number("0.6666666666666666"), "total_hosts": int64(2)},
				{"event_type": "process", "serial_event_id": 3, "pid": 12, "process_name": "powershell.exe", "count": int64(1), "hosts": []string{"host-a"}, "percent": json.Number("0.3333333333333333"), "total_hosts": int64(1)},
			},
		},
		{
			query: `process where true | unique_count pid > 11`,
			want: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe", "count": int64(2), "hosts": []string{"Host-B", "host-a"}, "percent": json.Number("0.6666666666666666"), "total_hosts": int64(2)},
				{"event_type": "process", "serial_event_id": 3, "pid": 12, "process_name": "powershell.exe", "count": int64(1), "hosts": []string{"host-a"}, "percent": json.Number("0.3333333333333333"), "total_hosts": int64(1)},
			},
		},
		{
			query: `process where true | count process_name | unique_count key`,
			want: []map[string]any{
				{"count": int64(1), "hosts": []string{"host-a"}, "key": "powershell.exe", "percent": json.Number("0.3333333333333333"), "total_hosts": int64(1)},
				{"count": int64(2), "hosts": []string{"Host-B", "host-a"}, "key": "cmd.exe", "percent": json.Number("0.6666666666666666"), "total_hosts": int64(2)},
			},
		},
		{
			query: `generic where true | unique_count hostname`,
			want: []map[string]any{
				{"serial_event_id": 4, "count": int64(1), "hosts": []string{"host-a"}, "percent": json.Number("1.0"), "total_hosts": int64(1)},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			for _, ev := range events {
				if _, err := eng.Feed(ev); err != nil {
					t.Fatal(err)
				}
			}
			matches, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			got := stripVolatileFields(matchData(matches))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("data=%#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestUniqueCountPipePreservesFloatCounts(t *testing.T) {
	events := []*Event{
		EventFromData(map[string]any{"event_type": "generic", "serial_event_id": 1, "process_name": "cmd.exe", "count": 1.5}),
		EventFromData(map[string]any{"event_type": "generic", "serial_event_id": 2, "process_name": "cmd.exe", "count": 2.25}),
		EventFromData(map[string]any{"event_type": "generic", "serial_event_id": 3, "process_name": "powershell.exe", "count": 2.5}),
	}
	eng := New(compileRule(t, `generic where true | unique_count process_name`))
	for _, ev := range events {
		if _, err := eng.Feed(ev); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := eng.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	got := stripVolatileFields(matchData(matches))
	want := []map[string]any{
		{"event_type": "generic", "serial_event_id": 1, "process_name": "cmd.exe", "count": 3.75, "percent": json.Number("0.6")},
		{"event_type": "generic", "serial_event_id": 3, "process_name": "powershell.exe", "count": 2.5, "percent": json.Number("0.4")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("data=%#v, want %#v", got, want)
	}
}

func matchData(matches []Match) []map[string]any {
	out := make([]map[string]any, 0, len(matches))
	for _, match := range matches {
		for _, event := range match.Events {
			out = append(out, event.Data)
		}
	}
	return out
}

func stripVolatileFields(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		clean := make(map[string]any, len(row))
		for key, value := range row {
			switch key {
			case "command_line", "timestamp":
				continue
			default:
				clean[key] = value
			}
		}
		out = append(out, clean)
	}
	return out
}

func appendMatchIDs(ids []int, matches []Match) []int {
	for _, match := range matches {
		for _, event := range match.Events {
			ids = append(ids, eventID(event))
		}
	}
	return ids
}

func appendMatchIDGroups(groups [][]int, matches []Match) [][]int {
	for _, match := range matches {
		var ids []int
		for _, event := range match.Events {
			ids = append(ids, eventID(event))
		}
		groups = append(groups, ids)
	}
	return groups
}

func eventID(event *Event) int {
	if event == nil || event.Data == nil {
		return 0
	}
	return int(toInt64(event.Data["serial_event_id"]))
}

func TestNamedSubqueryEventOfRuntime(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   []int
	}{
		{
			name:  "file event of process records matching pid",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "a.txt"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "b.txt"},
			},
			want: []int{2},
		},
		{
			name:  "process event of sees state from same event",
			query: `process where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "process_name": "cmd.exe", "subtype": "create"},
			},
			want: []int{1},
		},
		{
			name:  "terminate purges on next process event",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 10, "process_name": "python.exe", "subtype": "terminate"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "still-pending.txt"},
				{"event_type": "process", "serial_event_id": 4, "pid": 20, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 5, "pid": 10, "file_name": "purged.txt"},
			},
			want: []int{3},
		},
		{
			name:  "system create resets state",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 4, "process_name": "System", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "reset.txt"},
			},
		},
		{
			name:  "zero pid is not recorded",
			query: `file where event of [process where process_name == "python.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 0, "process_name": "python.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 2, "pid": 0, "file_name": "zero.txt"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var got []int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestNamedSubqueryChildOfRuntime(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   []int
	}{
		{
			name:  "process child of records direct child only",
			query: `process where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
			},
			want: []int{2},
		},
		{
			name:  "file event for child process matches",
			query: `file where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 3, "pid": 20, "file_name": "child.txt"},
				{"event_type": "file", "serial_event_id": 4, "pid": 10, "file_name": "parent.txt"},
			},
			want: []int{3},
		},
		{
			name:  "terminate purges child on next process event",
			query: `file where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "terminate"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "still-pending.txt"},
				{"event_type": "process", "serial_event_id": 5, "pid": 30, "ppid": 4, "process_name": "other.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 6, "pid": 20, "file_name": "purged.txt"},
			},
			want: []int{4},
		},
		{
			name:  "system create resets child state",
			query: `file where child of [process where process_name == "powershell.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 4, "ppid": 0, "process_name": "System", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "reset.txt"},
			},
		},
		{
			name:  "nested child of tracks next generation",
			query: `file where child of [process where child of [process where process_name == "cmd.exe"]]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 30, "file_name": "grandchild.txt"},
			},
			want: []int{4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var got []int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestNamedSubqueryDescendantOfRuntime(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   []int
	}{
		{
			name:  "process descendant of records all generations",
			query: `process where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 4, "pid": 40, "ppid": 4, "process_name": "other.exe", "subtype": "create"},
			},
			want: []int{2, 3},
		},
		{
			name:  "file event for descendant process matches",
			query: `file where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 30, "file_name": "grandchild.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 10, "file_name": "source.txt"},
			},
			want: []int{4},
		},
		{
			name:  "terminate purges descendant on next process event",
			query: `file where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "terminate"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "still-pending.txt"},
				{"event_type": "process", "serial_event_id": 5, "pid": 40, "ppid": 4, "process_name": "other.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 6, "pid": 20, "file_name": "purged.txt"},
			},
			want: []int{4},
		},
		{
			name:  "system create resets descendant state",
			query: `file where descendant of [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 4, "ppid": 0, "process_name": "System", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "reset.txt"},
			},
		},
		{
			name:  "nested descendant of tracks deeper generation",
			query: `file where descendant of [process where descendant of [process where process_name == "cmd.exe"]]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "subtype": "create"},
				{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "subtype": "create"},
				{"event_type": "file", "serial_event_id": 4, "pid": 30, "file_name": "nested-descendant.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 20, "file_name": "inner-source.txt"},
			},
			want: []int{4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRule(t, tc.query))
			var got []int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestEndgameDataSourceLifecycle(t *testing.T) {
	// Endgame sensor uses opcode integers: 1/3/9 = create/fork/exec, 2/4 = terminate.
	// ECS default uses subtype strings: "create"/"fork"/"terminate".
	t.Run("child of with endgame opcodes", func(t *testing.T) {
		query := `file where child of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			// powershell source registration (opcode 1 = create)
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("1")},
			// child spawned from powershell (opcode 1)
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "opcode": json.Number("1")},
			// file from child — should match
			{"event_type": "file", "serial_event_id": 3, "pid": 20, "file_name": "child.txt"},
			// file from parent — should not match
			{"event_type": "file", "serial_event_id": 4, "pid": 10, "file_name": "parent.txt"},
		}
		eng := New(compileRule(t, query, DataSource("endgame")))
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if !reflect.DeepEqual(got, []int{3}) {
			t.Fatalf("ids=%v, want [3]", got)
		}
	})

	t.Run("child of terminate with endgame opcode 2", func(t *testing.T) {
		query := `file where child of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("1")},
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "opcode": json.Number("1")},
			// terminate child via opcode 2
			{"event_type": "process", "serial_event_id": 3, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "opcode": json.Number("2")},
			// still in pending window before next process event
			{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "pending.txt"},
			// next process event flushes dead set
			{"event_type": "process", "serial_event_id": 5, "pid": 30, "ppid": 4, "process_name": "other.exe", "opcode": json.Number("1")},
			// now pid 20 is purged
			{"event_type": "file", "serial_event_id": 6, "pid": 20, "file_name": "purged.txt"},
		}
		eng := New(compileRule(t, query, DataSource("endgame")))
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if !reflect.DeepEqual(got, []int{4}) {
			t.Fatalf("ids=%v, want [4]", got)
		}
	})

	t.Run("descendant of with endgame opcodes multi-generation", func(t *testing.T) {
		query := `process where descendant of [process where process_name == "cmd.exe"]`
		events := []map[string]any{
			// cmd.exe source registration (opcode 1)
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "cmd.exe", "opcode": json.Number("1")},
			// child of cmd.exe (opcode 3 = fork)
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "powershell.exe", "opcode": json.Number("3")},
			// grandchild (opcode 1 = create)
			{"event_type": "process", "serial_event_id": 3, "pid": 30, "ppid": 20, "process_name": "whoami.exe", "opcode": json.Number("1")},
			// unrelated process
			{"event_type": "process", "serial_event_id": 4, "pid": 40, "ppid": 4, "process_name": "other.exe", "opcode": json.Number("1")},
		}
		eng := New(compileRule(t, query, DataSource("endgame")))
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if !reflect.DeepEqual(got, []int{2, 3}) {
			t.Fatalf("ids=%v, want [2 3]", got)
		}
	})

	t.Run("ECS mode ignores opcode field", func(t *testing.T) {
		// With ECS mode (default), opcode events don't trigger lifecycle.
		query := `file where child of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			// opcode 1 should be ignored in ECS mode (no subtype "create")
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("1")},
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "opcode": json.Number("1")},
			{"event_type": "file", "serial_event_id": 3, "pid": 20, "file_name": "should-not-match.txt"},
		}
		eng := New(compileRule(t, query)) // ECS default
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if len(got) != 0 {
			t.Fatalf("ECS mode must not match opcode events: ids=%v", got)
		}
	})

	t.Run("endgame mode ignores subtype field", func(t *testing.T) {
		// With Endgame mode, subtype strings don't trigger lifecycle.
		query := `file where child of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			// subtype "create" should be ignored in endgame mode (no opcode)
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "subtype": "create"},
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "subtype": "create"},
			{"event_type": "file", "serial_event_id": 3, "pid": 20, "file_name": "should-not-match.txt"},
		}
		eng := New(compileRule(t, query, DataSource("endgame")))
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if len(got) != 0 {
			t.Fatalf("Endgame mode must not match subtype events: ids=%v", got)
		}
	})

	t.Run("system reset with endgame opcode 1 and pid 4", func(t *testing.T) {
		query := `file where child of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("1")},
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "opcode": json.Number("1")},
			// System process recreated (sensor reboot)
			{"event_type": "process", "serial_event_id": 3, "pid": 4, "ppid": 0, "process_name": "System", "opcode": json.Number("1")},
			// after reset, file from pid 20 must not match
			{"event_type": "file", "serial_event_id": 4, "pid": 20, "file_name": "post-reset.txt"},
		}
		eng := New(compileRule(t, query, DataSource("endgame")))
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if len(got) != 0 {
			t.Fatalf("post-reset events must not match: ids=%v", got)
		}
	})

	t.Run("event of with endgame opcodes terminate", func(t *testing.T) {
		// event of [subquery] tracks PIDs that matched the subquery; terminate (opcode 2/4)
		// removes them so subsequent events from that PID no longer match.
		query := `file where event of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			// powershell registers as source (opcode 1 = create)
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("1")},
			// file from pid 10 before terminate — should match
			{"event_type": "file", "serial_event_id": 2, "pid": 10, "file_name": "before.txt"},
			// terminate powershell (opcode 2)
			{"event_type": "process", "serial_event_id": 3, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("2")},
			// another process event to flush the dead set
			{"event_type": "process", "serial_event_id": 4, "pid": 20, "ppid": 4, "process_name": "other.exe", "opcode": json.Number("1")},
			// file from pid 10 after terminate — should not match
			{"event_type": "file", "serial_event_id": 5, "pid": 10, "file_name": "after.txt"},
		}
		eng := New(compileRule(t, query, DataSource("endgame")))
		var got []int
		for _, data := range events {
			matches, err := eng.Feed(EventFromData(data))
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDs(got, matches)
		}
		if !reflect.DeepEqual(got, []int{2}) {
			t.Fatalf("ids=%v, want [2]", got)
		}
	})

	t.Run("DataSource case-insensitive endgame", func(t *testing.T) {
		// "Endgame" and "ENDGAME" should behave identically to "endgame".
		query := `file where child of [process where process_name == "powershell.exe"]`
		events := []map[string]any{
			{"event_type": "process", "serial_event_id": 1, "pid": 10, "ppid": 4, "process_name": "powershell.exe", "opcode": json.Number("1")},
			{"event_type": "process", "serial_event_id": 2, "pid": 20, "ppid": 10, "process_name": "cmd.exe", "opcode": json.Number("1")},
			{"event_type": "file", "serial_event_id": 3, "pid": 20, "file_name": "child.txt"},
		}
		for _, ds := range []string{"Endgame", "ENDGAME", "endgame"} {
			eng := New(compileRule(t, query, DataSource(ds)))
			var got []int
			for _, data := range events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatalf("DataSource(%q): %v", ds, err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, []int{3}) {
				t.Fatalf("DataSource(%q): ids=%v, want [3]", ds, got)
			}
		}
	})
}

func TestSequenceMaxSpanFractionalTimestampRuntime(t *testing.T) {
	cases := []struct {
		name   string
		events []*Event
		want   []int
	}{
		{
			name: "fractional data timestamp expires pending sequence",
			events: []*Event{
				EventFromData(map[string]any{"event_type": "process", "serial_event_id": 1, "timestamp": json.Number("10.1")}),
				EventFromData(map[string]any{"event_type": "file", "serial_event_id": 2, "timestamp": json.Number("10.9")}),
			},
		},
		{
			name: "public timestamp fallback remains available",
			events: []*Event{
				{Type: "process", Timestamp: 10, Data: map[string]any{"serial_event_id": 1}},
				{Type: "file", Timestamp: 10, Data: map[string]any{"serial_event_id": 2}},
			},
			want: []int{1, 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRule(t, `sequence with maxspan=0s [process where true] [file where true]`))
			var got []int
			for _, ev := range tc.events {
				matches, err := eng.Feed(ev)
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestNegativeSequenceRuntime(t *testing.T) {
	base := int64(116444736000000000)
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   [][]int
	}{
		{
			name:  "middle negative stage advances on nonmatching predicate and excludes event",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "missing.txt"] [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "registry", "serial_event_id": 3, "pid": 10, "timestamp": base + 20_000_000},
			},
			want: [][]int{{1, 3}},
		},
		{
			name:  "middle negative stage discards pending on matching predicate",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "cmd.exe"] [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 20_000_000, "file_name": "other.txt"},
				{"event_type": "registry", "serial_event_id": 4, "pid": 10, "timestamp": base + 30_000_000},
			},
		},
		{
			name:  "final negative stage emits prior positive events only",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "missing.txt"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
			want: [][]int{{1}},
		},
		{
			name:  "final negative stage discards pending on matching predicate",
			query: `sequence with maxspan=5s [process where pid == 10] ![file where file_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 20_000_000, "file_name": "other.txt"},
			},
		},
		{
			name:  "first negative stage can create empty unkeyed pending state",
			query: `sequence with maxspan=5s ![process where process_name == "missing.exe"] [file where file_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
			want: [][]int{{2}},
		},
		{
			name:  "keyed negative final stage uses existing pending by key",
			query: `sequence by pid with maxspan=5s [process where true] ![file where file_name == "missing.txt"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
			want: [][]int{{1}},
		},
		{
			name:  "keyed final negative stage discards matching key only",
			query: `sequence by pid with maxspan=5s [process where true] ![file where file_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "process", "serial_event_id": 2, "pid": 20, "timestamp": base, "process_name": "powershell.exe"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 4, "pid": 10, "timestamp": base + 20_000_000, "file_name": "other.txt"},
				{"event_type": "file", "serial_event_id": 5, "pid": 20, "timestamp": base + 30_000_000, "file_name": "other.txt"},
			},
			want: [][]int{{2}},
		},
		{
			name:  "first negative stage can create empty keyed pending state",
			query: `sequence by pid with maxspan=5s ![process where process_name == "missing.exe"] [file where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "timestamp": base, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "pid": 10, "timestamp": base + 10_000_000, "file_name": "cmd.exe"},
			},
			want: [][]int{{2}},
		},
		// B-42: negative stage with fork=true must not discard pending when predicate matches
		{
			name:  "middle negative fork stage does not discard pending when predicate matches",
			query: `sequence by pid with maxspan=5s [process where pid == 1] ![file where file_name == "bad"] fork=true [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 1, "timestamp": base},
				{"event_type": "file", "serial_event_id": 2, "pid": 1, "timestamp": base + 10_000_000, "file_name": "bad"},
				{"event_type": "file", "serial_event_id": 3, "pid": 1, "timestamp": base + 20_000_000, "file_name": "good"},
				{"event_type": "registry", "serial_event_id": 4, "pid": 1, "timestamp": base + 30_000_000},
			},
			want: [][]int{{1, 4}},
		},
		{
			name:  "middle negative non-fork stage discards pending when predicate matches",
			query: `sequence by pid with maxspan=5s [process where pid == 1] ![file where file_name == "bad"] [registry where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 1, "timestamp": base},
				{"event_type": "file", "serial_event_id": 2, "pid": 1, "timestamp": base + 10_000_000, "file_name": "bad"},
				{"event_type": "file", "serial_event_id": 3, "pid": 1, "timestamp": base + 20_000_000, "file_name": "good"},
				{"event_type": "registry", "serial_event_id": 4, "pid": 1, "timestamp": base + 30_000_000},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileNegativeSequenceRule(t, tc.query))
			var got [][]int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDGroups(got, matches)
			}
			matches, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDGroups(got, matches)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("matches=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestSequenceRunsRuntime(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   [][]int
	}{
		{
			name:  "first stage runs emit sliding windows",
			query: `sequence [file where true] with runs=3`,
			events: []map[string]any{
				{"event_type": "file", "serial_event_id": 1, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 2, "file_name": "two.txt"},
				{"event_type": "file", "serial_event_id": 3, "file_name": "three.txt"},
				{"event_type": "file", "serial_event_id": 4, "file_name": "four.txt"},
			},
			want: [][]int{{1, 2, 3}, {2, 3, 4}},
		},
		{
			name:  "later stage runs repeat the target step",
			query: `sequence [process where true] [file where true] with runs=2`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 3, "file_name": "two.txt"},
			},
			want: [][]int{{1, 2, 3}},
		},
		{
			name:  "runs preserve global keys",
			query: `sequence by pid [file where true] with runs=2`,
			events: []map[string]any{
				{"event_type": "file", "serial_event_id": 1, "pid": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 2, "pid": 20, "file_name": "wrong.txt"},
				{"event_type": "file", "serial_event_id": 3, "pid": 10, "file_name": "two.txt"},
			},
			want: [][]int{{1, 3}},
		},
		{
			name:  "runs preserve stage keys",
			query: `sequence [process where true] by pid [file where true] by process_id with runs=2`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "process_id": 10, "file_name": "one.txt"},
				{"event_type": "file", "serial_event_id": 3, "process_id": 20, "file_name": "wrong.txt"},
				{"event_type": "file", "serial_event_id": 4, "process_id": 10, "file_name": "two.txt"},
			},
			want: [][]int{{1, 2, 4}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileRunsRule(t, tc.query))
			var got [][]int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDGroups(got, matches)
			}
			matches, err := eng.Finalize()
			if err != nil {
				t.Fatal(err)
			}
			got = appendMatchIDGroups(got, matches)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("matches=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestElasticEndpointDollarVariableRuntime(t *testing.T) {
	events := []map[string]any{
		{
			"event_type":      "process",
			"serial_event_id": 1,
			"items":           []any{"a", "b"},
			"objects":         []any{map[string]any{"trusted": true}, map[string]any{"trusted": false}},
		},
		{
			"event_type":      "process",
			"serial_event_id": 2,
			"items":           []any{"missing"},
			"objects":         []any{map[string]any{"trusted": false}},
		},
	}
	cases := []struct {
		query string
		want  []int
	}{
		{query: `process where arraySearch(items, $item, $item == "a")`, want: []int{1}},
		{query: `process where arraySearch(objects, $sig, $sig.trusted == true)`, want: []int{1}},
		{query: `process where arraySearch(items, $item, item == "a")`, want: []int{1}},
		{query: `process where arraySearch(items, item, $item == "a")`, want: []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			eng := New(compileEndpointRule(t, tc.query, ElasticsearchSyntax()))
			var got []int
			for _, data := range events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				got = appendMatchIDs(got, matches)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ids=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestSampleRuntime(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		events []map[string]any
		want   [][]int
	}{
		{
			name:  "sample collects unkeyed matches",
			query: `sample [process where process_name == "cmd.exe"] [file where file_name == "payload.txt"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe"},
				{"event_type": "file", "serial_event_id": 2, "file_name": "payload.txt"},
			},
			want: [][]int{{1, 2}},
		},
		{
			name:  "sample allows same event to fill repeated terms",
			query: `sample [process where process_name == "cmd.exe"] [process where process_name == "cmd.exe"]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "process_name": "cmd.exe"},
			},
			want: [][]int{{1, 1}},
		},
		{
			name:  "sample by groups events by key",
			query: `sample by pid [process where true] [file where true]`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1, "pid": 10},
				{"event_type": "file", "serial_event_id": 2, "pid": 20},
				{"event_type": "file", "serial_event_id": 3, "pid": 10},
			},
			want: [][]int{{1, 3}},
		},
		{
			name:  "sample with pipes processes match groups",
			query: `sample [process where true] [file where true] | head 1`,
			events: []map[string]any{
				{"event_type": "process", "serial_event_id": 1},
				{"event_type": "file", "serial_event_id": 2},
				{"event_type": "process", "serial_event_id": 3},
				{"event_type": "file", "serial_event_id": 4},
			},
			want: [][]int{{1, 2}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := New(compileSampleRule(t, tc.query))
			var got [][]int
			for _, data := range tc.events {
				matches, err := eng.Feed(EventFromData(data))
				if err != nil {
					t.Fatal(err)
				}
				for _, match := range matches {
					var ids []int
					for _, ev := range match.Events {
						ids = append(ids, eventID(ev))
					}
					got = append(got, ids)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("matches=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnknownFunctionError(t *testing.T) {
	rule := compileRule(t, `process where unknownFunc(process_name)`)
	_, err := rule.Match(EventFromData(map[string]any{"event_type": "process", "process_name": "cmd.exe"}))
	if err == nil {
		t.Fatal("expected unknown function error")
	}
}

func TestMVPUseNumber(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"event_type":"process","pid":10}`))
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		t.Fatal(err)
	}
	ev := EventFromData(data)
	if _, ok := ev.Data["pid"].(json.Number); !ok {
		t.Fatalf("pid should keep public json.Number representation, got %T", ev.Data["pid"])
	}
	q, err := parser.ParseQuery(`process where pid == 10`)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := NewRule(q).Match(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected numeric match")
	}
}

func compileRule(t *testing.T, query string, opts ...RuleOption) *Rule {
	t.Helper()
	q, err := parser.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	return NewRule(q, opts...)
}

func compileSampleRule(t *testing.T, query string, opts ...RuleOption) *Rule {
	t.Helper()
	q, err := parser.ParseQueryWithOptions(query, parser.Options{AllowSample: true, ElasticsearchSyntax: true})
	if err != nil {
		t.Fatal(err)
	}
	return NewRule(q, opts...)
}

func compileNegativeSequenceRule(t *testing.T, query string, opts ...RuleOption) *Rule {
	t.Helper()
	q, err := parser.ParseQueryWithOptions(query, parser.Options{
		AllowNegation:       true,
		ElasticsearchSyntax: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewRule(q, opts...)
}

func compileRunsRule(t *testing.T, query string, opts ...RuleOption) *Rule {
	t.Helper()
	q, err := parser.ParseQueryWithOptions(query, parser.Options{
		AllowRuns:           true,
		ElasticsearchSyntax: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewRule(q, opts...)
}

func compileEndpointRule(t *testing.T, query string, opts ...RuleOption) *Rule {
	t.Helper()
	q, err := parser.ParseQueryWithOptions(query, parser.Options{ElasticEndpointSyntax: true})
	if err != nil {
		t.Fatal(err)
	}
	return NewRule(q, opts...)
}
