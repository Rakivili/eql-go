package validator

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Rakivili/eql-go/internal/diagnostic"
	"github.com/Rakivili/eql-go/internal/parser"
	schemapkg "github.com/Rakivili/eql-go/internal/schema"
)

func TestValidateCidrMatch(t *testing.T) {
	valid := []string{
		`network where cidrMatch(source_address, "10.6.48.157/8")`,
		`network where cidrMatch("10.6.48.157", "10.6.48.157/8")`,
		`network where cidrMatch(source_address, "192.168.0.0/16", "10.6.48.157/8")`,
		`network where process_name == "x" or cidrMatch(source_address, "0.0.0.0/0")`,
		`network where not cidrMatch(source_address, "192.168.0.0/16")`,
		`network where cidrMatch(source_address, "0.0.0.0/0") in (true)`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`network where cidrMatch(source_address)`,
		`network where cidrMatch(source_address, cidr_field)`,
		`network where cidrMatch(source_address, "not-cidr")`,
		`network where cidrMatch("bad-ip", "0.0.0.0/0")`,
		`network where safe(cidrMatch("bad-ip", "0.0.0.0/0"))`,
		`network where true and cidrMatch(source_address, "not-cidr")`,
		`network where cidrMatch(source_address, "not-cidr") in (true)`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := Validate(nil); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDynamicArrayFunctions(t *testing.T) {
	valid := []string{
		`registry where arraySearch(bytes_written_string_list, s, s == "en-US")`,
		`registry where arrayCount(bytes_written_string_list, s, s == "*en*") == 2`,
		`network where arraySearch(mysterious_field.subarray, sub1, arraySearch(sub1.c, nested, nested.x.y == "*"))`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`registry where arraySearch(bytes_written_string_list, s)`,
		`registry where arraySearch(bytes_written_string_list, s.name, s == "en-US")`,
		`registry where arrayCount(bytes_written_string_list, "s", s == "en-US") == 1`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateDiagnosticClasses(t *testing.T) {
	cases := []struct {
		name  string
		query string
		class diagnostic.Class
	}{
		{
			name:  "unknown function is semantic",
			query: `process where wildcrad(process_name, "x")`,
			class: diagnostic.ClassSemantic,
		},
		{
			name:  "literal argument type is type mismatch",
			query: `process where length(1)`,
			class: diagnostic.ClassTypeMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := parser.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateQuery(q)
			if err == nil {
				t.Fatal("expected validation error")
			}
			var diagnosticErr *diagnostic.Error
			if !errors.As(err, &diagnosticErr) {
				t.Fatalf("expected diagnostic error, got %T: %v", err, err)
			}
			if diagnosticErr.Class != tc.class {
				t.Fatalf("Class=%q, want %q", diagnosticErr.Class, tc.class)
			}
		})
	}
}

func TestValidateSafe(t *testing.T) {
	valid := []string{
		`network where safe(divide(process_name, process_name))`,
		`process where safe(pid == 10)`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where safe()`,
		`process where safe(pid == 10, true)`,
		`process where safe(wildcrad(process_name, "x"))`,
		`process where safe(length())`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateQuerySchemaRewritesEnumField(t *testing.T) {
	s, err := schemapkg.New(map[string]map[string]any{
		"process": {
			"process_name": "string",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parser.ParseQuery(`process where process_name.bash`)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuerySchema(got, s, SchemaAllowEnumFields(true)); err != nil {
		t.Fatal(err)
	}
	want, err := parser.ParseQuery(`process where process_name == 'bash'`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enum field rewrite mismatch\ngot=%#v\nwant=%#v", got.Expr, want.Expr)
	}
}

func TestValidateQuerySchemaMathLeftOperandCompatibility(t *testing.T) {
	s, err := schemapkg.New(map[string]map[string]any{
		"process": {
			"process_name": "string",
			"pid":          "number",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{name: "string left numeric literal right", query: `process where process_name + 1 == 2`},
		{name: "string left numeric field right", query: `process where process_name + pid == 2`},
		{name: "string left chained numeric right", query: `process where process_name + 1 + 2 == 2`},
		{name: "numeric left string right", query: `process where 1 + process_name == 2`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := parser.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateQuerySchema(q, s)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateQuerySchemaDiagnosticClasses(t *testing.T) {
	s, err := schemapkg.New(map[string]map[string]any{
		"process": {
			"pid":          "number",
			"process_name": "string",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		query string
		class diagnostic.Class
	}{
		{
			name:  "missing field is schema",
			query: `process where missing == 1`,
			class: diagnostic.ClassSchema,
		},
		{
			name:  "schema comparison mismatch is type mismatch",
			query: `process where pid == process_name`,
			class: diagnostic.ClassTypeMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := parser.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateQuerySchema(q, s)
			if err == nil {
				t.Fatal("expected schema validation error")
			}
			var diagnosticErr *diagnostic.Error
			if !errors.As(err, &diagnosticErr) {
				t.Fatalf("expected diagnostic error, got %T: %v", err, err)
			}
			if diagnosticErr.Class != tc.class {
				t.Fatalf("Class=%q, want %q", diagnosticErr.Class, tc.class)
			}
		})
	}
}

func TestValidateNamedSubquery(t *testing.T) {
	valid := []string{
		`process where event of [process where true]`,
		`file where event of [process where process_name == "python.exe"]`,
		`process where child of [process where true]`,
		`file where child of [process where process_name == "python.exe"]`,
		`process where descendant of [process where true]`,
		`file where descendant of [process where process_name == "python.exe"]`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`file where event of [process where wildcrad(process_name, "x")]`,
		`file where event of [process where length()]`,
		`file where child of [process where wildcrad(process_name, "x")]`,
		`file where child of [process where length()]`,
		`file where descendant of [process where wildcrad(process_name, "x")]`,
		`file where descendant of [process where length()]`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateSequenceUntil(t *testing.T) {
	valid := []string{
		`sequence [process where true] [file where true] until [process where subtype == "stop"]`,
		`sequence by pid [process where true] [file where true] until [process where subtype == "stop"]`,
		`sequence [process where true] by pid [file where true] by process_id until [process where subtype == "stop"] by pid`,
		`sequence by host [process where true] by pid [file where true] by process_id until [process where subtype == "stop"] by pid`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`sequence [process where true] [file where true] until [process where subtype == "stop"] by pid`,
		`sequence by pid [process where true] [file where true] until [process where subtype == "stop"] by pid`,
		`sequence [process where true] by pid [file where true] by process_id until [process where subtype == "stop"]`,
		`sequence [process where true] by pid [file where true] by process_id until [process where subtype == "stop"] by pid, host`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateSequenceFork(t *testing.T) {
	valid := []string{
		`sequence [process where true] [file where true] fork`,
		`sequence [process where true] [file where true] fork=true`,
		`sequence [process where true] [file where true] fork=false`,
		`sequence by pid [process where true] [file where true] fork`,
		`sequence [process where true] by pid [file where true] fork by process_id`,
		`sequence [process where true] [file where true] until [process where true] fork`,
		`sequence [process where true] [file where true] until [process where true] fork=false`,
		`sequence [process where true] [file where true] | head 1`,
		`sequence by pid [process where true] [file where true] | count`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`sequence [process where true] fork [file where true]`,
		`sequence [process where true] fork=false [file where true]`,
		`sequence [process where true] [file where true] fork by pid`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateNegativeSequenceRequiresMaxSpan(t *testing.T) {
	valid := []string{
		`sequence with maxspan=5s [process where true] ![file where true]`,
		`sequence by pid with maxspan=5s [process where true] ![file where true]`,
		`sequence with maxspan=5s ![process where true] [file where true]`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQueryWithOptions(query, parser.Options{
				AllowNegation:       true,
				ElasticsearchSyntax: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`sequence [process where true] ![file where true]`,
		`sequence by pid [process where true] ![file where true]`,
		`sequence ![process where true] [file where true]`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQueryWithOptions(query, parser.Options{
				AllowNegation:       true,
				ElasticsearchSyntax: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateJoin(t *testing.T) {
	valid := []string{
		`join [process where true] [file where true]`,
		`join by pid [process where true] [file where true]`,
		`join [process where true] by pid [file where true] by process_id`,
		`join by host [process where true] by pid [file where true] by process_id`,
		`join [process where true] [file where true] until [process where opcode == 2]`,
		`join by pid [process where true] [file where true] until [process where opcode == 2]`,
		`join [process where true] by pid [file where true] by process_id until [process where opcode == 2] by pid`,
		`join [process where true] [file where true] | head 1`,
		`join by pid [process where true] [file where true] | count`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`join [process where true] by pid [file where true]`,
		`join [process where true] by pid [file where true] by pid until [process where true]`,
		`join [process where true] [file where true] until [process where true] by pid`,
		`join [process where true] [file where true] fork`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateQuery(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateSample(t *testing.T) {
	valid := []string{
		`sample [process where true] [file where true]`,
		`sample by pid [process where true] [file where true]`,
		`sample [process where true] by pid [file where true] by process_id`,
		`sample [process where true] [file where true] fork`,
		`sample [process where true] [file where true] fork=false`,
		`sample [process where true] [file where true] | head 1`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQueryWithOptions(query, parser.Options{AllowSample: true, ElasticsearchSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateQuery(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`sample [process where 1] [file where true]`,
		`sample [process where true] fork [file where true]`,
		`sample [process where true] by pid [file where true]`,
		`sample [process where true] by pid [file where true] by process_id, host`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQueryWithOptions(query, parser.Options{AllowSample: true, ElasticsearchSyntax: true})
			if err != nil {
				return
			}
			if err := ValidateQuery(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateOneStageSequence(t *testing.T) {
	q, err := parser.ParseQueryWithOptions(`sequence [process where true]`, parser.Options{ElasticsearchSyntax: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuery(q); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePipeDynamicArguments(t *testing.T) {
	valid := []string{
		`process where true | count`,
		`process where true | count pid`,
		`process where true | sort pid + 1`,
		`process where true | sort length(process_name)`,
		`process where true | sort safe(1)`,
		`process where true | unique process_name`,
		`process where true | unique_count process_name`,
		`process where true | sort true and pid == 1`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where true | sort 5`,
		`process where true | sort 1 + 1`,
		`process where true | sort length("abc")`,
		`process where true | sort true == true`,
		`process where true | sort 1 in (1, 2)`,
		`process where true | unique "x"`,
		`process where true | count 5`,
		`process where true | count 1 + 1`,
		`process where true | unique_count false`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateFunctionSignatures(t *testing.T) {
	valid := []string{
		`process where length(process_name) == 7`,
		`process where wildcard(process_name, "cmd*")`,
		`process where number("32", 16) == 50`,
		`process where concat("a", "b") == "ab"`,
		`process where match("cmd.*", process_name)`,
		`process where matchLite("cmd.*", process_name)`,
		`process where match(process_name, ?'(a)\1')`,
		`process where matchLite(process_name, ?'(?=a)a')`,
		`process where match(process_name, ?'(?P<word>a)(?P=word)')`,
		`process where match(process_name, ?'a(?<=a)b')`,
		`process where substring(process_name, 0, 4) == "syst"`,
		`process where between(process_name, "s", "e", true) == "yst"`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where wildcrad(process_name, "x")`,
		`process where length()`,
		`process where startsWith(process_name)`,
		`process where number("1", 10, 10) == 1`,
		`process where concat()`,
		`process where arrayContains(bytes_written_string_list)`,
		`process where indexOf(process_name) == 0`,
		`process where substring(process_name) == "x"`,
		`process where between(process_name, "s") == "x"`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateStaticExpressionTypeChecks(t *testing.T) {
	valid := []string{
		`process where process_name in (1)`,
		`process where "x" + 1 == 2`,
		`process where null and true`,
		`process where safe(1)`,
		`process where field == true`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateQuery(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where not 1`,
		`process where false and 1`,
		`process where true or 1`,
		`process where length(process_name)`,
		`process where 1 in ("x")`,
		`process where true in (1)`,
		`process where process_name < true`,
		`process where pid + true > 0`,
		`process where 1 + "x" == 2`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateQuery(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateFunctionLiteralTypes(t *testing.T) {
	valid := []string{
		`process where length(null) == null`,
		`process where startsWith(null, "x") == null`,
		`process where startsWith("x", null) == null`,
		`process where match(null, "[a-z]+") == null`,
		`process where match("eql", null) == false`,
		`process where number(null) == null`,
		`process where number("10", 0) == 10`,
		`process where number("10", null) == 10`,
		`process where add(null, 2) == null`,
		`process where arrayContains(null, "x") == null`,
		`process where indexOf("foobarbaz", "o", null) == 1`,
		`process where substring("hello world", null, 5) == "hello"`,
		`process where substring("hello world", 6, null) == "world"`,
		`process where between("abc", "a", "b", null) == ""`,
		`network where cidrMatch(null, "0.0.0.0/0") == false`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where length(1) == null`,
		`process where wildcard(1, "*")`,
		`process where wildcard("x", null)`,
		`process where wildcard(process_name, pattern_field)`,
		`process where startsWith(1, "x")`,
		`process where startsWith("x", 1)`,
		`process where endsWith(1, "x")`,
		`process where stringContains("x", 1)`,
		`process where match(1, "*")`,
		`process where match("eql", 1)`,
		`process where match(process_name, pattern_field)`,
		`process where match(process_name, "[")`,
		`process where matchLite(process_name, "[")`,
		`process where match(process_name, ?'(?<=a+)b')`,
		`process where match(process_name, ?'(?>a)')`,
		`process where number(1) == null`,
		`process where number("1", true) == null`,
		`process where number("1", 1) == null`,
		`process where number("1", 37) == null`,
		`process where number("++314") == null`,
		`process where number("0xzz") == null`,
		`process where number("89", 8) == null`,
		`process where add("1", 2) == null`,
		`process where arrayContains(1, "x")`,
		`process where indexOf(1, "x") == null`,
		`process where indexOf("x", 1) == null`,
		`process where indexOf("x", "x", 1.5) == null`,
		`process where substring(1, 0) == null`,
		`process where substring("x", 1.5) == null`,
		`process where substring("x", 0, 1.5) == null`,
		`process where between(1, "a", "b") == null`,
		`process where between("abc", 1, "b") == null`,
		`process where between("abc", "a", 1) == null`,
		`process where between("abc", "a", "b", 1) == null`,
		`network where cidrMatch(1, "0.0.0.0/0")`,
		`process where safe(length(1)) == null`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateComparisonLiteralTypes(t *testing.T) {
	valid := []string{
		`process where true == false`,
		`process where true != false`,
		`process where true == null`,
		`process where null == true`,
		`process where null == "x"`,
		`process where "x" == null`,
		`process where null < "x"`,
		`process where "x" < null`,
		`process where null < 1`,
		`process where 1 < null`,
		`process where null < null`,
		`process where 1 == 1.0`,
		`process where 1 < 1.0`,
		`process where "x" < "y"`,
		`process where process_name == 10`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where true < false`,
		`process where true > false`,
		`process where true <= true`,
		`process where true >= null`,
		`process where null < true`,
		`process where "x" < 1`,
		`process where 1 < "x"`,
		`process where "x" == 1`,
		`process where true == 1`,
		`process where true != "true"`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateStreamingPipes(t *testing.T) {
	valid := []string{
		`process where true | head 2`,
		`process where true | head`,
		`process where true | tail 2`,
		`process where true | tail`,
		`process where true | count`,
		`process where true | count process_name`,
		`process where true | count process_name, pid`,
		`process where true | unique_count process_name`,
		`process where true | unique_count process_name, pid`,
		`process where true | sort pid`,
		`process where true | sort parent_process_name, pid`,
		`process where true | filter serial_event_id >= 4 | head 2`,
		`process where true | unique process_name`,
		`process where true | unique process_name, parent_process_name`,
	}
	for _, query := range valid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(q); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []string{
		`process where true | head 0`,
		`process where true | head -1`,
		`process where true | head 1.5`,
		`process where true | tail 0`,
		`process where true | tail -1`,
		`process where true | tail 1.5`,
		`process where true | sort`,
		`process where true | unique_count`,
		`process where true | filter`,
		`process where true | unique`,
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			q, err := parser.ParseQuery(query)
			if err != nil {
				return
			}
			if err := Validate(q); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
