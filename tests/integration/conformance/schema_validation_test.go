package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	eql "github.com/Rakivili/eql-go"
)

func TestSchemaValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	cases := []struct {
		name  string
		query string
	}{
		{name: "valid process fields", query: `process where process_name == "test" and command_line == "test" and pid > 0`},
		{name: "valid single quoted string comparison", query: `process where process_name == 'bash'`},
		{name: "valid mixed field", query: `file where file_path == "abc" and data == 1`},
		{name: "valid mixed string field", query: `file where file_path == "abc" and data == "fdata.exe"`},
		{name: "valid mixed null field", query: `file where file_path == "abc" and data != null`},
		{name: "valid array index", query: `complex where string_arr[3] != null`},
		{name: "valid wide open", query: `complex where wideopen.a.b[0].def == 1`},
		{name: "valid length array", query: `complex where length(nested.arr) > 0`},
		{name: "valid nested array item", query: `complex where nested.arr[0] == 1`},
		{name: "valid nested number", query: `complex where nested.double_nested.nn == 5`},
		{name: "valid nested object null", query: `complex where nested.double_nested.triplenest != null`},
		{name: "valid nested mixed", query: `complex where nested.double_nested.triplenest.m == 5`},
		{name: "valid nested bool null", query: `complex where nested.double_nested.triplenest.b != null`},
		{name: "valid nested bool null with path whitespace", query: `complex where nested.  double_nested.triplenest.b != null`},
		{name: "valid array contains", query: `complex where arrayContains(string_arr, 'thesearchstring')`},
		{name: "valid array contains multiple", query: `complex where arrayContains(string_arr, 'thesearchstring', 'anothersearchstring')`},
		{name: "valid array search string", query: `complex where arraySearch(string_arr, x, x == '*subs*')`},
		{name: "valid array search mixed", query: `complex where arraySearch(nested.arr, x, x == '*subs*')`},
		{name: "valid array contains object array", query: `complex where arrayContains(objarray, 1)`},
		{name: "valid array contains object array multiple", query: `complex where arrayContains(objarray, 1, 2, 3)`},
		{name: "valid array search object field", query: `complex where arraySearch(objarray, x, x.key == 'k')`},
		{name: "valid nested array search wide object", query: `complex where arraySearch(objarray, x, arraySearch(x, y, y.key == true))`},
		{name: "valid nested array search string", query: `complex where arraySearch(array_array, x, arraySearch(x.s, y, y == 'abc'))`},
		{name: "valid single filter", query: `file where file_path == "abc" and length(data) > 0 | filter file_path == "abc"`},
		{name: "valid sequence filter events", query: `sequence [file where pid=1] [process where pid=2] | filter events[0].file_name = events[1].process_name`},
		{name: "valid sequence by filter events", query: `sequence by pid [file where true] [process where true] | filter events[0].file_name = events[1].process_name`},
		{name: "valid join filter events", query: `join by pid [file where true] [process where true] | filter events[0].file_name = events[1].process_name`},
		{name: "valid join until by filter events", query: `join [file where true] by pid [process where true] by pid until [complex where false] by nested.num | filter events[0].file_name = events[1].process_name`},
		{name: "valid join until by filter events compact pipe", query: `join [file where true] by pid [process where true] by pid until [complex where false] by nested.num| filter events[0].file_name = events[1].process_name`},
		{name: "valid count filter", query: `process where true | count | filter key == 'total' and percent < 0.5 and count > 0`},
		{name: "valid unique count filter", query: `process where true | unique_count process_name | filter count > 5 and process_name == '*.exe'`},
		{name: "valid sequence unique count filter", query: `sequence[file where true][process where true] | unique_count events[0].process_name | filter count > 5 and events[1].elevated`},
		{name: "invalid event type", query: `network where true`},
		{name: "invalid event type case", query: `PROCESS where true`},
		{name: "invalid unknown event type", query: `person where true`},
		{name: "invalid missing field", query: `process where not bad_field`},
		{name: "invalid wrong process field", query: `process where file_path`},
		{name: "invalid wrong event field", query: `file where command_line`},
		{name: "invalid wrong nested event field", query: `process where wideopen.a.b.c`},
		{name: "invalid any missing field", query: `any where invalid_field`},
		{name: "invalid nested field", query: `complex where nested.double_nested.b`},
		{name: "invalid nested field with path whitespace", query: `complex where nested.  double_nested.b`},
		{name: "invalid comparison type", query: `process where pid == "1"`},
		{name: "invalid boolean ordered comparison", query: `process where elevated < true`},
		{name: "invalid length argument", query: `process where length(pid) > 0`},
		{name: "invalid startsWith argument", query: `process where startsWith(pid, "x")`},
		{name: "invalid array contains element", query: `complex where arrayContains(string_arr, 1)`},
		{name: "invalid array contains multiple elements", query: `complex where arrayContains(string_arr, 1, 2, 3)`},
		{name: "invalid array contains source", query: `process where arrayContains(pid, 4)`},
		{name: "invalid nested array search element", query: `complex where arraySearch(array_array, x, arraySearch(x.s, y, y == 1))`},
		{name: "invalid array search source", query: `process where arraySearch(pid, x, true)`},
		{name: "invalid array search variable", query: `complex where arraySearch(objarray, '*subs*')`},
		{name: "invalid unique missing field", query: `file where file_path == "abc" and data != null | unique missing_field == "abc"`},
		{name: "invalid sequence filter missing event field", query: `sequence [file where pid=1] [process where pid=2] | filter events[0].file_name = events[1].bad`},
		{name: "invalid until pipe field expression", query: `sequence [file where 1=1] by pid [process where 1=1] by pid until [complex where false] by pid | unique events[0].file_name = events[1].process_name`},
		{name: "invalid until pipe field expression compact pipe", query: `sequence [file where 1=1] by pid [process where 1=1] by pid until [complex where false] by pid| unique events[0].file_name = events[1].process_name`},
		{name: "invalid count filter original field", query: `process where true | count | filter key == 'total' and percent < 0.5 and count > 0 and elevated`},
		{name: "invalid unique count key field", query: `process where true | unique_count process_name | filter key == '*.abc' and count > 5 and process_name == '*.exe'`},
		{name: "invalid sequence unique count first event field", query: `sequence[file where true][process where true] | unique_count events[0].process_name | filter count > 5 and events[0].elevated`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, schemaOracleOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, goErr := eql.Compile(tc.query, eql.WithSchema(schema))
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("schema validation mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaDefaultBooleanValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	cases := []struct {
		name   string
		query  string
		wantOK bool
	}{
		{name: "invalid string where", query: `process where command_line`, wantOK: false},
		{name: "invalid number where", query: `process where pid`, wantOK: false},
		{name: "invalid logical string term", query: `process where command_line and elevated`, wantOK: false},
		{name: "invalid not string", query: `process where not command_line`, wantOK: false},
		{name: "valid boolean where", query: `process where elevated`, wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, schemaOracleOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if pythonOK != tc.wantOK {
				t.Fatalf("python schema oracle for %q returned %v, want %v", tc.query, pythonOK, tc.wantOK)
			}
			_, goErr := eql.Compile(tc.query, eql.WithSchema(schema))
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("default boolean schema mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaMathValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	cases := []struct {
		name   string
		query  string
		wantOK bool
	}{
		{name: "string left numeric literal right", query: `process where process_name + 1 == 2`, wantOK: true},
		{name: "string left numeric field right", query: `process where process_name + pid == 2`, wantOK: true},
		{name: "string left chained numeric right", query: `process where process_name + 1 + 2 == 2`, wantOK: true},
		{name: "numeric left string right", query: `process where 1 + process_name == 2`, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, schemaOracleOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if pythonOK != tc.wantOK {
				t.Fatalf("python schema oracle for %q returned %v, want %v", tc.query, pythonOK, tc.wantOK)
			}
			_, goErr := eql.Compile(tc.query, eql.WithSchema(schema))
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("schema math validation mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestUniqueCountEmptySchemaOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := map[string]map[string]any{
		"process": {},
	}
	query := `process where true | unique_count safe(1) | filter count == "x"`
	pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, query, schemaOracleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !pythonOK {
		t.Fatalf("python schema oracle for %q returned false, want true", query)
	}
	_, goErr := eql.Compile(query, eql.WithSchema(schema))
	if goErr != nil {
		t.Fatalf("unique_count empty schema mismatch for %q: goErr=%v pythonOK=%v", query, goErr, pythonOK)
	}
}

func TestSchemaEventValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	validOpts := schemaOracleOptions{AllowGeneric: true, AllowAny: true, ExplicitEventOptions: true}
	validSchemaOpts := []eql.SchemaOption{eql.SchemaAllowGeneric(true), eql.SchemaAllowAny(true)}
	valid := []string{
		`process where true`,
		`file where true`,
		`complex where true`,
		`any where true`,
		`generic where true`,
	}
	for _, query := range valid {
		assertSchemaOracle(t, pythonRepo, schema, query, validOpts, validSchemaOpts)
	}

	invalidOpts := schemaOracleOptions{AllowGeneric: false, AllowAny: false, ExplicitEventOptions: true}
	invalidSchemaOpts := []eql.SchemaOption{eql.SchemaAllowGeneric(false), eql.SchemaAllowAny(false)}
	invalid := []string{
		`PROCESS where true`,
		`network where true`,
		`person where true`,
		`generic where true`,
		`any where true`,
	}
	for _, query := range invalid {
		assertSchemaOracle(t, pythonRepo, schema, query, invalidOpts, invalidSchemaOpts)
	}
}

func TestSchemaAnyFieldOrderOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	cases := []struct {
		query string
	}{
		{query: `any where process_name == 'abc'`},
		{query: `any where process_name == 1`},
		{query: `any where pid == 1`},
		{query: `any where pid == '1'`},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			pythonOK, err := pythonSchemaFixtureParseOK(context.Background(), pythonRepo, tc.query)
			if err != nil {
				t.Fatal(err)
			}
			_, goErr := eql.Compile(tc.query, eql.WithSchema(schema))
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("schema validation mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func assertSchemaOracle(
	t *testing.T,
	pythonRepo string,
	schema map[string]map[string]any,
	query string,
	options schemaOracleOptions,
	schemaOpts []eql.SchemaOption,
) {
	t.Helper()
	pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, query, options)
	if err != nil {
		t.Fatal(err)
	}
	_, goErr := eql.Compile(query, eql.WithSchema(schema, schemaOpts...))
	goOK := goErr == nil
	if goOK != pythonOK {
		t.Fatalf("schema validation mismatch for %q: goOK=%v err=%v pythonOK=%v", query, goOK, goErr, pythonOK)
	}
}

func TestSchemaValidationOptions(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	cases := []struct {
		name    string
		query   string
		options schemaOracleOptions
		goOpts  []eql.SchemaOption
	}{
		{
			name:    "allow missing",
			query:   `process where missing_field`,
			options: schemaOracleOptions{AllowGeneric: true, AllowAny: true, AllowMissing: true},
			goOpts:  []eql.SchemaOption{eql.SchemaAllowMissing(true)},
		},
		{
			name:    "disallow any",
			query:   `any where true`,
			options: schemaOracleOptions{AllowGeneric: true, AllowAny: false},
			goOpts:  []eql.SchemaOption{eql.SchemaAllowAny(false)},
		},
		{
			name:    "disallow generic",
			query:   `generic where true`,
			options: schemaOracleOptions{AllowGeneric: false, AllowAny: true},
			goOpts:  []eql.SchemaOption{eql.SchemaAllowGeneric(false)},
		},
		{
			name:    "strict booleans",
			query:   `process where command_line`,
			options: schemaOracleOptions{StrictBooleans: true},
			goOpts:  []eql.SchemaOption{eql.SchemaStrictBooleans(true)},
		},
		{
			name:    "relaxed booleans",
			query:   `process where command_line`,
			options: schemaOracleOptions{ImpliedBooleans: true},
			goOpts:  []eql.SchemaOption{eql.SchemaStrictBooleans(false)},
		},
		{
			name:    "non nullable fields",
			query:   `process where command_line != null`,
			options: schemaOracleOptions{NonNullableFields: true},
			goOpts:  []eql.SchemaOption{eql.SchemaNonNullableFields(true)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, tc.options)
			if err != nil {
				t.Fatal(err)
			}
			_, goErr := eql.Compile(tc.query, eql.WithSchema(schema, tc.goOpts...))
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("schema option mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaStrictValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	opts := schemaOracleOptions{StrictBooleans: true, NonNullableFields: true}
	goOpts := []eql.SchemaOption{
		eql.SchemaStrictBooleans(true),
		eql.SchemaNonNullableFields(true),
	}
	cases := []struct {
		name  string
		query string
	}{
		{name: "invalid string null", query: `process where command_line != null`},
		{name: "invalid boolean null", query: `process where elevated != null`},
		{name: "invalid number null", query: `process where pid != null`},
		{name: "invalid ordered null", query: `process where pid > null`},
		{name: "invalid literal ordered null", query: `process where 5 > null`},
		{name: "invalid literal null", query: `process where 5 != null`},
		{name: "invalid logical null", query: `process where (pid == 0 or process_name == 'foo') == null`},
		{name: "invalid non boolean function", query: `process where indexOf(null, null)`},
		{name: "invalid in set null", query: `process where (process_name in ('net.exe')) != null`},
		{name: "invalid comparison null", query: `process where (pid > 0) != null`},
		{name: "invalid substring null", query: `process where substring(process_name, 1) == null`},
		{name: "valid string comparison", query: `process where command_line != 'abc.exe'`},
		{name: "valid boolean comparison", query: `process where elevated != true`},
		{name: "valid not boolean", query: `process where not elevated`},
		{name: "valid filter string", query: `process where pid > 0 | filter process_name`},
		{name: "valid filter number", query: `process where pid > 0 | filter length(process_name)`},
		{name: "valid index nullable", query: `process where indexOf(process_name, 'foo') != null`},
		{name: "valid propagated nullable", query: `process where substring(process_name, indexOf(process_name, 'foo')) == null`},
		{name: "invalid filter object", query: `complex where nested != null | filter nested.double_nested`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, opts)
			if err != nil {
				t.Fatal(err)
			}
			_, goErr := eql.Compile(tc.query, eql.WithSchema(schema, goOpts...))
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("strict schema mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaEndpointValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaEndpointValidationFixture()
	opts := schemaOracleOptions{ElasticEndpointSyntax: true}
	ruleOpts := []eql.RuleOption{
		eql.ElasticEndpointSyntax(),
		eql.WithSchema(schema),
	}
	cases := []struct {
		name  string
		query string
	}{
		{name: "valid scoped string array", query: `process where arraySearch(string_array, $variable, $variable == "foo")`},
		{name: "valid scoped object boolean field", query: `process where arraySearch(obj_array, $sig, $sig.trusted == true)`},
		{name: "invalid scoped object field type", query: `process where arraySearch(field.nested_field, $var, $var.nf1 == 3)`},
		{name: "invalid scoped object missing field", query: `process where arraySearch(field.nested_field, $var, $var.nf4 == "3")`},
		{name: "invalid missing second dollar", query: `process where arraySearch(field.nested_field, $var, var.nf2 == 3)`},
		{name: "valid nested scoped string field", query: `process where arraySearch(field.nested_field, $var, $var.nf1 == "three")`},
		{name: "valid nested scoped number field", query: `process where arraySearch(field.nested_field, $var, $var.nf2 == 3)`},
		{name: "valid sequence alias nested field", query: `sequence [process where process.name == "abc.exe"] as p0 [network where p0.process.name == process.name]`},
		{name: "valid sequence alias scalar field", query: `sequence by user.name [process where process.name == "abc.exe"] as p0 [network where p0.pid == 0]`},
		{name: "invalid sequence alias missing alias", query: `sequence by user.name [process where process.name == "abc.exe"] as p1 [network where p0.pid == 0]`},
		{name: "invalid sequence alias missing field", query: `sequence by user.name [process where process.name == "abc.exe"] as p1 [network where p1.badfield == 0]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, opts)
			if err != nil {
				t.Fatal(err)
			}
			_, goErr := eql.Compile(tc.query, ruleOpts...)
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("endpoint schema mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaOptionalFieldValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaEndpointValidationFixture()
	cases := []struct {
		name     string
		query    string
		options  schemaOracleOptions
		ruleOpts []eql.RuleOption
	}{
		{
			name:     "default optional nested field present",
			query:    `process where ?process.name : "cmd.exe"`,
			options:  schemaOracleOptions{ElasticsearchSyntax: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchSyntax(), eql.WithSchema(schema)},
		},
		{
			name:     "default optional scalar field present",
			query:    `process where ?process_name : "cmd.exe"`,
			options:  schemaOracleOptions{ElasticsearchSyntax: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchSyntax(), eql.WithSchema(schema)},
		},
		{
			name:     "default optional scalar field missing",
			query:    `process where ?unknown_field : "cmd.exe"`,
			options:  schemaOracleOptions{ElasticsearchSyntax: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchSyntax(), eql.WithSchema(schema)},
		},
		{
			name:     "default optional nested field missing",
			query:    `process where ?unknown.field : "cmd.exe"`,
			options:  schemaOracleOptions{ElasticsearchSyntax: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchSyntax(), eql.WithSchema(schema)},
		},
		{
			name:     "strict optional nested field present",
			query:    `process where ?process.name : "cmd.exe"`,
			options:  schemaOracleOptions{ValidateOptionalFields: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchValidateOptionalFields(), eql.WithSchema(schema)},
		},
		{
			name:     "strict optional scalar field present",
			query:    `process where ?process_name : "cmd.exe"`,
			options:  schemaOracleOptions{ValidateOptionalFields: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchValidateOptionalFields(), eql.WithSchema(schema)},
		},
		{
			name:     "strict optional scalar field missing",
			query:    `process where ?unknown_field : "cmd.exe"`,
			options:  schemaOracleOptions{ValidateOptionalFields: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchValidateOptionalFields(), eql.WithSchema(schema)},
		},
		{
			name:     "strict optional nested field missing",
			query:    `process where ?unknown.field : "cmd.exe"`,
			options:  schemaOracleOptions{ValidateOptionalFields: true},
			ruleOpts: []eql.RuleOption{eql.ElasticsearchValidateOptionalFields(), eql.WithSchema(schema)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, schema, tc.query, tc.options)
			if err != nil {
				t.Fatal(err)
			}
			_, goErr := eql.Compile(tc.query, tc.ruleOpts...)
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("optional field schema mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaEnumFieldValidationOracle(t *testing.T) {
	pythonRepo := schemaValidationPythonRepo(t)
	schema := schemaValidationFixture()
	endpointSchema := schemaEndpointValidationFixture()
	cases := []struct {
		name     string
		query    string
		schema   map[string]map[string]any
		options  schemaOracleOptions
		ruleOpts []eql.RuleOption
		wantOK   bool
	}{
		{
			name:     "disabled enum field",
			query:    `process where process_name.bash`,
			schema:   schema,
			ruleOpts: []eql.RuleOption{eql.WithSchema(schema)},
			wantOK:   false,
		},
		{
			name:     "enabled scalar enum field",
			query:    `process where process_name.bash`,
			schema:   schema,
			options:  schemaOracleOptions{AllowEnumFields: true},
			ruleOpts: []eql.RuleOption{eql.AllowEnumFields(), eql.WithSchema(schema)},
			wantOK:   true,
		},
		{
			name:     "pipe enum field",
			query:    `process where true | filter process_name.bash`,
			schema:   schema,
			options:  schemaOracleOptions{AllowEnumFields: true},
			ruleOpts: []eql.RuleOption{eql.AllowEnumFields(), eql.WithSchema(schema)},
			wantOK:   false,
		},
		{
			name:     "enabled safe enum field",
			query:    `process where safe(process_name.bash)`,
			schema:   schema,
			options:  schemaOracleOptions{AllowEnumFields: true},
			ruleOpts: []eql.RuleOption{eql.AllowEnumFields(), eql.WithSchema(schema)},
			wantOK:   true,
		},
		{
			name:     "enabled in-set enum field",
			query:    `process where process_name.bash in (true)`,
			schema:   schema,
			options:  schemaOracleOptions{AllowEnumFields: true},
			ruleOpts: []eql.RuleOption{eql.AllowEnumFields(), eql.WithSchema(schema)},
			wantOK:   true,
		},
		{
			name:     "non-string enum base",
			query:    `process where pid.bash`,
			schema:   schema,
			options:  schemaOracleOptions{AllowEnumFields: true},
			ruleOpts: []eql.RuleOption{eql.AllowEnumFields(), eql.WithSchema(schema)},
			wantOK:   false,
		},
		{
			name:     "missing enum base",
			query:    `process where missing.bash`,
			schema:   schema,
			options:  schemaOracleOptions{AllowEnumFields: true},
			ruleOpts: []eql.RuleOption{eql.AllowEnumFields(), eql.WithSchema(schema)},
			wantOK:   false,
		},
		{
			name:    "endpoint alias enum field",
			query:   `sequence [process where process.name.cmd] as p0 [network where p0.process.name.cmd]`,
			schema:  endpointSchema,
			options: schemaOracleOptions{AllowEnumFields: true, ElasticEndpointSyntax: true},
			ruleOpts: []eql.RuleOption{
				eql.AllowEnumFields(),
				eql.ElasticEndpointSyntax(),
				eql.WithSchema(endpointSchema),
			},
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonOK, err := pythonSchemaParseOK(context.Background(), pythonRepo, tc.schema, tc.query, tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if pythonOK != tc.wantOK {
				t.Fatalf("python schema oracle for %q returned %v, want %v", tc.query, pythonOK, tc.wantOK)
			}
			_, goErr := eql.Compile(tc.query, tc.ruleOpts...)
			goOK := goErr == nil
			if goOK != pythonOK {
				t.Fatalf("enum field schema mismatch for %q: goOK=%v err=%v pythonOK=%v", tc.query, goOK, goErr, pythonOK)
			}
		})
	}
}

func TestSchemaEnumFieldRuntimeRewrite(t *testing.T) {
	schema := schemaValidationFixture()
	cases := []string{
		`process where process_name.bash`,
		`process where safe(process_name.bash)`,
		`process where process_name.bash in (true)`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			rule, err := eql.Compile(query, eql.AllowEnumFields(), eql.WithSchema(schema))
			if err != nil {
				t.Fatal(err)
			}
			engine := eql.NewEngine(rule)
			matches, err := engine.Feed(eql.EventFromData(map[string]any{
				"event_type":      "process",
				"process_name":    "BASH",
				"serial_event_id": 1,
			}))
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 1 {
				t.Fatalf("expected enum rewrite to match case-insensitively, got %d matches", len(matches))
			}
		})
	}
}

func pythonSchemaFixtureParseOK(ctx context.Context, pythonRepo string, query string) (bool, error) {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return false, err
	}
	script := `
import json, sys
from eql import parse_query
from eql.schema import Schema
from eql.types import TypeHint

payload = json.load(sys.stdin)
STR = TypeHint.String.value
NUM = TypeHint.Numeric.value
BOOL = TypeHint.Boolean.value
MIXED = TypeHint.Unknown.value
schema = {
    "process": {
        "command_line": STR,
        "process_name": STR,
        "pid": NUM,
        "elevated": BOOL,
    },
    "file": {
        "file_path": STR,
        "file_name": STR,
        "process_name": NUM,
        "pid": NUM,
        "data": MIXED,
    },
    "complex": {
        "string_arr": [STR],
        "wideopen": {},
        "nested": {
            "arr": [MIXED],
            "double_nested": {"nn": NUM, "triplenest": {"m": MIXED, "b": BOOL}},
            "num": NUM,
        },
        "objarray": [{}],
        "array_array": [{"s": [STR]}],
    },
}
try:
    with Schema(schema, allow_generic=True, allow_any=True):
        parse_query(payload["query"])
    ok = True
except Exception:
    ok = False
print(json.dumps({"ok": ok}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return false, err
	}
	return result.OK, nil
}

type schemaOracleOptions struct {
	AllowGeneric           bool `json:"allow_generic"`
	AllowAny               bool `json:"allow_any"`
	AllowMissing           bool `json:"allow_missing"`
	ImpliedBooleans        bool `json:"implied_booleans"`
	StrictBooleans         bool `json:"strict_booleans"`
	NonNullableFields      bool `json:"non_nullable_fields"`
	AllowEnumFields        bool `json:"allow_enum_fields"`
	ElasticsearchSyntax    bool `json:"elasticsearch_syntax"`
	ElasticEndpointSyntax  bool `json:"elastic_endpoint_syntax"`
	ValidateOptionalFields bool `json:"validate_optional_fields"`
	ExplicitEventOptions   bool `json:"explicit_event_options"`
}

func pythonSchemaParseOK(ctx context.Context, pythonRepo string, schema map[string]map[string]any, query string, opts schemaOracleOptions) (bool, error) {
	if !opts.ExplicitEventOptions && !opts.AllowGeneric && !opts.AllowAny && !opts.AllowMissing {
		opts.AllowGeneric = true
		opts.AllowAny = true
	}
	payload := map[string]any{
		"schema":  schema,
		"query":   query,
		"options": opts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	script := `
import json, sys
from contextlib import ExitStack
from eql import parse_query
from eql.parser import (
    allow_enum_fields,
    elastic_endpoint_syntax,
    elasticsearch_syntax,
    elasticsearch_validate_optional_fields,
    implied_booleans,
    non_nullable_fields,
    strict_booleans,
)
from eql.schema import Schema

payload = json.load(sys.stdin)
opts = payload["options"]
try:
    with ExitStack() as stack:
        if opts["strict_booleans"]:
            stack.enter_context(strict_booleans)
        if opts["implied_booleans"]:
            stack.enter_context(implied_booleans)
        if opts["non_nullable_fields"]:
            stack.enter_context(non_nullable_fields)
        if opts["allow_enum_fields"]:
            stack.enter_context(allow_enum_fields)
        if opts["elasticsearch_syntax"]:
            stack.enter_context(elasticsearch_syntax)
        if opts["validate_optional_fields"]:
            stack.enter_context(elasticsearch_validate_optional_fields)
        if opts["elastic_endpoint_syntax"]:
            stack.enter_context(elastic_endpoint_syntax)
        stack.enter_context(Schema(
            payload["schema"],
            allow_generic=opts["allow_generic"],
            allow_any=opts["allow_any"],
            allow_missing=opts["allow_missing"],
        ))
        parse_query(payload["query"])
    ok = True
except Exception:
    ok = False
print(json.dumps({"ok": ok}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return false, err
	}
	return result.OK, nil
}

func schemaValidationFixture() map[string]map[string]any {
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

func schemaEndpointValidationFixture() map[string]map[string]any {
	return map[string]map[string]any{
		"process": {
			"process_name": "string",
			"pid":          "number",
			"string_array": []any{"string"},
			"obj_array":    []any{map[string]any{"trusted": "boolean"}},
			"process":      map[string]any{"name": "string"},
			"unique_pid":   "string",
			"user":         map[string]any{"name": "string"},
			"field": map[string]any{
				"nested_field": []any{
					map[string]any{"nf1": "string", "nf2": "number"},
				},
			},
		},
		"file": {
			"opcode":     "number",
			"unique_pid": "string",
		},
		"network": {
			"process": map[string]any{"name": "string"},
			"user":    map[string]any{"name": "string"},
		},
	}
}

func schemaValidationPythonRepo(t *testing.T) string {
	t.Helper()
	if repo := os.Getenv("EQL_PYTHON_REPO"); repo != "" {
		return repo
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
