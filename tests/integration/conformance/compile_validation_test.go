package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	eql "github.com/Rakivili/eql-go"
)

var compileErrorOracleCases = []struct {
	name             string
	query            string
	pythonSubstrings []string
	goSubstring      string
}{
	{
		name:             "safe unknown function",
		query:            `process where safe(wildcrad(process_name, "x"))`,
		pythonSubstrings: []string{"Unknown function wildcrad"},
		goSubstring:      "unknown function wildcrad",
	},
	{
		name:             "safe child arity",
		query:            `process where safe(length())`,
		pythonSubstrings: []string{"Expected at least 1 argument"},
		goSubstring:      "length expects 1 argument",
	},
	{
		name:             "safe cidr dynamic argument",
		query:            `network where safe(cidrMatch(source_address, cidr_field))`,
		pythonSubstrings: []string{"Expected literal", "not dynamic", "to cidrMatch"},
		goSubstring:      "cidrMatch argument 2 must be a string literal",
	},
	{
		name:             "cidr literal source invalid",
		query:            `network where cidrMatch("bad-ip", "0.0.0.0/0")`,
		pythonSubstrings: []string{"ValueError", "does not appear to be an IPv4 or IPv6 address"},
		goSubstring:      "cidrMatch argument 1 is not a valid IP address",
	},
	{
		name:             "safe cidr literal source invalid",
		query:            `network where safe(cidrMatch("bad-ip", "0.0.0.0/0"))`,
		pythonSubstrings: []string{"ValueError", "does not appear to be an IPv4 or IPv6 address"},
		goSubstring:      "cidrMatch argument 1 is not a valid IP address",
	},
	{
		name:             "safe child literal type",
		query:            `process where safe(length(1))`,
		pythonSubstrings: []string{"Expected", "string", "array", "not number", "to length"},
		goSubstring:      "length argument 1 must be string literal",
	},
	{
		name:             "match literal pattern type",
		query:            `process where match("eql", 1)`,
		pythonSubstrings: []string{"Expected string", "not number", "to match"},
		goSubstring:      "match argument 2 must be string literal",
	},
	{
		name:             "match dynamic pattern",
		query:            `process where match(command_line, pattern_field)`,
		pythonSubstrings: []string{"Expected literal", "not dynamic", "to match"},
		goSubstring:      "match argument 2 must be a string literal",
	},
	{
		name:             "safe match dynamic pattern",
		query:            `process where safe(match(command_line, pattern_field)) == null`,
		pythonSubstrings: []string{"Expected literal", "not dynamic", "to match"},
		goSubstring:      "match argument 2 must be a string literal",
	},
	{
		name:             "match invalid regex",
		query:            `process where match(command_line, "[")`,
		pythonSubstrings: []string{"Invalid argument to match"},
		goSubstring:      "match argument 2 is not a valid regular expression",
	},
	{
		name:             "matchLite invalid regex",
		query:            `process where matchLite(command_line, "[")`,
		pythonSubstrings: []string{"Invalid argument to matchLite"},
		goSubstring:      "matchLite argument 2 is not a valid regular expression",
	},
	{
		name:             "match variable lookbehind invalid in python",
		query:            `process where match(command_line, ?'(?<=a+)b')`,
		pythonSubstrings: []string{"Invalid argument to match"},
		goSubstring:      "look-behind requires fixed-width pattern",
	},
	{
		name:             "match atomic group invalid in python",
		query:            `process where match(command_line, ?'(?>a)')`,
		pythonSubstrings: []string{"Invalid argument to match"},
		goSubstring:      "atomic groups are not supported",
	},
	{
		name:             "match lowercase z anchor invalid in python",
		query:            `process where match(command_line, ?'\z')`,
		pythonSubstrings: []string{"Invalid argument to match"},
		goSubstring:      `bad escape \z`,
	},
	{
		name:             "match bare disable flag invalid in python",
		query:            `process where match(command_line, ?'(?-i)i')`,
		pythonSubstrings: []string{"Invalid argument to match"},
		goSubstring:      "missing : in flag group",
	},
	{
		name:             "wildcard dynamic pattern",
		query:            `process where wildcard(command_line, pattern_field)`,
		pythonSubstrings: []string{"Expected literal", "not dynamic", "to wildcard"},
		goSubstring:      "wildcard argument 2 must be a string literal",
	},
	{
		name:             "single quoted unicode escape",
		query:            `process where length('\u{41}') == 1`,
		pythonSubstrings: []string{"Invalid syntax"},
		goSubstring:      "invalid string literal",
	},
	{
		name:             "number literal source type",
		query:            `process where number(1) == null`,
		pythonSubstrings: []string{"Expected string", "not number", "to number"},
		goSubstring:      "number argument 1 must be string literal",
	},
	{
		name:             "number literal multiple signs",
		query:            `process where number("++314") == null`,
		pythonSubstrings: []string{"ValueError", "invalid literal for int()"},
		goSubstring:      "number literal is invalid",
	},
	{
		name:             "trailing dot float rejected",
		query:            `process where pid == 1.`,
		pythonSubstrings: []string{"EqlSyntaxError"},
		goSubstring:      "invalid number",
	},
	{
		name:             "boolean ordered comparison",
		query:            `process where true < false`,
		pythonSubstrings: []string{"Invalid comparison", "boolean", "boolean"},
		goSubstring:      "invalid comparison of boolean to boolean",
	},
	{
		name:             "ordered comparison dynamic boolean literal",
		query:            `process where process_name < true`,
		pythonSubstrings: []string{"Invalid comparison", "boolean", "boolean"},
		goSubstring:      "invalid comparison of unknown to boolean",
	},
	{
		name:             "string number equality comparison",
		query:            `process where "x" == 1`,
		pythonSubstrings: []string{"Invalid comparison", "string", "number"},
		goSubstring:      "invalid comparison of string to number",
	},
	{
		name:             "null boolean ordered comparison",
		query:            `process where null < true`,
		pythonSubstrings: []string{"Invalid comparison", "boolean", "boolean"},
		goSubstring:      "invalid comparison of null to boolean",
	},
	{
		name:             "not non boolean literal",
		query:            `process where not 1`,
		pythonSubstrings: []string{"Expected boolean not number"},
		goSubstring:      "expected boolean not number",
	},
	{
		name:             "and non boolean literal",
		query:            `process where false and 1`,
		pythonSubstrings: []string{"Expected boolean not number"},
		goSubstring:      "expected boolean not number",
	},
	{
		name:             "or non boolean literal",
		query:            `process where true or 1`,
		pythonSubstrings: []string{"Expected boolean not number"},
		goSubstring:      "expected boolean not number",
	},
	{
		name:             "function number as where condition",
		query:            `process where length(process_name)`,
		pythonSubstrings: []string{"Expected boolean not number"},
		goSubstring:      "expected boolean not number",
	},
	{
		name:             "in set literal type mismatch",
		query:            `process where 1 in ("x")`,
		pythonSubstrings: []string{"Unable to compare number to string"},
		goSubstring:      "invalid comparison of number to string",
	},
	{
		name:             "in set boolean number mismatch",
		query:            `process where true in (1)`,
		pythonSubstrings: []string{"Unable to compare boolean to number"},
		goSubstring:      "invalid comparison of boolean to number",
	},
	{
		name:             "math right boolean operand",
		query:            `process where pid + true > 0`,
		pythonSubstrings: []string{"Unable to add boolean"},
		goSubstring:      "math right operand expected number not boolean",
	},
	{
		name:             "math right string operand",
		query:            `process where 1 + "x" == 2`,
		pythonSubstrings: []string{"Unable to add string"},
		goSubstring:      "math right operand expected number not string",
	},
	{
		name:             "sequence maxspan missing unit",
		query:            `sequence with maxspan=5 [process where true] [file where true]`,
		pythonSubstrings: []string{"Missing time unit"},
		goSubstring:      "expected time unit",
	},
	{
		name:             "sequence maxspan invalid unit",
		query:            `sequence with maxspan=5seconds [process where true] [file where true]`,
		pythonSubstrings: []string{"Unknown time unit"},
		goSubstring:      "invalid maxspan time unit",
	},
	{
		name:             "sequence until unexpected by",
		query:            `sequence [process where true] [file where true] until [process where true] by pid`,
		pythonSubstrings: []string{"Expected 0 values"},
		goSubstring:      "sequence until by argument count must match event queries",
	},
	{
		name:             "sequence until missing stage by",
		query:            `sequence [process where true] by pid [file where true] by process_id until [process where true]`,
		pythonSubstrings: []string{"Expected 1 value"},
		goSubstring:      "sequence until by must be present",
	},
	{
		name:             "sequence fork on first stage",
		query:            `sequence [process where true] fork [file where true]`,
		pythonSubstrings: []string{"Fork is not allowed here"},
		goSubstring:      "sequence fork is not allowed on first event query",
	},
	{
		name:             "sequence fork numeric value",
		query:            `sequence [process where true] [file where true] fork=1`,
		pythonSubstrings: []string{"Invalid syntax"},
		goSubstring:      "expected boolean after fork",
	},
	{
		name:             "join stage by mismatch",
		query:            `join [process where true] by pid [file where true]`,
		pythonSubstrings: []string{"Expected 1 value"},
		goSubstring:      "join stage by must be present",
	},
	{
		name:             "join until unexpected by",
		query:            `join [process where true] [file where true] until [process where true] by pid`,
		pythonSubstrings: []string{"Expected 0 values"},
		goSubstring:      "join until by argument count must match event queries",
	},
	{
		name:             "join fork unsupported",
		query:            `join [process where true] [file where true] fork`,
		pythonSubstrings: []string{"Fork is not allowed here"},
		goSubstring:      "join fork is not supported",
	},
	{
		name:             "runs unsupported by default",
		query:            `sequence [process where true] with runs=2`,
		pythonSubstrings: []string{"Unsupported usage of repeated syntax"},
		goSubstring:      "Unsupported usage of repeated syntax",
	},
	{
		name:             "dollar variable unsupported by default",
		query:            `process where arraySearch(items, $item, $item == "a")`,
		pythonSubstrings: []string{"Invalid syntax"},
		goSubstring:      "Invalid syntax",
	},
	{
		name:             "sequence alias unsupported by default",
		query:            `sequence [process where true] as p0 [network where true]`,
		pythonSubstrings: []string{"Unsupported usage of alias syntax"},
		goSubstring:      "Unsupported usage of alias syntax",
	},
	{
		name:             "sort literal argument",
		query:            `process where true | sort 5`,
		pythonSubstrings: []string{"Expected dynamic", "not literal", "to sort"},
		goSubstring:      "sort argument 1 must be dynamic",
	},
	{
		name:             "sort folded math argument",
		query:            `process where true | sort 1 + 1`,
		pythonSubstrings: []string{"Expected dynamic", "not literal", "to sort"},
		goSubstring:      "sort argument 1 must be dynamic",
	},
	{
		name:             "sort folded function argument",
		query:            `process where true | sort length("abc")`,
		pythonSubstrings: []string{"Expected dynamic", "not literal", "to sort"},
		goSubstring:      "sort argument 1 must be dynamic",
	},
	{
		name:             "unique literal argument",
		query:            `process where true | unique "x"`,
		pythonSubstrings: []string{"Expected dynamic", "not literal", "to unique"},
		goSubstring:      "unique argument 1 must be dynamic",
	},
	{
		name:             "count literal argument",
		query:            `process where true | count 5`,
		pythonSubstrings: []string{"Expected dynamic", "not literal", "to count"},
		goSubstring:      "count argument 1 must be dynamic",
	},
	{
		name:             "unique_count literal argument",
		query:            `process where true | unique_count false`,
		pythonSubstrings: []string{"Expected dynamic", "not literal", "to unique_count"},
		goSubstring:      "unique_count argument 1 must be dynamic",
	},
}

func TestCompileErrorOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	for _, tc := range compileErrorOracleCases {
		t.Run(tc.name, func(t *testing.T) {
			pythonErr, err := pythonParseError(context.Background(), pythonRepo, tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr == "" {
				t.Fatalf("python accepted invalid query %q", tc.query)
			}
			for _, want := range tc.pythonSubstrings {
				if !strings.Contains(pythonErr, want) {
					t.Fatalf("python error %q does not contain %q", pythonErr, want)
				}
			}

			_, err = eql.Compile(tc.query)
			if err == nil {
				t.Fatalf("go accepted invalid query %q; python error: %s", tc.query, pythonErr)
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

func TestCompilePythonRegexFeaturesAcceptedOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	cases := []struct {
		name  string
		query string
	}{
		{
			name:  "match backreference",
			query: `process where match(command_line, ?'(a)\1')`,
		},
		{
			name:  "matchLite lookahead",
			query: `process where matchLite(command_line, ?'(?=a)a')`,
		},
		{
			name:  "match named backreference",
			query: `process where match(command_line, ?'(?P<word>a)(?P=word)')`,
		},
		{
			name:  "match fixed lookbehind",
			query: `process where match(command_line, ?'a(?<=a)b')`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonErr, err := pythonParseError(context.Background(), pythonRepo, tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr != "" {
				t.Fatalf("python rejected query %q: %s", tc.query, pythonErr)
			}
			if _, err := eql.Compile(tc.query); err != nil {
				t.Fatalf("go rejected query %q: %v", tc.query, err)
			}
		})
	}
}

func TestCompileNegativeSequenceErrorOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	query := `sequence [process where true] ![file where true]`
	pythonErr, err := pythonParseErrorWithParserOptions(context.Background(), pythonRepo, query, map[string]bool{
		"allow_negation": true,
		"elasticsearch":  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pythonErr, "Negative subquery used without maxspan") {
		t.Fatalf("python error %q does not contain negative maxspan message", pythonErr)
	}

	_, err = eql.Compile(query, eql.ElasticsearchSyntax(), eql.AllowNegation())
	if err == nil {
		t.Fatal("go accepted negative sequence without maxspan")
	}
	var appErr *eql.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	if appErr.Code != eql.CodeParse {
		t.Fatalf("expected CodeParse, got %d", appErr.Code)
	}
	if !strings.Contains(err.Error(), "negative subquery used without maxspan") {
		t.Fatalf("go error %q does not contain negative maxspan message", err)
	}
}

func TestCompileRunsErrorOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	cases := []struct {
		name             string
		query            string
		pythonSubstrings []string
		goSubstring      string
	}{
		{
			name:             "runs one rejected",
			query:            `sequence [process where true] with runs=1`,
			pythonSubstrings: []string{"Repeated sequence runs must be greater than 1"},
			goSubstring:      "Repeated sequence runs must be greater than 1",
		},
		{
			name:             "until runs rejected",
			query:            `sequence [process where true] [file where true] until [process where true] with runs=2`,
			pythonSubstrings: []string{"Unsupported usage of repeated syntax"},
			goSubstring:      "Unsupported usage of repeated syntax",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonErr, err := pythonParseErrorWithParserOptions(context.Background(), pythonRepo, tc.query, map[string]bool{
				"allow_runs":    true,
				"elasticsearch": true,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.pythonSubstrings {
				if !strings.Contains(pythonErr, want) {
					t.Fatalf("python error %q does not contain %q", pythonErr, want)
				}
			}

			_, err = eql.Compile(tc.query, eql.ElasticsearchSyntax(), eql.AllowRuns())
			if err == nil {
				t.Fatalf("go accepted invalid runs query %q", tc.query)
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

func TestCompileSampleGateOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	query := `sample [process where true] [file where true]`
	cases := []struct {
		name       string
		pythonOpts map[string]bool
		goOpts     []eql.RuleOption
	}{
		{name: "default", pythonOpts: map[string]bool{}},
		{name: "allow sample only", pythonOpts: map[string]bool{"allow_sample": true}, goOpts: []eql.RuleOption{eql.AllowSample()}},
		{name: "elasticsearch only", pythonOpts: map[string]bool{"elasticsearch": true}, goOpts: []eql.RuleOption{eql.ElasticsearchSyntax()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonErr, err := pythonParseErrorWithParserOptions(context.Background(), pythonRepo, query, tc.pythonOpts)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(pythonErr, "Sample not supported") {
				t.Fatalf("python error %q does not contain sample gate message", pythonErr)
			}

			_, err = eql.Compile(query, tc.goOpts...)
			if err == nil {
				t.Fatalf("go accepted sample query with options %#v", tc.pythonOpts)
			}
			var appErr *eql.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != eql.CodeParse {
				t.Fatalf("expected CodeParse, got %d", appErr.Code)
			}
			if !strings.Contains(err.Error(), "sample is not supported") {
				t.Fatalf("go error %q does not contain sample gate message", err)
			}
		})
	}

	pythonErr, err := pythonParseErrorWithParserOptions(context.Background(), pythonRepo, query, map[string]bool{
		"allow_sample":  true,
		"elasticsearch": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pythonErr != "" {
		t.Fatalf("python rejected sample with both required gates: %s", pythonErr)
	}
	if _, err := eql.Compile(query, eql.AllowSample(), eql.ElasticsearchSyntax()); err != nil {
		t.Fatalf("go rejected sample with both required gates: %v", err)
	}
}

func TestCompileUnaryPlusOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	query := `process where pid == +5`
	pythonErr, err := pythonParseError(context.Background(), pythonRepo, query)
	if err != nil {
		t.Fatal(err)
	}
	if pythonErr != "" {
		t.Fatalf("python rejected unary plus query: %s", pythonErr)
	}
	if _, err := eql.Compile(query); err != nil {
		t.Fatalf("go rejected unary plus query: %v", err)
	}
}

func TestCompileSequenceUntilForkOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	query := `sequence [process where true] [file where true] until [process where true] fork`
	pythonErr, err := pythonParseError(context.Background(), pythonRepo, query)
	if err != nil {
		t.Fatal(err)
	}
	if pythonErr != "" {
		t.Fatalf("python rejected sequence until fork: %s", pythonErr)
	}

	if _, err := eql.Compile(query); err != nil {
		t.Fatalf("go rejected sequence until fork: %v", err)
	}
}

func TestCompileBacktickEscapedFieldIdentifierOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	cases := []struct {
		name       string
		query      string
		pythonOpts map[string]bool
		goOpts     []eql.RuleOption
	}{
		{
			name:  "reserved base field",
			query: "process where `and` == 1",
		},
		{
			name:       "reserved optional path",
			query:      "process where ?`and`.`or` == null",
			pythonOpts: map[string]bool{"elasticsearch": true},
			goOpts:     []eql.RuleOption{eql.ElasticsearchSyntax()},
		},
		{
			name:       "reserved endpoint variable path",
			query:      "process where arraySearch(items, $`item`, $`item`.`or` == \"a\")",
			pythonOpts: map[string]bool{"endpoint": true},
			goOpts:     []eql.RuleOption{eql.ElasticEndpointSyntax()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.pythonOpts
			if opts == nil {
				opts = map[string]bool{}
			}
			pythonErr, err := pythonParseErrorWithParserOptions(context.Background(), pythonRepo, tc.query, opts)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr != "" {
				t.Fatalf("python rejected escaped field query: %s", pythonErr)
			}
			if _, err := eql.Compile(tc.query, tc.goOpts...); err != nil {
				t.Fatalf("go rejected escaped field query: %v", err)
			}
		})
	}
}

func TestCompileRejectsEscapedAndReservedNonFieldIdentifiersOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	cases := []struct {
		name        string
		query       string
		goSubstring string
	}{
		{
			name:        "escaped event type",
			query:       "`process` where true",
			goSubstring: "expected event type",
		},
		{
			name:        "reserved event type",
			query:       "const where true",
			goSubstring: "Invalid use of keyword",
		},
		{
			name:        "reserved field path",
			query:       "process where foo.const == 1",
			goSubstring: "Invalid use of keyword",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pythonErr, err := pythonParseError(context.Background(), pythonRepo, tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if pythonErr == "" {
				t.Fatalf("python accepted invalid identifier query %q", tc.query)
			}
			_, err = eql.Compile(tc.query)
			if err == nil {
				t.Fatalf("go accepted invalid identifier query %q; python error: %s", tc.query, pythonErr)
			}
			if !strings.Contains(err.Error(), tc.goSubstring) {
				t.Fatalf("go error %q does not contain %q", err, tc.goSubstring)
			}
		})
	}
}

func TestCompileSampleForkOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	valid := `sample [process where true] [file where true] fork`
	pythonErr, err := pythonParseErrorWithParserOptions(context.Background(), pythonRepo, valid, map[string]bool{
		"allow_sample":  true,
		"elasticsearch": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pythonErr != "" {
		t.Fatalf("python rejected non-first sample fork: %s", pythonErr)
	}
	if _, err := eql.Compile(valid, eql.AllowSample(), eql.ElasticsearchSyntax()); err != nil {
		t.Fatalf("go rejected non-first sample fork: %v", err)
	}

	invalid := `sample [process where true] fork [file where true]`
	pythonErr, err = pythonParseErrorWithParserOptions(context.Background(), pythonRepo, invalid, map[string]bool{
		"allow_sample":  true,
		"elasticsearch": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pythonErr, "Fork is not allowed here") {
		t.Fatalf("python error %q does not contain first-fork message", pythonErr)
	}
	_, err = eql.Compile(invalid, eql.AllowSample(), eql.ElasticsearchSyntax())
	if err == nil {
		t.Fatalf("go accepted first sample fork; python error: %s", pythonErr)
	}
	if !strings.Contains(err.Error(), "sample fork is not allowed on first event query") {
		t.Fatalf("go error %q does not contain sample fork message", err)
	}
}

func TestCompileOneStageSequenceElasticsearchOracle(t *testing.T) {
	pythonRepo := compileValidationPythonRepo(t)
	query := `sequence [process where true]`
	pythonErr, err := pythonParseError(context.Background(), pythonRepo, query)
	if err != nil {
		t.Fatal(err)
	}
	if pythonErr == "" {
		t.Fatal("python accepted one-stage sequence without Elasticsearch syntax")
	}
	if _, err := eql.Compile(query); err == nil {
		t.Fatal("go accepted one-stage sequence without Elasticsearch syntax")
	}

	pythonErr, err = pythonParseErrorWithParserOptions(context.Background(), pythonRepo, query, map[string]bool{"elasticsearch": true})
	if err != nil {
		t.Fatal(err)
	}
	if pythonErr != "" {
		t.Fatalf("python rejected one-stage sequence with Elasticsearch syntax: %s", pythonErr)
	}
	if _, err := eql.Compile(query, eql.ElasticsearchSyntax()); err != nil {
		t.Fatalf("go rejected one-stage sequence with Elasticsearch syntax: %v", err)
	}
}

func pythonParseError(ctx context.Context, pythonRepo string, query string) (string, error) {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return "", err
	}
	script := `
import json
import sys
from eql import parse_query
payload = json.load(sys.stdin)
try:
    parse_query(payload["query"])
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

func pythonParseErrorWithParserOptions(ctx context.Context, pythonRepo string, query string, opts map[string]bool) (string, error) {
	payload, err := json.Marshal(map[string]any{"query": query, "options": opts})
	if err != nil {
		return "", err
	}
	script := `
import contextlib
import json
import sys
from eql import parse_query
from eql.parser import allow_negation, allow_runs, allow_sample, elastic_endpoint_syntax, elasticsearch_syntax
payload = json.load(sys.stdin)
try:
    with contextlib.ExitStack() as stack:
        if payload["options"].get("allow_sample"):
            stack.enter_context(allow_sample)
        if payload["options"].get("allow_negation"):
            stack.enter_context(allow_negation)
        if payload["options"].get("allow_runs"):
            stack.enter_context(allow_runs)
        if payload["options"].get("endpoint"):
            stack.enter_context(elastic_endpoint_syntax)
        elif payload["options"].get("elasticsearch"):
            stack.enter_context(elasticsearch_syntax)
        parse_query(payload["query"])
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

func compileValidationPythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
