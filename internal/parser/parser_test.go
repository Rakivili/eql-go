package parser

import (
	"errors"
	"strings"
	"testing"

	"github.com/Rakivili/eql-go/internal/ast"
)

func TestMVPParseQuery(t *testing.T) {
	tests := []string{
		`process where true`,
		`sequence [process where true] [file where true]`,
		`sequence with maxspan=5s [process where true] [file where true]`,
		`sequence by pid with maxspan=500ms [process where true] [file where true]`,
		`sequence with maxspan=1m by pid [process where true] [file where true]`,
		`sequence by pid [process where true] [file where true]`,
		`sequence [process where true] [file where true] until [process where subtype == "stop"]`,
		`sequence by pid [process where true] [file where true] until [process where subtype == "stop"]`,
		`sequence [process where true] by pid [file where true] by process_id until [process where subtype == "stop"] by pid`,
		`sequence [process where true] [file where true] fork`,
		`sequence [process where true] [file where true] fork=true`,
		`sequence [process where true] [file where true] fork==false`,
		`sequence [process where true] [file where true] fork by pid`,
		`join [process where true] [file where true]`,
		`join by pid [process where true] [file where true]`,
		`join [process where true] by pid [file where true] by process_id`,
		`join by host [process where true] by pid [file where true] by process_id`,
		`join [process where true] [file where true] until [process where opcode == 2]`,
		`join by pid [process where true] [file where true] until [process where opcode == 2]`,
		`sequence by pid, process_name [process where true] [file where true]`,
		`sequence [process where true] by pid [file where true] by pid`,
		`sequence by host [process where true] by pid [file where true] by process_id`,
		`sequence [process where pid == 10] [file where pid == 10] [registry where true]`,
		`process where process_name == "cmd.exe"`,
		`process where pid >= 4 and process_name != null`,
		`process where process_name in ("cmd.exe", "powershell.exe")`,
		`process where process_name not in (parent_process_name, "cmd.exe")`,
		`process where pid in (10,)`,
		`process where length(process_name) == 7`,
		`process where wildcard(concat(process_name, ".bak"), "*.exe.bak")`,
		`process where matchLite(command_line, ?'.*?net1\s+\w+.*?')`,
		`process where command_line:stringContains("whoami")`,
		`file where file_name:length() == 12`,
		`process where process_name:concat(".bak"):wildcard("*.exe.bak")`,
		`process where pid == 10 and /* ignored */ process_name == "cmd.exe"`,
		`process where pid == 10 // ignored`,
		`process where concat()`,
		`process where concat(process_name,) == process_name`,
		`file where serial_event_id - 1 == 7`,
		`file where serial_event_id + 1 == 9`,
		`file where serial_event_id * 2 == 16`,
		`file where serial_event_id / 2 == 4`,
		`file where serial_event_id % 5 == 3`,
		`file where serial_event_id * (2 + 1) == 24`,
		`process where subtract(pid, -5) == 15`,
		`registry where arraySearch(bytes_written_string_list, s, s == "en-US")`,
		`registry where arrayCount(bytes_written_string_list, s, s == "*en*") == 2`,
		`network where safe(divide(process_name, process_name))`,
		`process where event of [process where true]`,
		`file where event of [process where process_name == "python.exe"]`,
		`process where child of [process where true]`,
		`file where child of [process where process_name == "python.exe"]`,
		`process where descendant of [process where true]`,
		`file where descendant of [process where process_name == "python.exe"]`,
		`process where true | head 2`,
		`process where true | tail 2`,
		`process where true | tail`,
		`process where true | count`,
		`process where true | count process_name`,
		`process where true | count process_name, pid`,
		`process where true | unique_count process_name`,
		`process where true | unique_count process_name, pid`,
		`process where true | sort pid`,
		`process where true | sort parent_process_name, pid`,
		`process where true | sort parent_process_name pid`,
		`process where true | filter serial_event_id >= 4 | head 2`,
		`process where true | filter percent >= .5`,
		`process where true | unique pid > 0`,
		`process where true | unique parent_process_name, pid > 0`,
		`process where true | unique parent_process_name pid > 0`,
		`process where not (pid == 0 or process_name == "x")`,
		`generic where top[0].middle.name == 'abc'`,
	}
	for _, text := range tests {
		if _, err := ParseQuery(text); err != nil {
			t.Fatalf("ParseQuery(%q) error: %v", text, err)
		}
	}
}

func TestMVPRejectUnsupported(t *testing.T) {
	for _, text := range []string{
		`sequence [process where true]`,
		`sequence by [process where true] [file where true]`,
		`sequence with maxspan=5 [process where true] [file where true]`,
		`sequence with maxspan=1.5s [process where true] [file where true]`,
		`sequence with maxspan=2seconds [process where true] [file where true]`,
		`sequence with maxspan=5s with maxspan=6s [process where true] [file where true]`,
		`sequence [process where true] [file where true] until`,
		`sequence [process where true] [file where true] until [process where 1]`,
		`sequence [process where true] [file where true] fork=1`,
		`sequence [process where true] [file where true] fork=yes`,
		`join [process where true]`,
		`join [process where true] [file where true] until`,
		`join [process where true] [file where true] fork=1`,
		`sample [process where true] [file where true]`,
		`sequence [process where 1] [file where true]`,
		`process where 0`,
		`process where "x"`,
		`process where process_name in ()`,
		`process where process_name in "cmd.exe"`,
		`process where length(process_name,`,
		`process where process_name:length () == 7`,
		`process where 1 + 2`,
		`process where serial_event_id +`,
		`process where true @`,
		`process where pid == 10 /* unterminated`,
		`process where true |`,
	} {
		if _, err := ParseQuery(text); err == nil {
			t.Fatalf("ParseQuery(%q) expected error", text)
		}
	}
}

func TestParseErrorSyntaxDiagnostic(t *testing.T) {
	query := `process where and`
	_, err := ParseQuery(query)
	if err == nil {
		t.Fatal("expected parse error")
	}
	var parseErr *ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ParseError, got %T", err)
	}
	if want := strings.Index(query, "and"); parseErr.Pos != want {
		t.Fatalf("Pos=%d, want %d", parseErr.Pos, want)
	}
	if parseErr.Line != 1 || parseErr.Column != 15 {
		t.Fatalf("line/column=%d/%d, want 1/15", parseErr.Line, parseErr.Column)
	}
	if parseErr.Source != query {
		t.Fatalf("Source=%q, want %q", parseErr.Source, query)
	}
	if parseErr.Width != len("and") {
		t.Fatalf("Width=%d, want %d", parseErr.Width, len("and"))
	}
	if !strings.Contains(parseErr.Caret, "^") {
		t.Fatalf("Caret=%q, want caret marker", parseErr.Caret)
	}
	for _, want := range []string{
		"Error at line:1,column:15",
		"expected expression",
		query,
		parseErr.Caret,
	} {
		if !strings.Contains(parseErr.Error(), want) {
			t.Fatalf("Error()=%q, want substring %q", parseErr.Error(), want)
		}
	}
}

func TestParseQueryWithSourceMapFunctionCall(t *testing.T) {
	query := `process where length(process_name)`
	parsed, sourceMap, err := ParseQueryWithSourceMap(query, Options{})
	if err != nil {
		t.Fatal(err)
	}
	call, ok := parsed.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expr=%T, want FunctionCall", parsed.Expr)
	}
	span, ok := sourceMap.Span(call)
	if !ok {
		t.Fatal("expected function call source span")
	}
	if want := strings.Index(query, "length"); span.Pos != want {
		t.Fatalf("Pos=%d, want %d", span.Pos, want)
	}
	if span.Width != len("length") {
		t.Fatalf("Width=%d, want %d", span.Width, len("length"))
	}
}

func TestParseErrorMultilineDiagnostic(t *testing.T) {
	query := "process where true\n| filter and"
	_, err := ParseQuery(query)
	if err == nil {
		t.Fatal("expected parse error")
	}
	var parseErr *ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ParseError, got %T", err)
	}
	if parseErr.Line != 2 || parseErr.Column != 10 {
		t.Fatalf("line/column=%d/%d, want 2/10", parseErr.Line, parseErr.Column)
	}
	if want := "| filter and"; parseErr.Source != want {
		t.Fatalf("Source=%q, want %q", parseErr.Source, want)
	}
	if !strings.Contains(parseErr.Error(), "Error at line:2,column:10") {
		t.Fatalf("Error()=%q, want multiline coordinate", parseErr.Error())
	}
}

func TestParseErrorEOFDiagnostic(t *testing.T) {
	query := `process where (pid == 1`
	_, err := ParseQuery(query)
	if err == nil {
		t.Fatal("expected parse error")
	}
	var parseErr *ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ParseError, got %T", err)
	}
	if parseErr.Pos != len(query) {
		t.Fatalf("Pos=%d, want %d", parseErr.Pos, len(query))
	}
	if parseErr.Line != 1 || parseErr.Column != len(query)+1 {
		t.Fatalf("line/column=%d/%d, want 1/%d", parseErr.Line, parseErr.Column, len(query)+1)
	}
	if parseErr.Source != query {
		t.Fatalf("Source=%q, want %q", parseErr.Source, query)
	}
	if !strings.Contains(parseErr.Caret, "^") {
		t.Fatalf("Caret=%q, want caret marker", parseErr.Caret)
	}
	if !strings.Contains(parseErr.Error(), "Error at line:1,column:24") {
		t.Fatalf("Error()=%q, want EOF coordinate", parseErr.Error())
	}
}

func TestParseNullComparisonASTNodes(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{query: `process where field == null`, want: "is-null"},
		{query: `process where null == field`, want: "is-null"},
		{query: `process where field != null`, want: "is-not-null"},
		{query: `process where null != field`, want: "is-not-null"},
		{query: `process where field > null`, want: "comparison"},
		{query: `process where field in (null)`, want: "in-set"},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.want {
			case "is-null":
				node, ok := q.Expr.(*ast.IsNull)
				if !ok {
					t.Fatalf("expected IsNull, got %#v", q.Expr)
				}
				assertNullTestField(t, node.Expr)
			case "is-not-null":
				node, ok := q.Expr.(*ast.IsNotNull)
				if !ok {
					t.Fatalf("expected IsNotNull, got %#v", q.Expr)
				}
				assertNullTestField(t, node.Expr)
			case "comparison":
				if _, ok := q.Expr.(*ast.Comparison); !ok {
					t.Fatalf("expected Comparison, got %#v", q.Expr)
				}
			case "in-set":
				if _, ok := q.Expr.(*ast.InSet); !ok {
					t.Fatalf("expected InSet, got %#v", q.Expr)
				}
			}
		})
	}
}

func assertNullTestField(t *testing.T, expr ast.Expr) {
	t.Helper()
	field, ok := expr.(*ast.Field)
	if !ok || field.Base != "field" || len(field.Path) != 0 {
		t.Fatalf("expected field null-test operand, got %#v", expr)
	}
}

func TestParseSampleWithOption(t *testing.T) {
	valid := []string{
		`sample [process where true] [file where true]`,
		`sample by pid [process where true] [file where true]`,
		`sample [process where true] by pid [file where true] by process_id`,
		`sample [process where true] [file where true] fork`,
		`sample [process where true] [file where true] fork=false`,
		`sample [process where true] [file where true] | head 1`,
	}
	for _, text := range valid {
		t.Run(text, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(text, Options{AllowSample: true, ElasticsearchSyntax: true}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{name: "default"},
		{name: "allow sample only", opts: Options{AllowSample: true}},
		{name: "elasticsearch only", opts: Options{ElasticsearchSyntax: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(`sample [process where true] [file where true]`, tc.opts); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
	invalid := []string{
		`sample [process where true]`,
		`sample by [process where true] [file where true]`,
	}
	for _, text := range invalid {
		t.Run(text, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(text, Options{AllowSample: true, ElasticsearchSyntax: true}); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseBacktickEscapedFieldIdentifiers(t *testing.T) {
	q, err := ParseQueryWithOptions("process where ?`and`.`or` == 1", Options{ElasticsearchSyntax: true})
	if err != nil {
		t.Fatal(err)
	}
	cmp, ok := q.Expr.(*ast.Comparison)
	if !ok {
		t.Fatalf("expr=%T, want Comparison", q.Expr)
	}
	field, ok := cmp.Left.(*ast.Field)
	if !ok {
		t.Fatalf("left=%T, want Field", cmp.Left)
	}
	if !field.Optional || field.Base != "and" || !parserSamePath(field.Path, []ast.PathPart{{Name: "or"}}) {
		t.Fatalf("field=%#v, want optional and.or", field)
	}

	q, err = ParseQueryWithOptions("process where arraySearch(items, $`item`, $`item`.`or` == \"a\")", Options{ElasticEndpointSyntax: true})
	if err != nil {
		t.Fatal(err)
	}
	call, ok := q.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expr=%T, want FunctionCall", q.Expr)
	}
	scoped, ok := call.Args[1].(*ast.Field)
	if !ok || !scoped.Scoped || scoped.Base != "item" {
		t.Fatalf("arg1=%#v, want scoped item field", call.Args[1])
	}
}

func TestRejectBacktickEscapedEventType(t *testing.T) {
	if _, err := ParseQuery("`process` where true"); err == nil {
		t.Fatal("expected escaped event type parse error")
	}
}

func TestRejectReservedKeywordsInIdentifierRoles(t *testing.T) {
	keywords := []string{"and", "by", "const", "false", "in", "join", "macro", "not", "null", "of", "or", "sample", "sequence", "true", "until", "with", "where"}
	for _, keyword := range keywords {
		t.Run("event "+keyword, func(t *testing.T) {
			if _, err := ParseQuery(keyword + " where true"); err == nil {
				t.Fatal("expected event keyword parse error")
			}
		})
		t.Run("field path "+keyword, func(t *testing.T) {
			if _, err := ParseQuery("process where foo." + keyword + " == 1"); err == nil {
				t.Fatal("expected field keyword parse error")
			}
		})
	}
}

func TestParseNegativeSequenceWithOptions(t *testing.T) {
	cases := []struct {
		query   string
		negated []bool
	}{
		{
			query:   `sequence with maxspan=5s [process where true] ![file where true]`,
			negated: []bool{false, true},
		},
		{
			query:   `sequence with maxspan=5s ![process where true] [file where true]`,
			negated: []bool{true, false},
		},
		{
			query:   `sequence with maxspan=5s [process where true] ![file where true] [registry where true]`,
			negated: []bool{false, true, false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(tc.query, Options{
				AllowNegation:       true,
				ElasticsearchSyntax: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(q.Sequence) != len(tc.negated) {
				t.Fatalf("sequence parts=%d, want %d", len(q.Sequence), len(tc.negated))
			}
			for i, want := range tc.negated {
				if q.Sequence[i].Negated != want {
					t.Fatalf("part %d negated=%v, want %v", i, q.Sequence[i].Negated, want)
				}
			}
		})
	}
}

func TestRejectNegativeSequenceWithoutRequiredOptions(t *testing.T) {
	query := `sequence with maxspan=5s [process where true] ![file where true]`
	cases := []struct {
		name string
		opts Options
	}{
		{name: "default"},
		{name: "elasticsearch only", opts: Options{ElasticsearchSyntax: true}},
		{name: "allow negation only", opts: Options{AllowNegation: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, tc.opts); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseOneStageSequenceRequiresElasticsearchSyntax(t *testing.T) {
	query := `sequence [process where true]`
	if _, err := ParseQuery(query); err == nil {
		t.Fatal("expected default parser to reject one-stage sequence")
	}
	q, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Sequence) != 1 {
		t.Fatalf("sequence parts=%d, want 1", len(q.Sequence))
	}
}

func TestParseSequenceRunsWithOptions(t *testing.T) {
	cases := []struct {
		query string
		want  int
	}{
		{query: `sequence [process where true] with runs=3`, want: 3},
		{query: `sequence [process where true] [file where true] with runs=2`, want: 3},
		{query: `sequence [process where true] by pid [file where true] by pid with runs=2`, want: 3},
		{query: `sequence [process where true] [file where true] with runs==2`, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(tc.query, Options{
				AllowRuns:           true,
				ElasticsearchSyntax: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(q.Sequence) != tc.want {
				t.Fatalf("sequence parts=%d, want %d", len(q.Sequence), tc.want)
			}
		})
	}
}

func TestRejectSequenceRunsWithoutRequiredOptions(t *testing.T) {
	query := `sequence [process where true] with runs=2`
	cases := []struct {
		name string
		opts Options
	}{
		{name: "default"},
		{name: "elasticsearch only", opts: Options{ElasticsearchSyntax: true}},
		{name: "allow runs only", opts: Options{AllowRuns: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, tc.opts); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestRejectInvalidSequenceRuns(t *testing.T) {
	cases := []string{
		`sequence [process where true] with runs=0`,
		`sequence [process where true] with runs=1`,
		`sequence [process where true] with runs=-1`,
		`sequence [process where true] with runs=2.5`,
		`sequence [process where true] [file where true] until [process where true] with runs=2`,
	}
	for _, query := range cases {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, Options{
				AllowRuns:           true,
				ElasticsearchSyntax: true,
			}); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseElasticEndpointDollarVariables(t *testing.T) {
	cases := []struct {
		query string
		path  int
	}{
		{query: `process where arraySearch(items, $item, $item == "a")`},
		{query: `process where arraySearch(objects, $sig, $sig.trusted == true)`, path: 1},
		{query: `process where $top_level == 1`},
		{query: `process where process_name : "cmd*"`, path: -1},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(tc.query, Options{ElasticEndpointSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			if tc.path < 0 {
				return
			}
			if !hasScopedField(q.Expr) {
				t.Fatalf("expected scoped field in %#v", q.Expr)
			}
		})
	}
}

func TestRejectDollarVariablesWithoutEndpointSyntax(t *testing.T) {
	query := `process where arraySearch(items, $item, $item == "a")`
	cases := []struct {
		name string
		opts Options
	}{
		{name: "default"},
		{name: "elasticsearch", opts: Options{ElasticsearchSyntax: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, tc.opts); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseElasticEndpointSequenceAliases(t *testing.T) {
	cases := []struct {
		name  string
		query string
		opts  Options
		want  []string
	}{
		{
			name:  "sequence first stage alias",
			query: `sequence [process where true] as p0 [network where true]`,
			opts:  Options{ElasticEndpointSyntax: true},
			want:  []string{"p0", ""},
		},
		{
			name:  "sequence final stage alias",
			query: `sequence [process where true] [network where true] as p1`,
			opts:  Options{ElasticEndpointSyntax: true},
			want:  []string{"", "p1"},
		},
		{
			name:  "sequence runs alias",
			query: `sequence [file where true] with runs=2 as f0`,
			opts:  Options{ElasticEndpointSyntax: true, AllowRuns: true},
			want:  []string{"f0", "f0"},
		},
		{
			name:  "join alias",
			query: `join [process where true] as p0 [network where true]`,
			opts:  Options{ElasticEndpointSyntax: true},
			want:  []string{"p0", ""},
		},
		{
			name:  "sample alias",
			query: `sample [process where true] as p0 [network where true]`,
			opts:  Options{ElasticsearchSyntax: true, ElasticEndpointSyntax: true, AllowSample: true},
			want:  []string{"p0", ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseQueryWithOptions(tc.query, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			parts := q.Sequence
			if len(parts) == 0 {
				parts = q.Join
			}
			if len(parts) == 0 {
				parts = q.Sample
			}
			if len(parts) != len(tc.want) {
				t.Fatalf("parts=%d, want %d", len(parts), len(tc.want))
			}
			for i, want := range tc.want {
				if parts[i].Alias != want {
					t.Fatalf("part %d alias=%q, want %q", i, parts[i].Alias, want)
				}
			}
		})
	}
}

func TestRejectSequenceAliasesWithoutEndpointSyntax(t *testing.T) {
	query := `sequence [process where true] as p0 [network where true]`
	cases := []struct {
		name string
		opts Options
	}{
		{name: "default"},
		{name: "elasticsearch", opts: Options{ElasticsearchSyntax: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, tc.opts); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseElasticsearchStringPredicates(t *testing.T) {
	cases := []struct {
		query string
		fn    string
		args  int
	}{
		{query: `process where process_name : "cmd*"`, fn: "wildcard", args: 2},
		{query: `process where process_name : """cmd*"""`, fn: "wildcard", args: 2},
		{query: `process where process_name : """""cmd*"""""`, fn: "wildcard", args: 2},
		{query: `process where process_name : ("cmd*", "power*")`, fn: "wildcard", args: 3},
		{query: `process where process_name : ("cmd*", """power*""")`, fn: "wildcard", args: 3},
		{query: `process where process_name like "cmd*"`, fn: "wildcard", args: 2},
		{query: `process where process_name like ("cmd*", "power*")`, fn: "wildcard", args: 3},
		{query: `process where process_name like~ ("cmd*", "power*")`, fn: "wildcard", args: 3},
		{query: `process where process_name regex "cmd.*"`, fn: "match", args: 2},
		{query: `process where process_name regex ("cmd.*", "power.*")`, fn: "match", args: 3},
		{query: `process where process_name regex~ ("cmd.*", "power.*")`, fn: "match", args: 3},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(tc.query, Options{ElasticsearchSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			call, ok := q.Expr.(*ast.FunctionCall)
			if !ok {
				t.Fatalf("expr=%T, want FunctionCall", q.Expr)
			}
			if call.Name != tc.fn {
				t.Fatalf("function=%s, want %s", call.Name, tc.fn)
			}
			if len(call.Args) != tc.args {
				t.Fatalf("arg count=%d, want %d", len(call.Args), tc.args)
			}
		})
	}
}

func TestElasticsearchStringLiteralSyntax(t *testing.T) {
	valid := []struct {
		query string
		want  string
	}{
		{query: `process where process_name == "cmd.exe"`, want: "cmd.exe"},
		{query: `process where process_name == """cmd.exe"""`, want: "cmd.exe"},
		{query: `process where process_name == """""cmd.exe"""""`, want: `""cmd.exe""`},
		{query: `process where process_name in~ ("cmd.exe", """powershell.exe""")`, want: ""},
	}
	for _, tc := range valid {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(tc.query, Options{ElasticsearchSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				return
			}
			cmp, ok := q.Expr.(*ast.Comparison)
			if !ok {
				t.Fatalf("expr=%T, want Comparison", q.Expr)
			}
			lit, ok := cmp.Right.(*ast.Literal)
			if !ok || lit.Kind != ast.LiteralString {
				t.Fatalf("right=%T, want string literal", cmp.Right)
			}
			if lit.Value != tc.want {
				t.Fatalf("literal=%q, want %q", lit.Value, tc.want)
			}
		})
	}

	invalid := []string{
		`process where process_name == 'cmd.exe'`,
		`process where process_name == ?'cmd.exe'`,
		`process where process_name == ?"cmd.exe"`,
		`process where process_name == "cmd.exe`,
		`process where process_name == """cmd.exe`,
		"process where process_name == \"cmd\n.exe\"",
		"process where process_name == \"\"\"cmd\n.exe\"\"\"",
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true}); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestRejectStringLiteralsWithRawNewline(t *testing.T) {
	cases := []struct {
		name  string
		query string
		opts  Options
	}{
		{name: "double quoted default", query: "process where process_name == \"cmd\n.exe\""},
		{name: "double quoted elasticsearch", query: "process where process_name == \"cmd\n.exe\"", opts: Options{ElasticsearchSyntax: true}},
		{name: "triple quoted elasticsearch", query: "process where process_name == \"\"\"cmd\n.exe\"\"\"", opts: Options{ElasticsearchSyntax: true}},
		{name: "raw double quoted default", query: "process where process_name == ?\"cmd\n.exe\""},
		{name: "raw single quoted default", query: "process where process_name == ?'cmd\n.exe'"},
		{name: "raw double quoted elasticsearch", query: "process where process_name == ?\"cmd\n.exe\"", opts: Options{ElasticsearchSyntax: true}},
		{name: "raw single quoted elasticsearch", query: "process where process_name == ?'cmd\n.exe'", opts: Options{ElasticsearchSyntax: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(tc.query, tc.opts); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestElasticsearchTildeFunctionCalls(t *testing.T) {
	for _, query := range []string{
		`process where wildcard~(process_name, "cmd*")`,
		`process where wildcard~ (process_name, "cmd*")`,
	} {
		t.Run(query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			call, ok := q.Expr.(*ast.FunctionCall)
			if !ok {
				t.Fatalf("expr=%T, want FunctionCall", q.Expr)
			}
			if strings.HasSuffix(call.Name, "~") {
				t.Fatalf("function name still has tilde suffix: %q", call.Name)
			}
		})
	}
}

func TestRejectElasticsearchTildeMethodCalls(t *testing.T) {
	for _, query := range []string{
		`process where process_name:stringContains~("cmd")`,
		`process where process_name:stringContains~ ("cmd")`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true}); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestRejectTildeFunctionCallsByDefault(t *testing.T) {
	for _, query := range []string{
		`process where wildcard~(process_name, "cmd*")`,
		`process where wildcard~ (process_name, "cmd*")`,
		`process where process_name:stringContains~("cmd")`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQuery(query); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestRejectElasticsearchOnlyStringLiteralSyntaxByDefault(t *testing.T) {
	for _, query := range []string{
		`process where process_name == """cmd.exe"""`,
		`process where process_name : """cmd.exe"""`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQuery(query); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseElasticsearchInsensitiveIn(t *testing.T) {
	for _, query := range []string{
		`process where process_name in~ ("cmd.exe", "powershell.exe")`,
		`process where process_name not in~ ("cmd.exe", "powershell.exe")`,
	} {
		t.Run(query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			if q.Expr == nil {
				t.Fatal("expected expression")
			}
		})
	}
}

func TestParseElasticsearchOptionalFields(t *testing.T) {
	for _, query := range []string{
		`process where ?process_name == "cmd.exe"`,
		`process where ?process.name : "cmd*"`,
		`process where ?unknown_field == null`,
		`process where ?unknown.field : "cmd*"`,
	} {
		t.Run(query, func(t *testing.T) {
			q, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true})
			if err != nil {
				t.Fatal(err)
			}
			if !hasOptionalField(q.Expr) {
				t.Fatalf("expected optional field in %#v", q.Expr)
			}
		})
	}
}

func TestRejectElasticsearchStringPredicatesByDefault(t *testing.T) {
	for _, query := range []string{
		`process where process_name : "cmd*"`,
		`process where process_name like ("cmd*", "power*")`,
		`process where process_name regex ("cmd.*", "power.*")`,
		`process where process_name in~ ("cmd.exe")`,
		`process where process_name not in~ ("cmd.exe")`,
		`process where ?process_name == "cmd.exe"`,
		`process where ?process_name : "cmd*"`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQuery(query); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestRejectInvalidElasticsearchStringPredicateValues(t *testing.T) {
	for _, query := range []string{
		`process where process_name : length(process_name)`,
		`process where process_name like ()`,
		`process where process_name : ("cmd*",)`,
		`process where process_name regex (command_line)`,
		`process where process_name = "cmd.exe"`,
	} {
		t.Run(query, func(t *testing.T) {
			if _, err := ParseQueryWithOptions(query, Options{ElasticsearchSyntax: true}); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func hasOptionalField(expr ast.Expr) bool {
	switch n := expr.(type) {
	case *ast.Field:
		return n.Optional
	case *ast.FunctionCall:
		for _, arg := range n.Args {
			if hasOptionalField(arg) {
				return true
			}
		}
	case *ast.Comparison:
		return hasOptionalField(n.Left) || hasOptionalField(n.Right)
	case *ast.IsNull:
		return hasOptionalField(n.Expr)
	case *ast.IsNotNull:
		return hasOptionalField(n.Expr)
	case *ast.InSet:
		if hasOptionalField(n.Expr) {
			return true
		}
		for _, value := range n.Values {
			if hasOptionalField(value) {
				return true
			}
		}
	case *ast.Not:
		return hasOptionalField(n.Term)
	case *ast.Logical:
		for _, term := range n.Terms {
			if hasOptionalField(term) {
				return true
			}
		}
	case *ast.MathOperation:
		return hasOptionalField(n.Left) || hasOptionalField(n.Right)
	}
	return false
}

func parserSamePath(left []ast.PathPart, right []ast.PathPart) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func hasScopedField(expr ast.Expr) bool {
	switch n := expr.(type) {
	case *ast.Field:
		return n.Scoped
	case *ast.FunctionCall:
		for _, arg := range n.Args {
			if hasScopedField(arg) {
				return true
			}
		}
	case *ast.Comparison:
		return hasScopedField(n.Left) || hasScopedField(n.Right)
	case *ast.IsNull:
		return hasScopedField(n.Expr)
	case *ast.IsNotNull:
		return hasScopedField(n.Expr)
	case *ast.InSet:
		if hasScopedField(n.Expr) {
			return true
		}
		for _, value := range n.Values {
			if hasScopedField(value) {
				return true
			}
		}
	case *ast.Logical:
		for _, term := range n.Terms {
			if hasScopedField(term) {
				return true
			}
		}
	case *ast.Not:
		return hasScopedField(n.Term)
	}
	return false
}

func TestParseExpression(t *testing.T) {
	for _, text := range []string{
		`7 + 3`,
		`+5`,
		`1 - +2`,
		`pid == +5`,
		`"hello":length()`,
		`concat("cmd", ".exe"):length()`,
		`(100 * 10) - ("hello":length())`,
		`a == 1 or true`,
		`not (process_name == "cmd.exe")`,
		`.5 < 1`,
		`1e2 == 100`,
		`1.0e2 == 100`,
	} {
		if _, err := ParseExpression(text); err != nil {
			t.Fatalf("ParseExpression(%q) error: %v", text, err)
		}
	}
	for _, text := range []string{
		`1.`,
		`1.e2`,
		`pid == 1.`,
	} {
		if _, err := ParseExpression(text); err == nil {
			t.Fatalf("ParseExpression(%q) expected error", text)
		}
	}
	if _, err := ParseExpression(`a == 1 | head 1`); err == nil {
		t.Fatal("expected expression parser to reject trailing tokens")
	}
}

func TestParseSequenceMaxSpanDuration(t *testing.T) {
	cases := []struct {
		query string
		want  int64
	}{
		{query: `sequence with maxspan=5s [process where true] [file where true]`, want: 50_000_000},
		{query: `sequence with maxspan=5000ms [process where true] [file where true]`, want: 50_000_000},
		{query: `sequence with maxspan=500ms [process where true] [file where true]`, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			q, err := ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if !q.HasMaxSpan {
				t.Fatal("expected query to record maxspan")
			}
			if q.MaxSpan != tc.want {
				t.Fatalf("MaxSpan=%d, want %d", q.MaxSpan, tc.want)
			}
		})
	}
}

func TestUnquoteStringEscapes(t *testing.T) {
	cases := []struct {
		source string
		want   string
	}{
		{source: `"just \u{41} here"`, want: "just A here"},
		{source: `"just \u{041} here"`, want: "just A here"},
		{source: `"just \u{0041} here"`, want: "just A here"},
		{source: `"just \u{407} here"`, want: "just Ї here"},
		{source: `"just \u{1F4A9} here"`, want: "just 💩 here"},
		{source: `"a\nb\tc"`, want: "a\nb\tc"},
		{source: `'a\nb\tc'`, want: "a\nb\tc"},
		{source: `?'a\nb'`, want: `a\nb`},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			got, err := unquote(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("unquote(%q)=%q, want %q", tc.source, got, tc.want)
			}
		})
	}

	invalid := []string{
		`"just \u{0} here"`,
		`"just \u{1} here"`,
		`"just \u{0000001F4A9} here"`,
		`"just \u{not-hex} here"`,
		`'just \u{41} here'`,
		`"bad \z escape"`,
	}
	for _, source := range invalid {
		t.Run(source, func(t *testing.T) {
			if _, err := unquote(source); err == nil {
				t.Fatal("expected unquote error")
			}
		})
	}
}
