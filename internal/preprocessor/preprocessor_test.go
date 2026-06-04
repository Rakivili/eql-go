package preprocessor

import (
	"testing"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/parser"
)

func TestParseDefinitionsExpandsConstLiterals(t *testing.T) {
	pp, err := ParseDefinitions(`
		const TARGET = "cmd.exe"
		const ALT_TARGET == "powershell.exe"
		// Python-style line comments are ignored.
		const GOOD_PID = 10
		const ENABLED = true
		const LIMIT = 1
	`)
	if err != nil {
		t.Fatal(err)
	}
	query, err := parser.ParseQuery(`process where process_name == TARGET and pid == GOOD_PID and ENABLED | head LIMIT`)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pp.ExpandQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	logical, ok := expanded.Expr.(*ast.Logical)
	if !ok || logical.Op != "and" || len(logical.Terms) != 3 {
		t.Fatalf("expected three-term and expression, got %#v", expanded.Expr)
	}
	assertComparisonLiteral(t, logical.Terms[0], ast.LiteralString, "cmd.exe")
	assertComparisonLiteral(t, logical.Terms[1], ast.LiteralNumber, ast.Int(10))
	assertLiteral(t, logical.Terms[2], ast.LiteralBool, true)
	if len(expanded.Pipes) != 1 || len(expanded.Pipes[0].Args) != 1 {
		t.Fatalf("expected one pipe arg, got %#v", expanded.Pipes)
	}
	assertLiteral(t, expanded.Pipes[0].Args[0], ast.LiteralNumber, ast.Int(1))
}

func TestParseDefinitionsRejectsHashComments(t *testing.T) {
	if _, err := ParseDefinitions(`
		# Python rejects hash comments in definitions.
		const TARGET = "cmd.exe"
	`); err == nil {
		t.Fatal("expected hash comment definition parse error")
	}
}

func TestParseDefinitionsExpandsConstNullComparisonToNullTest(t *testing.T) {
	pp, err := ParseDefinitions(`const EMPTY = null`)
	if err != nil {
		t.Fatal(err)
	}
	query, err := parser.ParseQuery(`process where process_name == EMPTY`)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pp.ExpandQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	nullTest, ok := expanded.Expr.(*ast.IsNull)
	if !ok {
		t.Fatalf("expected IsNull after const expansion, got %#v", expanded.Expr)
	}
	field, ok := nullTest.Expr.(*ast.Field)
	if !ok || field.Base != "process_name" {
		t.Fatalf("unexpected null-test operand %#v", nullTest.Expr)
	}
}

func TestParseDefinitionsMacroNullArgumentKeepsRawComparison(t *testing.T) {
	pp, err := ParseDefinitions(`macro IS_VALUE(value) process_name == value`)
	if err != nil {
		t.Fatal(err)
	}
	query, err := parser.ParseQuery(`process where IS_VALUE(null)`)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pp.ExpandQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	cmp, ok := expanded.Expr.(*ast.Comparison)
	if !ok {
		t.Fatalf("expected raw comparison after macro substitution, got %#v", expanded.Expr)
	}
	if _, ok := cmp.Left.(*ast.Field); !ok {
		t.Fatalf("expected field left operand, got %#v", cmp.Left)
	}
	if lit, ok := cmp.Right.(*ast.Literal); !ok || lit.Kind != ast.LiteralNull {
		t.Fatalf("expected null right operand, got %#v", cmp.Right)
	}
}

func TestExpandQueryDoesNotExpandPathRoots(t *testing.T) {
	pp, err := ParseDefinitions(`const TARGET = "cmd.exe"`)
	if err != nil {
		t.Fatal(err)
	}
	query, err := parser.ParseQuery(`file where TARGET.name == "cmd.exe"`)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pp.ExpandQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	cmp, ok := expanded.Expr.(*ast.Comparison)
	if !ok {
		t.Fatalf("expected comparison, got %#v", expanded.Expr)
	}
	field, ok := cmp.Left.(*ast.Field)
	if !ok {
		t.Fatalf("expected left field, got %#v", cmp.Left)
	}
	if field.Base != "TARGET" || len(field.Path) != 1 || field.Path[0].Name != "name" {
		t.Fatalf("unexpected field after expansion: %#v", field)
	}
}

func TestParseDefinitionsExpandsMacros(t *testing.T) {
	pp, err := ParseDefinitions(`
		const TARGET = "cmd.exe"
		macro PROCESS_IS(name) process_name == name
		macro TARGET_PROCESS() PROCESS_IS(TARGET)
		macro A_OR_B(a,b)
			a or b
		macro VALUE_OF(obj) obj.value
		macro IN_GRAYLIST(proc)
			proc in (
				"msbuild.exe",
				"powershell.exe",
				"cmd.exe"
			)
	`)
	if err != nil {
		t.Fatal(err)
	}
	query, err := parser.ParseQuery(`process where A_OR_B(TARGET_PROCESS(), VALUE_OF(nested) == 7)`)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pp.ExpandQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	logical, ok := expanded.Expr.(*ast.Logical)
	if !ok || logical.Op != "or" || len(logical.Terms) != 2 {
		t.Fatalf("expected two-term or expression, got %#v", expanded.Expr)
	}
	assertComparisonLiteral(t, logical.Terms[0], ast.LiteralString, "cmd.exe")
	cmp, ok := logical.Terms[1].(*ast.Comparison)
	if !ok {
		t.Fatalf("expected comparison, got %#v", logical.Terms[1])
	}
	field, ok := cmp.Left.(*ast.Field)
	if !ok {
		t.Fatalf("expected field, got %#v", cmp.Left)
	}
	if field.Base != "nested" || len(field.Path) != 1 || field.Path[0].Name != "value" {
		t.Fatalf("unexpected extended field %#v", field)
	}
	query, err = parser.ParseQuery(`process where IN_GRAYLIST(process_name)`)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err = pp.ExpandQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := expanded.Expr.(*ast.InSet); !ok {
		t.Fatalf("expected in-set from multiline macro, got %#v", expanded.Expr)
	}
}

func TestMacroPathAndIndexExpansion(t *testing.T) {
	pp, err := ParseDefinitions(`
		macro NAME(dictfield) dictfield.name
		macro ZERO(arrayfield) arrayfield[0]
		macro ZNAME(objarray) objarray[0].name
		macro NAMEZ(arrayobj) arrayobj.name[0]
		macro ZNAME2(objarray) NAME(ZERO(objarray))
		macro NAMEZ2(arrayobj) ZERO(NAME(arrayobj))
	`)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		query string
		path  []ast.PathPart
	}{
		{
			query: `process where NAME(foo.bar.baz) == "x"`,
			path:  []ast.PathPart{{Name: "bar"}, {Name: "baz"}, {Name: "name"}},
		},
		{
			query: `process where ZERO(foo.bar.baz) == "x"`,
			path:  []ast.PathPart{{Name: "bar"}, {Name: "baz"}, {Index: 0, IsIdx: true}},
		},
		{
			query: `process where ZNAME(foo.bar.baz) == "x"`,
			path:  []ast.PathPart{{Name: "bar"}, {Name: "baz"}, {Index: 0, IsIdx: true}, {Name: "name"}},
		},
		{
			query: `process where ZNAME2(foo.bar.baz) == "x"`,
			path:  []ast.PathPart{{Name: "bar"}, {Name: "baz"}, {Index: 0, IsIdx: true}, {Name: "name"}},
		},
		{
			query: `process where NAMEZ(foo) == "x"`,
			path:  []ast.PathPart{{Name: "name"}, {Index: 0, IsIdx: true}},
		},
		{
			query: `process where NAMEZ2(foo) == "x"`,
			path:  []ast.PathPart{{Name: "name"}, {Index: 0, IsIdx: true}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			query, err := parser.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			expanded, err := pp.ExpandQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			cmp, ok := expanded.Expr.(*ast.Comparison)
			if !ok {
				t.Fatalf("expected comparison, got %#v", expanded.Expr)
			}
			field, ok := cmp.Left.(*ast.Field)
			if !ok {
				t.Fatalf("expected field, got %#v", cmp.Left)
			}
			if field.Base != "foo" || !samePath(field.Path, tc.path) {
				t.Fatalf("unexpected field %#v, want base foo path %#v", field, tc.path)
			}
		})
	}
}

func TestExpandQueryRejectsInvalidMacroCalls(t *testing.T) {
	cases := []struct {
		name  string
		defs  string
		query string
	}{
		{
			name:  "arity mismatch",
			defs:  `macro PROCESS_IS(name) process_name == name`,
			query: `process where PROCESS_IS()`,
		},
		{
			name:  "path extension requires field",
			defs:  `macro VALUE_OF(obj) obj.value`,
			query: `process where VALUE_OF("x") == "x"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pp, err := ParseDefinitions(tc.defs)
			if err != nil {
				t.Fatal(err)
			}
			query, err := parser.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pp.ExpandQuery(query); err == nil {
				t.Fatal("expected expansion error")
			}
		})
	}
}

func TestParseDefinitionsRejectsUnsupportedDefinitions(t *testing.T) {
	cases := []string{
		`const TARGET = process_name`,
		`const TARGET = "cmd.exe"
		 const TARGET = "powershell.exe"`,
		`const true = 1`,
		`const sequence = 1`,
		"const `and` = 1",
		`let X = 1`,
		`macro by() true`,
		`macro X(join) true`,
		`macro X()`,
		`macro X(,) true`,
		`macro X() wildcrad(process_name, "x")`,
		`macro X() length()`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseDefinitions(input); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func samePath(left []ast.PathPart, right []ast.PathPart) bool {
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

func assertComparisonLiteral(t *testing.T, expr ast.Expr, kind ast.LiteralKind, value any) {
	t.Helper()
	cmp, ok := expr.(*ast.Comparison)
	if !ok {
		t.Fatalf("expected comparison, got %#v", expr)
	}
	assertLiteral(t, cmp.Right, kind, value)
}

func assertLiteral(t *testing.T, expr ast.Expr, kind ast.LiteralKind, value any) {
	t.Helper()
	lit, ok := expr.(*ast.Literal)
	if !ok {
		t.Fatalf("expected literal, got %#v", expr)
	}
	if lit.Kind != kind || lit.Value != value {
		t.Fatalf("expected literal (%v, %#v), got (%v, %#v)", kind, value, lit.Kind, lit.Value)
	}
}
