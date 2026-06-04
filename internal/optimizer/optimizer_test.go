package optimizer

import (
	"reflect"
	"testing"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/parser"
)

func TestOptimizeBooleanLogic(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{expr: `a == 1 or true`, want: `true`},
		{expr: `true or a == 1`, want: `true`},
		{expr: `false or a == 1`, want: `a == 1`},
		{expr: `a == 1 or false`, want: `a == 1`},
		{expr: `a or b or false or c`, want: `a or b or c`},
		{expr: `false or null`, want: `null`},
		{expr: `null or false`, want: `null`},
		{expr: `null or null`, want: `null`},
		{expr: `null or null or false`, want: `null`},
		{expr: `null or null or true`, want: `true`},
		{expr: `a == 1 and true`, want: `a == 1`},
		{expr: `true and a == 1`, want: `a == 1`},
		{expr: `false and a == 1`, want: `false`},
		{expr: `a == 1 and false`, want: `false`},
		{expr: `a and b and true and c`, want: `a and b and c`},
		{expr: `true and null`, want: `null`},
		{expr: `null and true`, want: `null`},
		{expr: `null and null`, want: `null`},
		{expr: `null and null and true`, want: `null`},
		{expr: `null and null and false`, want: `false`},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeNot(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{expr: `not true`, want: `false`},
		{expr: `not false`, want: `true`},
		{expr: `not null`, want: `null`},
		{expr: `not not (a == 1)`, want: `a == 1`},
		{expr: `not (a == 1)`, want: `a != 1`},
		{expr: `not (a < 1)`, want: `a >= 1`},
		{expr: `not (a == null)`, want: `a != null`},
		{expr: `not (a != null)`, want: `a == null`},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeNullTests(t *testing.T) {
	cases := []struct {
		expr string
		want ast.Expr
	}{
		{expr: `null == null`, want: boolLiteral(true)},
		{expr: `null != null`, want: boolLiteral(false)},
		{expr: `"x" == null`, want: boolLiteral(false)},
		{expr: `1 != null`, want: boolLiteral(true)},
		{expr: `field == null`, want: &ast.IsNull{Expr: &ast.Field{Base: "field"}}},
		{expr: `field != null`, want: &ast.IsNotNull{Expr: &ast.Field{Base: "field"}}},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestOptimizeRawNullComparisonPropagatesNull(t *testing.T) {
	raw := &ast.Comparison{
		Left:  &ast.Literal{Kind: ast.LiteralNull},
		Op:    "==",
		Right: &ast.Literal{Kind: ast.LiteralNull},
	}
	got := OptimizeExpr(raw, defaultOptions())
	if !reflect.DeepEqual(got, nullLiteral()) {
		t.Fatalf("raw null comparison optimized to %#v, want null", got)
	}
}

func TestOptimizeConstantFolding(t *testing.T) {
	cases := []struct {
		expr string
		want ast.Expr
	}{
		{expr: `7 + 3`, want: numberLiteralExpr(ast.Int(10))},
		{expr: `7 + -3`, want: numberLiteralExpr(ast.Int(4))},
		{expr: `7 * 3.0`, want: numberLiteralExpr(ast.Float(21))},
		{expr: `7 / 3`, want: numberLiteralExpr(ast.Int(2))},
		{expr: `7 % 3`, want: numberLiteralExpr(ast.Int(1))},
		{expr: `7.5 % 2.0`, want: numberLiteralExpr(ast.Float(1.5))},
		{expr: `3 + 4 - 5 * 6 / 7`, want: numberLiteralExpr(ast.Int(3))},
		{expr: `3 < 4`, want: boolLiteral(true)},
		{expr: `3 <= 4`, want: boolLiteral(true)},
		{expr: `3 != 4`, want: boolLiteral(true)},
		{expr: `4 > 3`, want: boolLiteral(true)},
		{expr: `3 >= 4`, want: boolLiteral(false)},
		{expr: `"Foo" == "foo"`, want: boolLiteral(true)},
		{expr: `"Foo" != "foo"`, want: boolLiteral(false)},
		{expr: `true == true`, want: boolLiteral(true)},
		{expr: `true != false`, want: boolLiteral(true)},
		{expr: `true < false`, want: nullLiteral()},
		{expr: `true < true`, want: nullLiteral()},
		{expr: `null == null`, want: boolLiteral(true)},
		{expr: `null != null`, want: boolLiteral(false)},
		{expr: `null < null`, want: nullLiteral()},
		{expr: `null <= null`, want: nullLiteral()},
		{expr: `null >= null`, want: nullLiteral()},
		{expr: `null > null`, want: nullLiteral()},
		{expr: `null > 1`, want: nullLiteral()},
		{expr: `"1" == 1`, want: nullLiteral()},
		{expr: `345 in (123, 345)`, want: boolLiteral(true)},
		{expr: `345 not in (123, 456)`, want: boolLiteral(true)},
		{expr: `345 in (123, 456)`, want: boolLiteral(false)},
		{expr: `'foo' in ('foo', 'bar', 'baz')`, want: boolLiteral(true)},
		{expr: `'foo' not in ('foo', 'bar', 'baz')`, want: boolLiteral(false)},
		{expr: `'foo' in ('bar', 'baz')`, want: boolLiteral(false)},
		{expr: `'foo' in ('Foo', 'Bar', 'Baz')`, want: boolLiteral(true)},
		{expr: `null in (1, null)`, want: boolLiteral(true)},
		{expr: `null in (1)`, want: boolLiteral(false)},
		{expr: `1 in (null)`, want: boolLiteral(false)},
		{expr: `length("foo")`, want: numberLiteralExpr(ast.Int(3))},
		{expr: `startsWith("FooBarBaz", "Foo")`, want: boolLiteral(true)},
		{expr: `startsWith("FooBarBaz", "Bar")`, want: boolLiteral(false)},
		{expr: `endsWith("FooBarBaz", "Baz")`, want: boolLiteral(true)},
		{expr: `stringContains("FooBarBaz", "Bar")`, want: boolLiteral(true)},
		{expr: `wildcard("Foo", "Foo*", "*Bar*")`, want: boolLiteral(true)},
		{expr: `match("foo", "[a-z]{3}")`, want: boolLiteral(true)},
		{expr: `string(1)`, want: &ast.Literal{Kind: ast.LiteralString, Value: "1"}},
		{expr: `number("0x10")`, want: numberLiteralExpr(ast.Int(16))},
		{expr: `number("bad")`, want: nullLiteral()},
		{expr: `number("52403", 7)`, want: numberLiteralExpr(ast.Int(12890))},
		{expr: `concat("a", "||", 1, "||", true)`, want: &ast.Literal{Kind: ast.LiteralString, Value: "a||1||true"}},
		{expr: `indexOf("foobarbaz", "o", null)`, want: numberLiteralExpr(ast.Int(1))},
		{expr: `indexOf("foobarbaz", "L")`, want: nullLiteral()},
		{expr: `substring("hello world", null, 5)`, want: &ast.Literal{Kind: ast.LiteralString, Value: "hello"}},
		{expr: `between("System Idle Process", "s", "e")`, want: &ast.Literal{Kind: ast.LiteralString, Value: "yst"}},
		{expr: `between("welcome to the planet", "welcome", "village")`, want: nullLiteral()},
		{expr: `divide(7, 3)`, want: numberLiteralExpr(ast.Int(2))},
		{expr: `divide(7, 0)`, want: nullLiteral()},
		{expr: `length(null)`, want: nullLiteral()},
		{expr: `concat("a", null)`, want: nullLiteral()},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestOptimizeLeavesUnfoldableMath(t *testing.T) {
	got := OptimizeExpr(parseExpr(t, `7 / 0`), defaultOptions())
	want := parseExpr(t, `7 / 0`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("divide by zero should stay unfolded: %#v", got)
	}
	got = OptimizeExpr(parseExpr(t, `pid + 1`), defaultOptions())
	want = parseExpr(t, `pid + 1`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dynamic math should stay unfolded: %#v", got)
	}
	got = OptimizeExpr(parseExpr(t, `modulo(7, 0)`), defaultOptions())
	want = parseExpr(t, `modulo(7, 0)`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulo by zero should stay unfolded: %#v", got)
	}
}

func TestOptimizeCaseSensitiveStringComparison(t *testing.T) {
	got := OptimizeExpr(parseExpr(t, `"Foo" == "foo"`), Options{})
	want := boolLiteral(false)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("case-sensitive optimized comparison=%#v, want %#v", got, want)
	}
	got = OptimizeExpr(parseExpr(t, `'foo' in ('Foo', 'Bar', 'Baz')`), Options{})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("case-sensitive optimized in-set=%#v, want %#v", got, want)
	}
	got = OptimizeExpr(parseExpr(t, `fieldname in ("d", "D")`), Options{})
	wantExpr := parseExpr(t, `fieldname in ("d", "D")`)
	if !reflect.DeepEqual(got, wantExpr) {
		t.Fatalf("case-sensitive in-set de-duplication=%#v, want %#v", got, wantExpr)
	}
}

func TestOptimizeElasticsearchSyntaxKeepsWildcardEqualityComparison(t *testing.T) {
	got := OptimizeExpr(
		parseExpr(t, `process_name == "cmd*"`),
		Options{CaseInsensitive: true, ElasticsearchSyntax: true},
	)
	want := parseExpr(t, `process_name == "cmd*"`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Elasticsearch syntax wildcard equality=%#v, want %#v", got, want)
	}
}

func TestOptimizeOtherExpressionShapes(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{expr: `process_name in (1 + 1, 3)`, want: `process_name in (2, 3)`},
		{expr: `length(3 + 4) == 7`, want: `length(7) == 7`},
		{expr: `process_name`, want: `process_name`},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeInSetNormalization(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{expr: `pid in (4)`, want: `pid == 4`},
		{expr: `pid not in (4)`, want: `pid != 4`},
		{expr: `pid in (pid)`, want: `true`},
		{expr: `pid not in (pid)`, want: `false`},
		{
			expr: `"something" in ("str", "str2", "str3", "str4", someField)`,
			want: `"something" == someField`,
		},
		{
			expr: `"something" in ("str", "str2", "str3", "str4", field1, field2)`,
			want: `"something" in (field1, field2)`,
		},
		{
			expr: `fieldname in ("a", "b", "C", "d", 1, "d", "D", "c")`,
			want: `fieldname in ("a", "b", "C", "d", 1)`,
		},
		{
			expr: `fieldA in ("a", "b", "C", "d", fieldA, fieldB, fieldC)`,
			want: `true`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeInSetNullSingletonStaysRawComparison(t *testing.T) {
	cases := []struct {
		expr string
		op   string
	}{
		{expr: `field in (null)`, op: "=="},
		{expr: `field not in (null)`, op: "!="},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			cmp, ok := got.(*ast.Comparison)
			if !ok {
				t.Fatalf("expected raw Comparison, got %#v", got)
			}
			if cmp.Op != tc.op {
				t.Fatalf("comparison op=%q, want %q", cmp.Op, tc.op)
			}
			if _, ok := cmp.Left.(*ast.Field); !ok {
				t.Fatalf("expected field left operand, got %#v", cmp.Left)
			}
			if lit, ok := cmp.Right.(*ast.Literal); !ok || lit.Kind != ast.LiteralNull {
				t.Fatalf("expected null right operand, got %#v", cmp.Right)
			}
		})
	}
}

func TestOptimizeInSetLogicalMerges(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{
			expr: `fieldname in ("a", "b", "C", "x") and fieldname in ("d", "c", "g", "X")`,
			want: `fieldname in ("C", "x")`,
		},
		{
			expr: `fieldname in ("a", "b", "C", "x") and fieldname in ("d", "f", "g", 123)`,
			want: `false`,
		},
		{
			expr: `fieldname in ("a", "b", "C", "x") or fieldname in ("d", "c", "g", "X")`,
			want: `fieldname in ("a", "b", "C", "x", "d", "g")`,
		},
		{
			expr: `NAME in ("a", "b", "c", "d") and not NAME in ("b", "d")`,
			want: `NAME in ("a", "c")`,
		},
		{
			expr: `opcode == 1 and name in ("a", "b", "c", "d") and name in ("b", "d")`,
			want: `opcode == 1 and name in ("b", "d")`,
		},
		{
			expr: `opcode == 1 and name in ("a", "b", "c", "d") and name in ("b", "d") and x == 1`,
			want: `opcode == 1 and name in ("b", "d") and x == 1`,
		},
		{
			expr: `opcode == 1 or name in ("a", "b", "c", "d") or name in ("e", "f")`,
			want: `opcode == 1 or name in ("a", "b", "c", "d", "e", "f")`,
		},
		{
			expr: `opcode == 1 or name in ("a", "b", "c", "d") or name in ("e", "f") or x == 1`,
			want: `opcode == 1 or name in ("a", "b", "c", "d", "e", "f") or x == 1`,
		},
		{
			expr: `pid == 4 or pid == 8 or pid == 520`,
			want: `pid in (4, 8, 520)`,
		},
		{
			expr: `name in ("a", "b") or name == "c"`,
			want: `name in ("a", "b", "c")`,
		},
		{
			expr: `name in ("a", "b") and name == "c"`,
			want: `false`,
		},
		{
			expr: `name in ("a", "b") and name == "b"`,
			want: `name == "b"`,
		},
		{
			expr: `name == "c" or name in ("a", "b")`,
			want: `name in ("c", "a", "b")`,
		},
		{
			expr: `name == "c" and name in ("a", "b")`,
			want: `false`,
		},
		{
			expr: `name == "b" and name in ("a", "b")`,
			want: `name == "b"`,
		},
		{
			expr: `name in ("a", "b", "c") and name != "c"`,
			want: `name in ("a", "b")`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeWildcardComparison(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{expr: `field == "a*b*c"`, want: `wildcard(field, "a*b*c")`},
		{expr: `field != "a*b*c"`, want: `not wildcard(field, "a*b*c")`},
		{expr: `"a*b" == field`, want: `wildcard(field, "a*b")`},
		{expr: `"a*b" != field`, want: `not wildcard(field, "a*b")`},
		{expr: `"a*b" == concat(field, "foo")`, want: `wildcard(concat(field, "foo"), "a*b")`},
		{expr: `"a*b" != concat(field, "foo")`, want: `not wildcard(concat(field, "foo"), "a*b")`},
		{expr: `concat(field, "hello", "world") == "foo*bar"`, want: `wildcard(concat(field, "hello", "world"), "foo*bar")`},
		{expr: `concat(field, "hello", "world") != "foo*bar"`, want: `not wildcard(concat(field, "hello", "world"), "foo*bar")`},
		{expr: `field == "abc"`, want: `field == "abc"`},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeVariadicFunctionOrMerges(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{
			expr: `name == "foo*" or name == "*bar"`,
			want: `wildcard(name, "foo*", "*bar")`,
		},
		{
			expr: `match(name, "fo[o]") or match(name, "ba[r]?")`,
			want: `match(name, "fo[o]", "ba[r]?")`,
		},
		{
			expr: `matchLite(name, "fo[o]") or matchLite(name, "ba[r]?")`,
			want: `matchLite(name, "fo[o]", "ba[r]?")`,
		},
		{
			expr: `name == "foo*" or other_field == "bar" or name == "*baz"`,
			want: `wildcard(name, "foo*") or other_field == "bar" or wildcard(name, "*baz")`,
		},
		{
			expr: `name == "foo*" or title == "*bar"`,
			want: `wildcard(name, "foo*") or wildcard(title, "*bar")`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got := OptimizeExpr(parseExpr(t, tc.expr), defaultOptions())
			want := parseExpr(t, tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("OptimizeExpr(%q)=%#v, want %#v", tc.expr, got, want)
			}
		})
	}
}

func TestOptimizeQueryOptimizesPipes(t *testing.T) {
	query, err := parser.ParseQuery(`process where true | filter false or serial_event_id == 1 | head 1 + 1`)
	if err != nil {
		t.Fatal(err)
	}
	got := OptimizeQuery(query, defaultOptions())
	want, err := parser.ParseQuery(`process where true | filter serial_event_id == 1 | head 2`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OptimizeQuery()=%#v, want %#v", got, want)
	}
}

func TestOptimizeNilQuery(t *testing.T) {
	if OptimizeQuery(nil, defaultOptions()) != nil {
		t.Fatal("nil query should stay nil")
	}
}

func parseExpr(t *testing.T, expr string) ast.Expr {
	t.Helper()
	parsed, err := parser.ParseExpression(expr)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func defaultOptions() Options {
	return Options{CaseInsensitive: true}
}

func numberLiteralExpr(value ast.Num) ast.Expr {
	return &ast.Literal{Kind: ast.LiteralNumber, Value: value}
}
