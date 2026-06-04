package conformance

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestFoldingOracleSubset(t *testing.T) {
	pythonRepo := foldingPythonRepo(t)
	cases := []struct {
		name          string
		expression    string
		caseSensitive bool
	}{
		{name: "add ints", expression: `7 + 3`},
		{name: "add negative", expression: `7 + -3`},
		{name: "multiply int float", expression: `7 * 3.0`},
		{name: "floor divide ints", expression: `7 / 3`},
		{name: "divide float", expression: `7 / 3.0`},
		{name: "modulo ints", expression: `7 % 3`},
		{name: "compound arithmetic", expression: `3 + 4 - 5 * 6 / 7`},
		{name: "grouped arithmetic", expression: `((3 + 4) - 5) * 6 / 7`},
		{name: "integer comparison", expression: `-3 < 4`},
		{name: "int float comparison", expression: `3 >= 4.0`},
		{name: "string insensitive equality", expression: `"Foo" == "foo"`},
		{name: "string sensitive equality", expression: `"Foo" == "foo"`, caseSensitive: true},
		{name: "null equality", expression: `null == null`},
		{name: "null ordered comparison", expression: `null > 1`},
		{name: "or true null", expression: `true or null`},
		{name: "or false null", expression: `false or null`},
		{name: "or null false", expression: `null or false`},
		{name: "or null null", expression: `null or null`},
		{name: "or null null true", expression: `null or null or true`},
		{name: "or null null false", expression: `null or null or false`},
		{name: "and true null", expression: `true and null`},
		{name: "and false null", expression: `false and null`},
		{name: "and null true", expression: `null and true`},
		{name: "and null false", expression: `null and false`},
		{name: "and null null", expression: `null and null`},
		{name: "and null null true", expression: `null and null and true`},
		{name: "and null null false", expression: `null and null and false`},
		{name: "in set numeric match", expression: `345 in (123, 345)`},
		{name: "not in set numeric miss", expression: `345 not in (123, 456)`},
		{name: "in set string miss", expression: `'foo' in ('bar', 'baz')`},
		{name: "in set string insensitive match", expression: `'foo' in ('Foo', 'Bar', 'Baz')`},
		{name: "in set string sensitive miss", expression: `'foo' in ('Foo', 'Bar', 'Baz')`, caseSensitive: true},
		{name: "not in set string match", expression: `'Foo' not in ('Foo', 'Bar', 'Baz')`},
		{name: "length function", expression: `length("foo")`},
		{name: "length unicode accent", expression: `length("é")`},
		{name: "length unicode cjk", expression: `length("你好")`},
		{name: "unicode escape", expression: `length("just \u{1F4A9} here")`},
		{name: "startsWith function", expression: `startsWith("FooBarBaz", "Foo")`},
		{name: "startsWith false", expression: `startsWith("FooBarBaz", "Bar")`},
		{name: "endsWith function", expression: `endsWith("FooBarBaz", "Baz")`},
		{name: "stringContains function", expression: `stringContains("FooBarBaz", "Bar")`},
		{name: "wildcard function", expression: `wildcard("Foo", "Foo*", "*Bar*")`},
		{name: "wildcard dotall", expression: `wildcard("foo\nbar", "foo*bar")`},
		{name: "wildcard case-sensitive", expression: `wildcard("foo", "F*o*o*")`, caseSensitive: true},
		{name: "match function", expression: `match("foo", "[a-z]{3}")`},
		{name: "match backreference", expression: `match("aa", ?'(a)\1')`},
		{name: "matchLite lookahead", expression: `matchLite("abc", ?'(?=a)a')`},
		{name: "match named backreference", expression: `match("aa", ?'(?P<word>a)(?P=word)')`},
		{name: "match variadic backreference", expression: `match("aa", ?'z+', ?'(a)\1')`},
		{name: "match absolute end anchor", expression: `match("a", ?'a\Z')`},
		{name: "match absolute end anchor rejects trailing newline", expression: `match("a\n", ?'a\Z')`},
		{name: "string function", expression: `string(1)`},
		{name: "number function", expression: `number("0x10")`},
		{name: "number uppercase hex prefix", expression: `number("0X10")`},
		{name: "number base zero decimal", expression: `number("010", 0)`},
		{name: "number base zero hex string", expression: `number("0x10", 0)`},
		{name: "number null base", expression: `number("10", null)`},
		{name: "number invalid string", expression: `number("bad")`},
		{name: "number base seven", expression: `number("52403", 7)`},
		{name: "concat function", expression: `concat("a", "||", 1, "||", true)`},
		{name: "indexOf null start", expression: `indexOf("foobarbaz", "o", null)`},
		{name: "indexOf missing substring", expression: `indexOf("foobarbaz", "L")`},
		{name: "substring null start", expression: `substring("hello world", null, 5)`},
		{name: "substring null end", expression: `substring("hello world", 6, null)`},
		{name: "between function", expression: `between("System Idle Process", "s", "e")`},
		{name: "between case-sensitive", expression: `between("System Idle Process", "s", "e")`, caseSensitive: true},
		{name: "between missing right", expression: `between("welcome to the planet", "welcome", "village")`},
		{name: "divide by zero function", expression: `divide(7, 0)`},
		{name: "method length complex arithmetic", expression: `(100 * 10) - ("hello":length())`},
		{name: "method length nested concat", expression: `concat((100 * 10) - ("hello":length()) == 995, "...")`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpression(context.Background(), pythonRepo, tc.expression, tc.caseSensitive)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() {
				t.Fatalf(
					"expression mismatch for %q\npython runtime=%s folded=%s\ngo     runtime=%s folded=%s",
					tc.expression,
					result.Python.Runtime,
					result.Python.Folded,
					result.Go.Runtime,
					result.Go.Folded,
				)
			}
		})
	}
}

func foldingPythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
