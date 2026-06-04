package conformance

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	conf "github.com/Rakivili/eql-go/internal/conformance"
)

func TestOptimizerWildcardEquivalentOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases := []struct {
		name       string
		expression string
		alternate  string
	}{
		{name: "right pattern equality", expression: `field == "a*b*c"`, alternate: `wildcard(field, "a*b*c")`},
		{name: "right pattern inequality", expression: `field != "a*b*c"`, alternate: `not wildcard(field, "a*b*c")`},
		{name: "left pattern equality", expression: `"a*b" == field`, alternate: `wildcard(field, "a*b")`},
		{name: "left pattern inequality", expression: `"a*b" != field`, alternate: `not wildcard(field, "a*b")`},
		{name: "left pattern function source", expression: `"a*b" == concat(field, "foo")`, alternate: `wildcard(concat(field, "foo"), "a*b")`},
		{name: "left pattern function source inequality", expression: `"a*b" != concat(field, "foo")`, alternate: `not wildcard(concat(field, "foo"), "a*b")`},
		{name: "right pattern function source", expression: `concat(field, "hello", "world") == "foo*bar"`, alternate: `wildcard(concat(field, "hello", "world"), "foo*bar")`},
		{name: "right pattern function source inequality", expression: `concat(field, "hello", "world") != "foo*bar"`, alternate: `not wildcard(concat(field, "hello", "world"), "foo*bar")`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpressionEquivalent(context.Background(), pythonRepo, tc.expression, tc.alternate)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() || !result.Python {
				t.Fatalf(
					"equivalence mismatch for %q\nalternate %q\npython=%v go=%v",
					tc.expression,
					tc.alternate,
					result.Python,
					result.Go,
				)
			}
		})
	}
}

func TestOptimizerBooleanRewriteOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases := []struct {
		name       string
		expression string
		optimized  string
	}{
		{name: "or right true", expression: `a == 1 or true`, optimized: `true`},
		{name: "or left true", expression: `true or a == 1`, optimized: `true`},
		{name: "or left false", expression: `false or a == 1`, optimized: `a == 1`},
		{name: "or right false", expression: `a == 1 or false`, optimized: `a == 1`},
		{name: "or contains true", expression: `a or b or true or c`, optimized: `true`},
		{name: "or removes false", expression: `a or b or false or c`, optimized: `a or b or c`},
		{name: "and right true", expression: `a == 1 and true`, optimized: `a == 1`},
		{name: "and left true", expression: `true and a == 1`, optimized: `a == 1`},
		{name: "and left false", expression: `false and a == 1`, optimized: `false`},
		{name: "and right false", expression: `a == 1 and false`, optimized: `false`},
		{name: "and contains false", expression: `a and b and false and c`, optimized: `false`},
		{name: "and removes true", expression: `a and b and true and c`, optimized: `a and b and c`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpressionOptimized(context.Background(), pythonRepo, tc.expression, tc.optimized)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() || !result.Python {
				t.Fatalf(
					"optimizer mismatch for %q\noptimized %q\npython=%v go=%v",
					tc.expression,
					tc.optimized,
					result.Python,
					result.Go,
				)
			}
		})
	}
}

func TestOptimizerInSetRewriteOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases := []struct {
		name       string
		expression string
		optimized  string
	}{
		{name: "single literal", expression: `pid in (4)`, optimized: `pid == 4`},
		{name: "negated single literal", expression: `pid not in (4)`, optimized: `pid != 4`},
		{name: "single dynamic self", expression: `pid in (pid)`, optimized: `true`},
		{name: "negated single dynamic self", expression: `pid not in (pid)`, optimized: `false`},
		{
			name:       "literal source drops missed literals",
			expression: `"something" in ("str", "str2", "str3", "str4", someField)`,
			optimized:  `"something" == someField`,
		},
		{
			name:       "literal source keeps dynamic candidates",
			expression: `"something" in ("str", "str2", "str3", "str4", field1, field2)`,
			optimized:  `"something" in (field1, field2)`,
		},
		{
			name:       "literal de-duplication",
			expression: `fieldname in ("a", "b", "C", "d", 1, "d", "D", "c")`,
			optimized:  `fieldname in ("a", "b", "C", "d", 1)`,
		},
		{
			name:       "dynamic self candidate",
			expression: `fieldA in ("a", "b", "C", "d", fieldA, fieldB, fieldC)`,
			optimized:  `true`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpressionOptimized(context.Background(), pythonRepo, tc.expression, tc.optimized)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() || !result.Python {
				t.Fatalf(
					"optimizer mismatch for %q\noptimized %q\npython=%v go=%v",
					tc.expression,
					tc.optimized,
					result.Python,
					result.Go,
				)
			}
		})
	}
}

func TestOptimizerInSetLogicalMergeOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases := []struct {
		name       string
		expression string
		optimized  string
	}{
		{
			name:       "set intersection",
			expression: `fieldname in ("a", "b", "C", "x") and fieldname in ("d", "c", "g", "X")`,
			optimized:  `fieldname in ("C", "x")`,
		},
		{
			name:       "empty set intersection",
			expression: `fieldname in ("a", "b", "C", "x") and fieldname in ("d", "f", "g", 123)`,
			optimized:  `false`,
		},
		{
			name:       "set union",
			expression: `fieldname in ("a", "b", "C", "x") or fieldname in ("d", "c", "g", "X")`,
			optimized:  `fieldname in ("a", "b", "C", "x", "d", "g")`,
		},
		{
			name:       "set subtraction",
			expression: `NAME in ("a", "b", "c", "d") and not NAME in ("b", "d")`,
			optimized:  `NAME in ("a", "c")`,
		},
		{
			name:       "and merge at tail",
			expression: `opcode == 1 and name in ("a", "b", "c", "d") and name in ("b", "d")`,
			optimized:  `opcode == 1 and name in ("b", "d")`,
		},
		{
			name:       "and merge in middle",
			expression: `opcode == 1 and name in ("a", "b", "c", "d") and name in ("b", "d") and x == 1`,
			optimized:  `opcode == 1 and name in ("b", "d") and x == 1`,
		},
		{
			name:       "or merge at tail",
			expression: `opcode == 1 or name in ("a", "b", "c", "d") or name in ("e", "f")`,
			optimized:  `opcode == 1 or name in ("a", "b", "c", "d", "e", "f")`,
		},
		{
			name:       "or merge in middle",
			expression: `opcode == 1 or name in ("a", "b", "c", "d") or name in ("e", "f") or x == 1`,
			optimized:  `opcode == 1 or name in ("a", "b", "c", "d", "e", "f") or x == 1`,
		},
		{
			name:       "comparison chain to set",
			expression: `pid == 4 or pid == 8 or pid == 520`,
			optimized:  `pid in (4, 8, 520)`,
		},
		{
			name:       "set or comparison",
			expression: `name in ("a", "b") or name == "c"`,
			optimized:  `name in ("a", "b", "c")`,
		},
		{
			name:       "set and missing comparison",
			expression: `name in ("a", "b") and name == "c"`,
			optimized:  `false`,
		},
		{
			name:       "set and matching comparison",
			expression: `name in ("a", "b") and name == "b"`,
			optimized:  `name == "b"`,
		},
		{
			name:       "comparison or set",
			expression: `name == "c" or name in ("a", "b")`,
			optimized:  `name in ("c", "a", "b")`,
		},
		{
			name:       "comparison and missing set",
			expression: `name == "c" and name in ("a", "b")`,
			optimized:  `false`,
		},
		{
			name:       "comparison and matching set",
			expression: `name == "b" and name in ("a", "b")`,
			optimized:  `name == "b"`,
		},
		{
			name:       "set and inequality subtraction",
			expression: `name in ("a", "b", "c") and name != "c"`,
			optimized:  `name in ("a", "b")`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpressionOptimized(context.Background(), pythonRepo, tc.expression, tc.optimized)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() || !result.Python {
				t.Fatalf(
					"optimizer mismatch for %q\noptimized %q\npython=%v go=%v",
					tc.expression,
					tc.optimized,
					result.Python,
					result.Go,
				)
			}
		})
	}
}

func TestOptimizerVariadicFunctionOrMergeOracle(t *testing.T) {
	pythonRepo := optimizerPythonRepo(t)
	cases := []struct {
		name       string
		expression string
		optimized  string
	}{
		{
			name:       "wildcard comparisons",
			expression: `name == "foo*" or name == "*bar"`,
			optimized:  `wildcard(name, "foo*", "*bar")`,
		},
		{
			name:       "match calls",
			expression: `match(name, "fo[o]") or match(name, "ba[r]?")`,
			optimized:  `match(name, "fo[o]", "ba[r]?")`,
		},
		{
			name:       "matchLite calls",
			expression: `matchLite(name, "fo[o]") or matchLite(name, "ba[r]?")`,
			optimized:  `matchLite(name, "fo[o]", "ba[r]?")`,
		},
		{
			name:       "nonadjacent wildcard calls",
			expression: `name == "foo*" or other_field == "bar" or name == "*baz"`,
			optimized:  `wildcard(name, "foo*") or other_field == "bar" or wildcard(name, "*baz")`,
		},
		{
			name:       "different wildcard sources",
			expression: `name == "foo*" or title == "*bar"`,
			optimized:  `wildcard(name, "foo*") or wildcard(title, "*bar")`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conf.CompareExpressionOptimized(context.Background(), pythonRepo, tc.expression, tc.optimized)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Equal() || !result.Python {
				t.Fatalf(
					"optimizer mismatch for %q\noptimized %q\npython=%v go=%v",
					tc.expression,
					tc.optimized,
					result.Python,
					result.Go,
				)
			}
		})
	}
}

func optimizerPythonRepo(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "eql"))
}
