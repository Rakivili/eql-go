package types

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Rakivili/eql-go/internal/ast"
)

func TestTypeHintValuesAndPrimitives(t *testing.T) {
	if TypeUnknown.String() != "mixed" {
		t.Fatalf("unknown type string=%q", TypeUnknown.String())
	}
	if TypeHint("").Normalize() != TypeUnknown {
		t.Fatalf("zero-value type should normalize to unknown")
	}
	primitives := PrimitiveHints()
	want := []TypeHint{TypeBoolean, TypeNumeric, TypeNull, TypeString}
	if !equalHints(primitives, want) {
		t.Fatalf("PrimitiveHints()=%v, want %v", primitives, want)
	}
	for _, hint := range want {
		if !hint.IsPrimitive() {
			t.Fatalf("%s should be primitive", hint)
		}
	}
	if TypeArray.IsPrimitive() {
		t.Fatal("array should not be primitive")
	}
}

func TestTypeFoldChecks(t *testing.T) {
	dynamic := TypeUnknown.RequireDynamic().Expect()
	literal := TypeUnknown.RequireLiteral().Expect()
	either := TypeUnknown.Expect()

	dynamicNode := NewNodeInfo(&ast.Field{Base: "a"}, TypeNumeric)
	if !dynamicNode.ValidateLiteral(dynamic) {
		t.Fatal("field should satisfy dynamic requirement")
	}
	if dynamicNode.ValidateLiteral(literal) {
		t.Fatal("field should not satisfy literal requirement")
	}
	if !dynamicNode.ValidateLiteral(either) {
		t.Fatal("field should satisfy unconstrained requirement")
	}

	literalNode := NewNodeInfo(&ast.Literal{Kind: ast.LiteralNull}, TypeNumeric)
	if literalNode.ValidateLiteral(dynamic) {
		t.Fatal("literal should not satisfy dynamic requirement")
	}
	if !literalNode.ValidateLiteral(literal) {
		t.Fatal("literal should satisfy literal requirement")
	}
	if !literalNode.ValidateLiteral(either) {
		t.Fatal("literal should satisfy unconstrained requirement")
	}

	foldedNode := NewNodeInfo(
		&ast.FunctionCall{Name: "length", Args: []ast.Expr{&ast.Literal{Kind: ast.LiteralNull}}},
		TypeNumeric,
		WithLiteralState(false, true),
	)
	if foldedNode.ValidateLiteral(dynamic) {
		t.Fatal("folded expression should not satisfy dynamic requirement")
	}
	if foldedNode.ValidateLiteral(literal) {
		t.Fatal("folded expression should not satisfy literal requirement")
	}
	if !foldedNode.ValidateLiteral(either) {
		t.Fatal("folded expression should satisfy unconstrained requirement")
	}
}

func TestNodeInfoValidateType(t *testing.T) {
	cases := []struct {
		name     string
		node     NodeInfo
		expected Expectation
		want     bool
	}{
		{name: "string string", node: NewNodeInfo(nil, TypeString), expected: TypeString.Expect(), want: true},
		{name: "string boolean", node: NewNodeInfo(nil, TypeString), expected: TypeBoolean.Expect()},
		{name: "numeric string", node: NewNodeInfo(nil, TypeNumeric), expected: TypeString.Expect()},
		{name: "null numeric", node: NewNodeInfo(nil, TypeNull), expected: TypeNumeric.Expect(), want: true},
		{name: "string null", node: NewNodeInfo(nil, TypeString), expected: TypeNull.Expect(), want: true},
		{name: "null null", node: NewNodeInfo(nil, TypeNull), expected: TypeNull.Expect(), want: true},
		{name: "string numeric or null", node: NewNodeInfo(nil, TypeString), expected: Expect(TypeNumeric, TypeNull), want: true},
		{name: "string primitives", node: NewNodeInfo(nil, TypeString), expected: Expect(PrimitiveHints()...), want: true},
		{name: "unknown numeric", node: NewNodeInfo(nil, TypeUnknown), expected: TypeNumeric.Expect(), want: true},
		{name: "numeric unknown", node: NewNodeInfo(nil, TypeNumeric), expected: TypeUnknown.Expect(), want: true},
		{
			name:     "non-null string expected null",
			node:     NewNodeInfo(nil, TypeString, WithNullable(false)),
			expected: TypeNull.Expect(),
		},
		{
			name:     "null expected non-null node",
			node:     NewNodeInfo(nil, TypeNull),
			expected: ExpectNode(NewNodeInfo(nil, TypeString, WithNullable(false))),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.node.ValidateType(tc.expected); got != tc.want {
				t.Fatalf("ValidateType()=%v, want %v", got, tc.want)
			}
			if got := tc.node.Validate(tc.expected); got != tc.want {
				t.Fatalf("Validate()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestNodeInfoValidateTypePythonOracle(t *testing.T) {
	pythonRepo := typeSystemPythonRepo(t)
	type oracleCase struct {
		Left  TypeHint `json:"left"`
		Right TypeHint `json:"right"`
	}
	cases := []oracleCase{
		{Left: TypeString, Right: TypeString},
		{Left: TypeString, Right: TypeBoolean},
		{Left: TypeNumeric, Right: TypeString},
		{Left: TypeNull, Right: TypeNumeric},
		{Left: TypeString, Right: TypeNull},
		{Left: TypeNull, Right: TypeNull},
		{Left: TypeUnknown, Right: TypeNumeric},
		{Left: TypeNumeric, Right: TypeUnknown},
	}
	body, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	script := `
import json, sys
from eql.types import TypeHint, NodeInfo

cases = json.load(sys.stdin)
out = []
by_value = {hint.value: hint for hint in TypeHint}
for case in cases:
    left = by_value[case["left"]]
    right = by_value[case["right"]]
    out.append(NodeInfo(None, left).validate_type(right))
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(context.Background(), "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python type oracle: %v: %s", err, bytes.TrimSpace(out))
	}
	var python []bool
	if err := json.Unmarshal(bytes.TrimSpace(out), &python); err != nil {
		t.Fatal(err)
	}
	if len(python) != len(cases) {
		t.Fatalf("python returned %d rows, want %d", len(python), len(cases))
	}
	for i, tc := range cases {
		goValue := NewNodeInfo(nil, tc.Left).ValidateType(tc.Right.Expect())
		if goValue != python[i] {
			t.Fatalf("%s.ValidateType(%s): go=%v python=%v", tc.Left, tc.Right, goValue, python[i])
		}
	}
}

func TestNodeInfoEqual(t *testing.T) {
	left := NewNodeInfo(
		&ast.Field{Base: "a"},
		TypeString,
		WithNullable(false),
		WithSchema(map[string]any{"a": "string"}),
		WithSource("source"),
	)
	right := NewNodeInfo(
		&ast.Field{Base: "a"},
		TypeString,
		WithNullable(false),
		WithSchema(map[string]any{"a": "string"}),
		WithSource("source"),
	)
	if !left.Equal(right) {
		t.Fatal("equal node info should match")
	}
	if left.Equal(NewNodeInfo(&ast.Field{Base: "b"}, TypeString)) {
		t.Fatal("different node info should not match")
	}
}

func TestParseTypeHint(t *testing.T) {
	if got, ok := ParseTypeHint("number"); !ok || got != TypeNumeric {
		t.Fatalf("ParseTypeHint(number)=(%s,%v)", got, ok)
	}
	if got, ok := ParseTypeHint("bad"); ok || got != TypeUnknown {
		t.Fatalf("ParseTypeHint(bad)=(%s,%v)", got, ok)
	}
}

func equalHints(left []TypeHint, right []TypeHint) bool {
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

func typeSystemPythonRepo(t *testing.T) string {
	t.Helper()
	if repo := os.Getenv("EQL_PYTHON_REPO"); repo != "" {
		return repo
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "eql"))
}
