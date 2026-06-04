package ast

import (
	"encoding/json"
	"testing"
)

func TestParseNum(t *testing.T) {
	cases := []struct {
		text  string
		isInt bool
		value string
	}{
		{text: "10", isInt: true, value: "10"},
		{text: "-3", isInt: true, value: "-3"},
		{text: "10.5", value: "10.5"},
		{text: "1e3", value: "1000"},
	}
	for _, tc := range cases {
		got, err := ParseNum(tc.text)
		if err != nil {
			t.Fatalf("ParseNum(%q): %v", tc.text, err)
		}
		if got.IsInt != tc.isInt {
			t.Fatalf("ParseNum(%q) IsInt=%v", tc.text, got.IsInt)
		}
		if got.String() != tc.value {
			t.Fatalf("ParseNum(%q) String=%q", tc.text, got.String())
		}
	}
}

func TestParseNumError(t *testing.T) {
	if _, err := ParseNum("not-a-number"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNumMarshalJSON(t *testing.T) {
	body, err := json.Marshal(map[string]Num{"pid": Int(10)})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"pid":10}` {
		t.Fatalf("unexpected json %s", body)
	}
}

func TestNumHelpers(t *testing.T) {
	if Int(10).Float64() != 10 {
		t.Fatal("unexpected int Float64")
	}
	if Float(1.5).Float64() != 1.5 {
		t.Fatal("unexpected float Float64")
	}
	if !Int(0).IsZero() {
		t.Fatal("expected int zero")
	}
	if !Float(0).IsZero() {
		t.Fatal("expected float zero")
	}
	if Int(1).IsZero() || Float(1).IsZero() {
		t.Fatal("non-zero numbers should not report zero")
	}
}

func TestExprKind(t *testing.T) {
	cases := []struct {
		expr Expr
		want string
	}{
		{expr: &Comparison{}, want: "boolean"},
		{expr: &IsNull{}, want: "boolean"},
		{expr: &IsNotNull{}, want: "boolean"},
		{expr: &InSet{}, want: "boolean"},
		{expr: &Logical{}, want: "boolean"},
		{expr: &Not{}, want: "boolean"},
		{expr: &Literal{Kind: LiteralBool}, want: "boolean"},
		{expr: &Literal{Kind: LiteralNull}, want: "null"},
		{expr: &Literal{Kind: LiteralNumber}, want: "number"},
		{expr: &Literal{Kind: LiteralString}, want: "string"},
		{expr: &Field{}, want: "unknown"},
		{expr: &FunctionCall{}, want: "unknown"},
		{expr: &MathOperation{}, want: "number"},
	}
	for _, tc := range cases {
		if got := ExprKind(tc.expr); got != tc.want {
			t.Fatalf("ExprKind(%T)=%q, want %q", tc.expr, got, tc.want)
		}
	}
	if got := ExprKind(nil); got == "" {
		t.Fatal("nil expression should still return a diagnostic kind")
	}
	(&Literal{}).exprNode()
	(&Field{}).exprNode()
	(&FunctionCall{}).exprNode()
	(&MathOperation{}).exprNode()
	(&Comparison{}).exprNode()
	(&IsNull{}).exprNode()
	(&IsNotNull{}).exprNode()
	(&InSet{}).exprNode()
	(&Logical{}).exprNode()
	(&Not{}).exprNode()
}
