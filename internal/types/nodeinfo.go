package types

import (
	"reflect"

	"github.com/Rakivili/eql-go/internal/ast"
)

// Expectation is a union of acceptable type and literal constraints.
type Expectation struct {
	alternatives []constraint
}

type constraint struct {
	typeInfo       TypeHint
	nullable       bool
	hasFoldCheck   bool
	requireLiteral bool
}

// Expect creates a union expectation from one or more type hints.
func Expect(hints ...TypeHint) Expectation {
	out := Expectation{alternatives: make([]constraint, 0, len(hints))}
	for _, hint := range hints {
		out.alternatives = append(out.alternatives, constraint{
			typeInfo: hint.Normalize(),
			nullable: true,
		})
	}
	return out
}

// ExpectFold creates an expectation from a type fold check.
func ExpectFold(check TypeFoldCheck) Expectation {
	check = check.Normalize()
	return Expectation{alternatives: []constraint{{
		typeInfo:       check.TypeInfo,
		nullable:       true,
		hasFoldCheck:   true,
		requireLiteral: check.RequireLiteral,
	}}}
}

// ExpectNode creates an expectation from another node's type information.
func ExpectNode(info NodeInfo) Expectation {
	return Expectation{alternatives: []constraint{{
		typeInfo: info.Type(),
		nullable: info.IsNullable(),
	}}}
}

// AnyOf returns the union of multiple expectations.
func AnyOf(expectations ...Expectation) Expectation {
	total := 0
	for _, expectation := range expectations {
		total += len(expectation.alternatives)
	}
	out := Expectation{alternatives: make([]constraint, 0, total)}
	for _, expectation := range expectations {
		out.alternatives = append(out.alternatives, expectation.alternatives...)
	}
	return out
}

// Empty reports whether the expectation has no acceptable alternatives.
func (e Expectation) Empty() bool {
	return len(e.alternatives) == 0
}

// NodeInfo holds type and schema information for an expression.
type NodeInfo struct {
	Node           ast.Expr
	TypeInfo       TypeHint
	Nullable       bool
	Schema         any
	Source         any
	Literal        bool
	FoldsToLiteral bool
}

// NodeOption configures NodeInfo construction.
type NodeOption func(*NodeInfo)

// NewNodeInfo creates NodeInfo with Python-compatible nullable defaults.
func NewNodeInfo(node ast.Expr, typeInfo TypeHint, opts ...NodeOption) NodeInfo {
	info := NodeInfo{
		Node:     node,
		TypeInfo: typeInfo.Normalize(),
		Nullable: true,
	}
	if _, ok := node.(*ast.Literal); ok {
		info.Literal = true
		info.FoldsToLiteral = true
	}
	for _, opt := range opts {
		opt(&info)
	}
	if info.Type() == TypeNull || info.Type() == TypeUnknown {
		info.Nullable = true
	}
	return info
}

// WithNullable sets whether non-null, known values may be compared to null.
func WithNullable(nullable bool) NodeOption {
	return func(info *NodeInfo) {
		info.Nullable = nullable
	}
}

// WithSchema attaches composite schema information.
func WithSchema(schema any) NodeOption {
	return func(info *NodeInfo) {
		info.Schema = schema
	}
}

// WithSource attaches parse-source metadata.
func WithSource(source any) NodeOption {
	return func(info *NodeInfo) {
		info.Source = source
	}
}

// WithLiteralState overrides literal and folded-literal state.
func WithLiteralState(literal bool, foldsToLiteral bool) NodeOption {
	return func(info *NodeInfo) {
		info.Literal = literal
		info.FoldsToLiteral = foldsToLiteral
	}
}

// Type returns TypeUnknown for the zero-value type hint.
func (n NodeInfo) Type() TypeHint {
	return n.TypeInfo.Normalize()
}

// IsNullable reports whether this node may match TypeNull.
func (n NodeInfo) IsNullable() bool {
	switch n.Type() {
	case TypeNull, TypeUnknown:
		return true
	default:
		return n.Nullable
	}
}

// Validate checks both type compatibility and literal/dynamic requirements.
func (n NodeInfo) Validate(expected Expectation) bool {
	for _, alternative := range expected.alternatives {
		if n.validateType(alternative) && n.validateLiteral(alternative) {
			return true
		}
	}
	return false
}

// ValidateType checks only type compatibility.
func (n NodeInfo) ValidateType(expected Expectation) bool {
	for _, alternative := range expected.alternatives {
		if n.validateType(alternative) {
			return true
		}
	}
	return false
}

// ValidateLiteral checks only literal/dynamic requirements.
func (n NodeInfo) ValidateLiteral(expected Expectation) bool {
	if expected.Empty() {
		return true
	}
	for _, alternative := range expected.alternatives {
		if n.validateLiteral(alternative) {
			return true
		}
	}
	return false
}

func (n NodeInfo) validateType(expected constraint) bool {
	selfType := n.Type()
	otherType := expected.typeInfo.Normalize()
	if selfType == TypeNull {
		return expected.nullable
	}
	if otherType == TypeNull {
		return n.IsNullable()
	}
	return selfType == otherType || selfType == TypeUnknown || otherType == TypeUnknown
}

func (n NodeInfo) validateLiteral(expected constraint) bool {
	if !expected.hasFoldCheck {
		return true
	}
	if expected.requireLiteral {
		return n.Literal
	}
	return !n.FoldsToLiteral
}

// Equal reports whether two NodeInfo values contain equal public data.
func (n NodeInfo) Equal(other NodeInfo) bool {
	return reflect.DeepEqual(n.Node, other.Node) &&
		n.Type() == other.Type() &&
		n.IsNullable() == other.IsNullable() &&
		reflect.DeepEqual(n.Schema, other.Schema) &&
		reflect.DeepEqual(n.Source, other.Source) &&
		n.Literal == other.Literal &&
		n.FoldsToLiteral == other.FoldsToLiteral
}
