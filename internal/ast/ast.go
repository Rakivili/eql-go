package ast

import (
	"fmt"
	"strconv"
	"strings"
)

// Expr is the internal marker interface for query expressions.
type Expr interface {
	exprNode()
}

// Query is the internal representation of one parsed query.
type Query struct {
	EventType  string
	Expr       Expr
	Sequence   []EventQuery
	SequenceBy []Expr
	MaxSpan    int64
	HasMaxSpan bool
	// SequenceUntil is an optional close query for classic sequence state.
	SequenceUntil *EventQuery
	Sample        []EventQuery
	SampleBy      []Expr
	Join          []EventQuery
	JoinBy        []Expr
	JoinUntil     *EventQuery
	Pipes         []Pipe
}

// EventQuery is one event filter in a single-event query or sequence stage.
type EventQuery struct {
	EventType string
	Expr      Expr
	By        []Expr
	Fork      bool
	HasFork   bool
	Negated   bool
	Alias     string
}

// Pipe is an internal pipe command applied after a base query match.
type Pipe struct {
	Name string
	Args []Expr
}

// Num preserves whether a parsed numeric literal was integral or floating point.
type Num struct {
	I     int64
	F     float64
	IsInt bool
}

// Int creates an integral numeric literal.
func Int(v int64) Num {
	return Num{I: v, F: float64(v), IsInt: true}
}

// Float creates a floating-point numeric literal.
func Float(v float64) Num {
	return Num{F: v}
}

// ParseNum parses an EQL numeric literal.
func ParseNum(s string) (Num, error) {
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return Num{}, err
		}
		return Float(f), nil
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return Num{}, err
	}
	return Int(i), nil
}

// Float64 returns the numeric value as a float64 for comparison.
func (n Num) Float64() float64 {
	if n.IsInt {
		return float64(n.I)
	}
	return n.F
}

// IsZero reports whether the numeric value is zero.
func (n Num) IsZero() bool {
	if n.IsInt {
		return n.I == 0
	}
	return n.F == 0
}

// String renders the number using JSON-compatible formatting.
func (n Num) String() string {
	if n.IsInt {
		return strconv.FormatInt(n.I, 10)
	}
	return strconv.FormatFloat(n.F, 'g', -1, 64)
}

// MarshalJSON renders the number without wrapping it as an object.
func (n Num) MarshalJSON() ([]byte, error) {
	return []byte(n.String()), nil
}

// LiteralKind identifies the type of a literal expression.
type LiteralKind int

const (
	// LiteralNull represents the EQL null literal.
	LiteralNull LiteralKind = iota
	// LiteralBool represents a boolean literal.
	LiteralBool
	// LiteralString represents a string literal.
	LiteralString
	// LiteralNumber represents a numeric literal.
	LiteralNumber
)

// Literal is an internal literal expression node.
type Literal struct {
	Kind  LiteralKind
	Value any
}

func (*Literal) exprNode() {}

// Field is an internal field-access expression node.
type Field struct {
	Base     string
	Path     []PathPart
	Optional bool
	Scoped   bool
}

func (*Field) exprNode() {}

// FunctionCall is an internal function-call expression node.
type FunctionCall struct {
	Name string
	Args []Expr
}

func (*FunctionCall) exprNode() {}

// NamedSubquery is an internal named relationship expression node.
type NamedSubquery struct {
	QueryType string
	Query     EventQuery
}

func (*NamedSubquery) exprNode() {}

// MathOperation is an internal numeric binary operation expression node.
type MathOperation struct {
	Left  Expr
	Op    string
	Right Expr
}

func (*MathOperation) exprNode() {}

// PathPart is one dotted or indexed segment of a field path.
type PathPart struct {
	Name  string
	Index int
	IsIdx bool
}

// Comparison is an internal binary comparison expression node.
type Comparison struct {
	Left  Expr
	Op    string
	Right Expr
}

func (*Comparison) exprNode() {}

// IsNull is an internal null-test expression node.
type IsNull struct {
	Expr Expr
}

func (*IsNull) exprNode() {}

// IsNotNull is an internal non-null-test expression node.
type IsNotNull struct {
	Expr Expr
}

func (*IsNotNull) exprNode() {}

// InSet is an internal set-membership expression node.
type InSet struct {
	Expr   Expr
	Values []Expr
}

func (*InSet) exprNode() {}

// Logical is an internal and/or expression node.
type Logical struct {
	Op    string
	Terms []Expr
}

func (*Logical) exprNode() {}

// Not is an internal negation expression node.
type Not struct {
	Term Expr
}

func (*Not) exprNode() {}

// ExprKind returns a coarse type name used in parse errors.
func ExprKind(e Expr) string {
	switch e.(type) {
	case *Comparison, *IsNull, *IsNotNull, *InSet, *Logical, *Not, *NamedSubquery:
		return "boolean"
	case *MathOperation:
		return "number"
	case *FunctionCall:
		return "unknown"
	case *Literal:
		l := e.(*Literal)
		switch l.Kind {
		case LiteralBool:
			return "boolean"
		case LiteralNull:
			return "null"
		case LiteralNumber:
			return "number"
		case LiteralString:
			return "string"
		default:
			return "unknown"
		}
	case *Field:
		return "unknown"
	default:
		return fmt.Sprintf("%T", e)
	}
}
