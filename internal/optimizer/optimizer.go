package optimizer

import (
	"math"
	"reflect"
	"strings"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/engine"
	"github.com/Rakivili/eql-go/internal/pycompat"
	"github.com/Rakivili/eql-go/internal/validator"
)

// Options configures expression optimization semantics.
type Options struct {
	CaseInsensitive     bool
	ElasticsearchSyntax bool
}

// OptimizeQuery returns a semantically equivalent query with simple constant
// expressions folded.
func OptimizeQuery(q *ast.Query, opts Options) *ast.Query {
	if q == nil {
		return nil
	}
	out := *q
	if len(q.Sequence) > 0 {
		out.Sequence = make([]ast.EventQuery, 0, len(q.Sequence))
		for _, part := range q.Sequence {
			next := ast.EventQuery{
				EventType: part.EventType,
				Expr:      OptimizeExpr(part.Expr, opts),
				Fork:      part.Fork,
				HasFork:   part.HasFork,
				Negated:   part.Negated,
				Alias:     part.Alias,
			}
			next.By = make([]ast.Expr, 0, len(part.By))
			for _, expr := range part.By {
				next.By = append(next.By, OptimizeExpr(expr, opts))
			}
			out.Sequence = append(out.Sequence, next)
		}
		out.SequenceBy = make([]ast.Expr, 0, len(q.SequenceBy))
		for _, expr := range q.SequenceBy {
			out.SequenceBy = append(out.SequenceBy, OptimizeExpr(expr, opts))
		}
		if q.SequenceUntil != nil {
			next := ast.EventQuery{
				EventType: q.SequenceUntil.EventType,
				Expr:      OptimizeExpr(q.SequenceUntil.Expr, opts),
				Fork:      q.SequenceUntil.Fork,
				HasFork:   q.SequenceUntil.HasFork,
				Negated:   q.SequenceUntil.Negated,
				Alias:     q.SequenceUntil.Alias,
			}
			next.By = make([]ast.Expr, 0, len(q.SequenceUntil.By))
			for _, expr := range q.SequenceUntil.By {
				next.By = append(next.By, OptimizeExpr(expr, opts))
			}
			out.SequenceUntil = &next
		}
	} else if len(q.Sample) > 0 {
		out.Sample = make([]ast.EventQuery, 0, len(q.Sample))
		for _, part := range q.Sample {
			next := ast.EventQuery{
				EventType: part.EventType,
				Expr:      OptimizeExpr(part.Expr, opts),
				Fork:      part.Fork,
				HasFork:   part.HasFork,
				Negated:   part.Negated,
				Alias:     part.Alias,
			}
			next.By = make([]ast.Expr, 0, len(part.By))
			for _, expr := range part.By {
				next.By = append(next.By, OptimizeExpr(expr, opts))
			}
			out.Sample = append(out.Sample, next)
		}
		out.SampleBy = make([]ast.Expr, 0, len(q.SampleBy))
		for _, expr := range q.SampleBy {
			out.SampleBy = append(out.SampleBy, OptimizeExpr(expr, opts))
		}
	} else if len(q.Join) > 0 {
		out.Join = make([]ast.EventQuery, 0, len(q.Join))
		for _, part := range q.Join {
			next := ast.EventQuery{
				EventType: part.EventType,
				Expr:      OptimizeExpr(part.Expr, opts),
				Fork:      part.Fork,
				HasFork:   part.HasFork,
				Negated:   part.Negated,
				Alias:     part.Alias,
			}
			next.By = make([]ast.Expr, 0, len(part.By))
			for _, expr := range part.By {
				next.By = append(next.By, OptimizeExpr(expr, opts))
			}
			out.Join = append(out.Join, next)
		}
		out.JoinBy = make([]ast.Expr, 0, len(q.JoinBy))
		for _, expr := range q.JoinBy {
			out.JoinBy = append(out.JoinBy, OptimizeExpr(expr, opts))
		}
		if q.JoinUntil != nil {
			next := ast.EventQuery{
				EventType: q.JoinUntil.EventType,
				Expr:      OptimizeExpr(q.JoinUntil.Expr, opts),
				Fork:      q.JoinUntil.Fork,
				HasFork:   q.JoinUntil.HasFork,
				Negated:   q.JoinUntil.Negated,
				Alias:     q.JoinUntil.Alias,
			}
			next.By = make([]ast.Expr, 0, len(q.JoinUntil.By))
			for _, expr := range q.JoinUntil.By {
				next.By = append(next.By, OptimizeExpr(expr, opts))
			}
			out.JoinUntil = &next
		}
	} else {
		out.Expr = OptimizeExpr(q.Expr, opts)
	}
	out.Pipes = make([]ast.Pipe, 0, len(q.Pipes))
	for _, pipe := range q.Pipes {
		next := ast.Pipe{Name: pipe.Name, Args: make([]ast.Expr, 0, len(pipe.Args))}
		for _, arg := range pipe.Args {
			next.Args = append(next.Args, OptimizeExpr(arg, opts))
		}
		out.Pipes = append(out.Pipes, next)
	}
	return &out
}

// OptimizeExpr folds literal-only subexpressions and simplifies boolean logic.
func OptimizeExpr(expr ast.Expr, opts Options) ast.Expr {
	switch n := expr.(type) {
	case *ast.Logical:
		return optimizeLogical(n, opts)
	case *ast.Not:
		return optimizeNot(n, opts)
	case *ast.Comparison:
		return optimizeComparison(n, opts)
	case *ast.IsNull:
		return optimizeIsNull(n, opts)
	case *ast.IsNotNull:
		return optimizeIsNotNull(n, opts)
	case *ast.MathOperation:
		return optimizeMath(n, opts)
	case *ast.InSet:
		return optimizeInSet(n, opts)
	case *ast.FunctionCall:
		args := make([]ast.Expr, 0, len(n.Args))
		allLiteral := true
		for _, arg := range n.Args {
			optimized := OptimizeExpr(arg, opts)
			args = append(args, optimized)
			if _, ok := optimized.(*ast.Literal); !ok {
				allLiteral = false
			}
		}
		call := &ast.FunctionCall{Name: n.Name, Args: args}
		if allLiteral && foldableFunction(call.Name) {
			if lit, ok := foldFunctionCall(call, opts); ok {
				return lit
			}
		}
		return call
	case *ast.NamedSubquery:
		next := *n
		next.Query.Expr = OptimizeExpr(n.Query.Expr, opts)
		return &next
	default:
		return expr
	}
}

func optimizeLogical(n *ast.Logical, opts Options) ast.Expr {
	terms := make([]ast.Expr, 0, len(n.Terms))
	for _, term := range n.Terms {
		optimized := OptimizeExpr(term, opts)
		if nested, ok := optimized.(*ast.Logical); ok && nested.Op == n.Op {
			terms = append(terms, nested.Terms...)
			continue
		}
		terms = append(terms, optimized)
	}
	terms = mergeLogicalTerms(n.Op, terms, opts)

	switch n.Op {
	case "and":
		out := make([]ast.Expr, 0, len(terms))
		for _, term := range terms {
			if isBoolLiteral(term, false) {
				return boolLiteral(false)
			}
			if isBoolLiteral(term, true) {
				continue
			}
			out = append(out, term)
		}
		if allNullLiterals(out) {
			return nullLiteral()
		}
		return logicalOrSingle("and", out, boolLiteral(true))
	case "or":
		out := make([]ast.Expr, 0, len(terms))
		for _, term := range terms {
			if isBoolLiteral(term, true) {
				return boolLiteral(true)
			}
			if isBoolLiteral(term, false) {
				continue
			}
			out = append(out, term)
		}
		if allNullLiterals(out) {
			return nullLiteral()
		}
		return logicalOrSingle("or", out, boolLiteral(false))
	default:
		return &ast.Logical{Op: n.Op, Terms: terms}
	}
}

func mergeLogicalTerms(op string, terms []ast.Expr, opts Options) []ast.Expr {
	if len(terms) < 2 {
		return terms
	}
	out := make([]ast.Expr, 0, len(terms))
	current := terms[0]
	for _, term := range terms[1:] {
		if merged, ok := mergeLogicalPair(op, current, term, opts); ok {
			current = merged
			continue
		}
		out = append(out, current)
		current = term
	}
	out = append(out, current)
	return out
}

func mergeLogicalPair(op string, left ast.Expr, right ast.Expr, opts Options) (ast.Expr, bool) {
	switch op {
	case "and":
		return mergeAndPair(left, right, opts)
	case "or":
		return mergeOrPair(left, right, opts)
	default:
		return nil, false
	}
}

func mergeAndPair(left ast.Expr, right ast.Expr, opts Options) (ast.Expr, bool) {
	if leftSet, ok := left.(*ast.InSet); ok {
		if rightSet, ok := right.(*ast.InSet); ok {
			return mergeInSetIntersection(leftSet, rightSet, opts)
		}
		if rightSet, ok := negatedInSet(right); ok {
			return mergeInSetSubtraction(leftSet, rightSet, opts)
		}
		if cmp, ok := right.(*ast.Comparison); ok {
			switch cmp.Op {
			case "==":
				if singleton, ok := singletonInSet(cmp); ok {
					return mergeInSetIntersection(leftSet, singleton, opts)
				}
			case "!=":
				if singleton, ok := singletonInSet(cmp); ok {
					return mergeInSetSubtraction(leftSet, singleton, opts)
				}
			}
		}
	}
	if cmp, ok := left.(*ast.Comparison); ok && cmp.Op == "==" {
		if singleton, ok := singletonInSet(cmp); ok {
			if rightSet, ok := right.(*ast.InSet); ok {
				return mergeInSetIntersection(singleton, rightSet, opts)
			}
		}
	}
	return nil, false
}

func mergeOrPair(left ast.Expr, right ast.Expr, opts Options) (ast.Expr, bool) {
	if merged, ok := mergeVariadicFunctionOr(left, right); ok {
		return merged, true
	}
	if leftSet, ok := left.(*ast.InSet); ok {
		if rightSet, ok := right.(*ast.InSet); ok {
			return mergeInSetUnion(leftSet, rightSet, opts)
		}
		if cmp, ok := right.(*ast.Comparison); ok && cmp.Op == "==" {
			if singleton, ok := singletonInSet(cmp); ok {
				return mergeInSetUnion(leftSet, singleton, opts)
			}
		}
	}
	if cmp, ok := left.(*ast.Comparison); ok && cmp.Op == "==" {
		if singleton, ok := singletonInSet(cmp); ok {
			if rightCmp, ok := right.(*ast.Comparison); ok && rightCmp.Op == "==" {
				if rightSingleton, ok := singletonInSet(rightCmp); ok {
					return mergeInSetUnion(singleton, rightSingleton, opts)
				}
			}
			if rightSet, ok := right.(*ast.InSet); ok {
				return mergeInSetUnion(singleton, rightSet, opts)
			}
		}
	}
	return nil, false
}

func mergeVariadicFunctionOr(left ast.Expr, right ast.Expr) (ast.Expr, bool) {
	leftCall, ok := left.(*ast.FunctionCall)
	if !ok || !mergeableVariadicFunction(leftCall.Name) || len(leftCall.Args) == 0 {
		return nil, false
	}
	rightCall, ok := right.(*ast.FunctionCall)
	if !ok || rightCall.Name != leftCall.Name || len(rightCall.Args) == 0 {
		return nil, false
	}
	if !reflect.DeepEqual(leftCall.Args[0], rightCall.Args[0]) {
		return nil, false
	}
	args := make([]ast.Expr, 0, len(leftCall.Args)+len(rightCall.Args)-1)
	args = append(args, leftCall.Args...)
	args = append(args, rightCall.Args[1:]...)
	return &ast.FunctionCall{Name: leftCall.Name, Args: args}, true
}

func mergeableVariadicFunction(name string) bool {
	switch name {
	case "wildcard", "match", "matchLite":
		return true
	default:
		return false
	}
}

func logicalOrSingle(op string, terms []ast.Expr, empty ast.Expr) ast.Expr {
	switch len(terms) {
	case 0:
		return empty
	case 1:
		return terms[0]
	default:
		return &ast.Logical{Op: op, Terms: terms}
	}
}

func allNullLiterals(terms []ast.Expr) bool {
	if len(terms) == 0 {
		return false
	}
	for _, term := range terms {
		if !isNullLiteral(term) {
			return false
		}
	}
	return true
}

func optimizeNot(n *ast.Not, opts Options) ast.Expr {
	term := OptimizeExpr(n.Term, opts)
	if nested, ok := term.(*ast.Not); ok {
		return nested.Term
	}
	if lit, ok := term.(*ast.Literal); ok {
		switch lit.Kind {
		case ast.LiteralBool:
			return boolLiteral(lit.Value != true)
		case ast.LiteralNull:
			return nullLiteral()
		}
	}
	if cmp, ok := term.(*ast.Comparison); ok {
		if inverse, ok := invertedComparison(cmp.Op); ok {
			return &ast.Comparison{Left: cmp.Left, Op: inverse, Right: cmp.Right}
		}
	}
	if isNull, ok := term.(*ast.IsNull); ok {
		return &ast.IsNotNull{Expr: isNull.Expr}
	}
	if isNotNull, ok := term.(*ast.IsNotNull); ok {
		return &ast.IsNull{Expr: isNotNull.Expr}
	}
	return &ast.Not{Term: term}
}

func optimizeIsNull(n *ast.IsNull, opts Options) ast.Expr {
	expr := OptimizeExpr(n.Expr, opts)
	if lit, ok := expr.(*ast.Literal); ok {
		return boolLiteral(lit.Kind == ast.LiteralNull)
	}
	return &ast.IsNull{Expr: expr}
}

func optimizeIsNotNull(n *ast.IsNotNull, opts Options) ast.Expr {
	expr := OptimizeExpr(n.Expr, opts)
	if lit, ok := expr.(*ast.Literal); ok {
		return boolLiteral(lit.Kind != ast.LiteralNull)
	}
	return &ast.IsNotNull{Expr: expr}
}

func optimizeComparison(n *ast.Comparison, opts Options) ast.Expr {
	left := OptimizeExpr(n.Left, opts)
	right := OptimizeExpr(n.Right, opts)
	if !opts.ElasticsearchSyntax {
		if wildcard, ok := optimizeWildcardComparison(left, n.Op, right, opts); ok {
			return wildcard
		}
	}
	leftLit, leftOK := left.(*ast.Literal)
	rightLit, rightOK := right.(*ast.Literal)
	if leftOK && rightOK {
		return literalFromComparison(leftLit, rightLit, n.Op, opts)
	}
	if reflect.DeepEqual(left, right) {
		switch n.Op {
		case "==", "<=", ">=":
			return boolLiteral(true)
		case "!=", "<", ">":
			return boolLiteral(false)
		}
	}
	return &ast.Comparison{Left: left, Op: n.Op, Right: right}
}

func optimizeWildcardComparison(left ast.Expr, op string, right ast.Expr, opts Options) (ast.Expr, bool) {
	if op != "==" && op != "!=" {
		return nil, false
	}
	if pattern, ok := wildcardPatternLiteral(left); ok {
		return wildcardExpr(right, pattern, op, opts), true
	}
	if pattern, ok := wildcardPatternLiteral(right); ok {
		return wildcardExpr(left, pattern, op, opts), true
	}
	return nil, false
}

func wildcardPatternLiteral(expr ast.Expr) (*ast.Literal, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok || lit.Kind != ast.LiteralString {
		return nil, false
	}
	value, ok := lit.Value.(string)
	return lit, ok && strings.Contains(value, "*")
}

func wildcardExpr(source ast.Expr, pattern ast.Expr, op string, opts Options) ast.Expr {
	call := &ast.FunctionCall{Name: "wildcard", Args: []ast.Expr{source, pattern}}
	optimized := OptimizeExpr(call, opts)
	if op == "!=" {
		return optimizeNot(&ast.Not{Term: optimized}, opts)
	}
	return optimized
}

func optimizeMath(n *ast.MathOperation, opts Options) ast.Expr {
	left := OptimizeExpr(n.Left, opts)
	right := OptimizeExpr(n.Right, opts)
	leftLit, leftOK := numberLiteral(left)
	rightLit, rightOK := numberLiteral(right)
	if leftOK && rightOK {
		if value, ok := evalMath(leftLit, rightLit, n.Op); ok {
			return &ast.Literal{Kind: ast.LiteralNumber, Value: value}
		}
	}
	return &ast.MathOperation{Left: left, Op: n.Op, Right: right}
}

func optimizeInSet(n *ast.InSet, opts Options) ast.Expr {
	expr := OptimizeExpr(n.Expr, opts)
	literals := newLiteralSet(opts)
	dynamic := make([]ast.Expr, 0, len(n.Values))
	for _, value := range n.Values {
		optimized := OptimizeExpr(value, opts)
		lit, ok := optimized.(*ast.Literal)
		if !ok {
			dynamic = append(dynamic, optimized)
			continue
		}
		literals.add(lit)
	}
	lit, ok := expr.(*ast.Literal)
	if ok {
		if literals.has(lit) {
			return boolLiteral(true)
		}
		if len(dynamic) == 0 {
			return boolLiteral(false)
		}
		values := dynamic
		if len(values) == 1 {
			return optimizeComparison(&ast.Comparison{Left: expr, Op: "==", Right: values[0]}, opts)
		}
		return &ast.InSet{Expr: expr, Values: values}
	}
	values := append(literals.exprs(), dynamic...)
	switch len(values) {
	case 0:
		return boolLiteral(false)
	case 1:
		return optimizeComparison(&ast.Comparison{Left: expr, Op: "==", Right: values[0]}, opts)
	}
	for _, value := range values {
		if reflect.DeepEqual(expr, value) {
			return boolLiteral(true)
		}
	}
	return &ast.InSet{Expr: expr, Values: values}
}

func mergeInSetIntersection(left *ast.InSet, right *ast.InSet, opts Options) (ast.Expr, bool) {
	if !reflect.DeepEqual(left.Expr, right.Expr) {
		return nil, false
	}
	leftLits, ok := literalSetFromInSet(left, opts)
	if !ok {
		return nil, false
	}
	rightLits, ok := literalSetFromInSet(right, opts)
	if !ok {
		return nil, false
	}
	values := make([]ast.Expr, 0, len(leftLits.order))
	for _, key := range leftLits.order {
		if _, exists := rightLits.items[key]; exists {
			values = append(values, leftLits.items[key])
		}
	}
	return optimizeInSet(&ast.InSet{Expr: left.Expr, Values: values}, opts), true
}

func mergeInSetSubtraction(left *ast.InSet, right *ast.InSet, opts Options) (ast.Expr, bool) {
	if !reflect.DeepEqual(left.Expr, right.Expr) {
		return nil, false
	}
	leftLits, ok := literalSetFromInSet(left, opts)
	if !ok {
		return nil, false
	}
	rightLits, ok := literalSetFromInSet(right, opts)
	if !ok {
		return nil, false
	}
	values := make([]ast.Expr, 0, len(leftLits.order))
	for _, key := range leftLits.order {
		if _, exists := rightLits.items[key]; !exists {
			values = append(values, leftLits.items[key])
		}
	}
	return optimizeInSet(&ast.InSet{Expr: left.Expr, Values: values}, opts), true
}

func mergeInSetUnion(left *ast.InSet, right *ast.InSet, opts Options) (ast.Expr, bool) {
	if !reflect.DeepEqual(left.Expr, right.Expr) {
		return nil, false
	}
	leftLits, ok := literalSetFromInSet(left, opts)
	if !ok {
		return nil, false
	}
	rightLits, ok := literalSetFromInSet(right, opts)
	if !ok {
		return nil, false
	}
	for _, key := range rightLits.order {
		if _, exists := leftLits.items[key]; exists {
			continue
		}
		leftLits.order = append(leftLits.order, key)
		leftLits.items[key] = rightLits.items[key]
	}
	return optimizeInSet(&ast.InSet{Expr: left.Expr, Values: leftLits.exprs()}, opts), true
}

func literalSetFromInSet(set *ast.InSet, opts Options) (*literalSet, bool) {
	literals := newLiteralSet(opts)
	for _, value := range set.Values {
		lit, ok := value.(*ast.Literal)
		if !ok {
			return nil, false
		}
		literals.add(lit)
	}
	return literals, true
}

func singletonInSet(cmp *ast.Comparison) (*ast.InSet, bool) {
	lit, ok := cmp.Right.(*ast.Literal)
	if !ok {
		return nil, false
	}
	return &ast.InSet{Expr: cmp.Left, Values: []ast.Expr{lit}}, true
}

func negatedInSet(expr ast.Expr) (*ast.InSet, bool) {
	not, ok := expr.(*ast.Not)
	if !ok {
		return nil, false
	}
	set, ok := not.Term.(*ast.InSet)
	return set, ok
}

type literalSet struct {
	opts  Options
	order []literalKey
	items map[literalKey]*ast.Literal
}

type literalKey struct {
	class string
	text  string
	num   float64
}

func newLiteralSet(opts Options) *literalSet {
	return &literalSet{
		opts:  opts,
		items: make(map[literalKey]*ast.Literal),
	}
}

func (s *literalSet) add(lit *ast.Literal) {
	key, ok := s.key(lit)
	if !ok {
		return
	}
	if _, exists := s.items[key]; !exists {
		s.order = append(s.order, key)
	}
	if key.class == "string" {
		if _, exists := s.items[key]; !exists {
			s.items[key] = lit
		}
		return
	}
	s.items[key] = lit
}

func (s *literalSet) has(lit *ast.Literal) bool {
	key, ok := s.key(lit)
	if !ok {
		return false
	}
	_, ok = s.items[key]
	return ok
}

func (s *literalSet) exprs() []ast.Expr {
	values := make([]ast.Expr, 0, len(s.order))
	for _, key := range s.order {
		values = append(values, s.items[key])
	}
	return values
}

func (s *literalSet) key(lit *ast.Literal) (literalKey, bool) {
	switch lit.Kind {
	case ast.LiteralString:
		value, ok := lit.Value.(string)
		if !ok {
			return literalKey{}, false
		}
		if s.opts.CaseInsensitive {
			value = pycompat.Lower(value)
		}
		return literalKey{class: "string", text: value}, true
	case ast.LiteralNumber:
		value, ok := lit.Value.(ast.Num)
		if !ok {
			return literalKey{}, false
		}
		return literalKey{class: "number", num: value.Float64()}, true
	case ast.LiteralBool:
		if lit.Value == true {
			return literalKey{class: "number", num: 1}, true
		}
		return literalKey{class: "number", num: 0}, true
	case ast.LiteralNull:
		return literalKey{class: "null"}, true
	default:
		return literalKey{}, false
	}
}

func literalFromComparison(left, right *ast.Literal, op string, opts Options) ast.Expr {
	if left.Kind == ast.LiteralNull || right.Kind == ast.LiteralNull {
		return nullLiteral()
	}
	if left.Kind == ast.LiteralString {
		if right.Kind != ast.LiteralString {
			return nullLiteral()
		}
		a, _ := left.Value.(string)
		b, _ := right.Value.(string)
		if opts.CaseInsensitive {
			a = pycompat.Lower(a)
			b = pycompat.Lower(b)
		}
		return compareOrdered(a, b, op)
	}
	if left.Kind == ast.LiteralNumber {
		a, ok := left.Value.(ast.Num)
		if !ok || right.Kind != ast.LiteralNumber {
			return nullLiteral()
		}
		b, ok := right.Value.(ast.Num)
		if !ok {
			return nullLiteral()
		}
		return compareOrdered(a.Float64(), b.Float64(), op)
	}
	if left.Kind == ast.LiteralBool {
		if right.Kind != ast.LiteralBool {
			return nullLiteral()
		}
		if op == "==" || op == "!=" {
			result := left.Value == right.Value
			if op == "!=" {
				result = !result
			}
			return boolLiteral(result)
		}
		return nullLiteral()
	}
	if reflect.DeepEqual(left.Value, right.Value) {
		return compareOrdered(0, 0, op)
	}
	return nullLiteral()
}

func foldableFunction(name string) bool {
	switch name {
	case "length",
		"wildcard",
		"startsWith",
		"endsWith",
		"stringContains",
		"match",
		"matchLite",
		"string",
		"number",
		"concat",
		"add",
		"subtract",
		"multiply",
		"divide",
		"modulo",
		"arrayContains",
		"indexOf",
		"substring",
		"between",
		"cidrMatch":
		return true
	default:
		return false
	}
}

func foldFunctionCall(call *ast.FunctionCall, opts Options) (*ast.Literal, bool) {
	if err := validator.Validate(&ast.Query{EventType: engine.EventTypeGeneric, Expr: call}); err != nil {
		return nil, false
	}
	engineOpts := []engine.RuleOption(nil)
	if !opts.CaseInsensitive {
		engineOpts = append(engineOpts, engine.CaseSensitive())
	}
	value, err := engine.EvalExpression(call, nil, engineOpts...)
	if err != nil {
		return nil, false
	}
	return literalFromRuntimeValue(value)
}

func literalFromRuntimeValue(value any) (*ast.Literal, bool) {
	switch v := value.(type) {
	case nil:
		return &ast.Literal{Kind: ast.LiteralNull}, true
	case bool:
		return &ast.Literal{Kind: ast.LiteralBool, Value: v}, true
	case string:
		return &ast.Literal{Kind: ast.LiteralString, Value: v}, true
	case ast.Num:
		return &ast.Literal{Kind: ast.LiteralNumber, Value: v}, true
	default:
		return nil, false
	}
}

type ordered interface {
	~string | ~float64 | ~int
}

func compareOrdered[T ordered](a, b T, op string) ast.Expr {
	switch op {
	case "==":
		return boolLiteral(a == b)
	case "!=":
		return boolLiteral(a != b)
	case "<":
		return boolLiteral(a < b)
	case "<=":
		return boolLiteral(a <= b)
	case ">":
		return boolLiteral(a > b)
	case ">=":
		return boolLiteral(a >= b)
	default:
		return nullLiteral()
	}
}

func evalMath(left, right ast.Num, op string) (ast.Num, bool) {
	switch op {
	case "+":
		if left.IsInt && right.IsInt {
			return ast.Int(left.I + right.I), true
		}
		return ast.Float(left.Float64() + right.Float64()), true
	case "-":
		if left.IsInt && right.IsInt {
			return ast.Int(left.I - right.I), true
		}
		return ast.Float(left.Float64() - right.Float64()), true
	case "*":
		if left.IsInt && right.IsInt {
			return ast.Int(left.I * right.I), true
		}
		return ast.Float(left.Float64() * right.Float64()), true
	case "/":
		if right.IsZero() {
			return ast.Num{}, false
		}
		if left.IsInt && right.IsInt {
			return ast.Int(floorDiv(left.I, right.I)), true
		}
		return ast.Float(left.Float64() / right.Float64()), true
	case "%":
		if right.IsZero() {
			return ast.Num{}, false
		}
		if left.IsInt && right.IsInt {
			return ast.Int(floorMod(left.I, right.I)), true
		}
		return ast.Float(floatMod(left.Float64(), right.Float64())), true
	default:
		return ast.Num{}, false
	}
}

func floorDiv(left, right int64) int64 {
	q := left / right
	r := left % right
	if r != 0 && ((r > 0) != (right > 0)) {
		q--
	}
	return q
}

func floorMod(left, right int64) int64 {
	return left - floorDiv(left, right)*right
}

func floatMod(left, right float64) float64 {
	return left - math.Floor(left/right)*right
}

func numberLiteral(expr ast.Expr) (ast.Num, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok || lit.Kind != ast.LiteralNumber {
		return ast.Num{}, false
	}
	num, ok := lit.Value.(ast.Num)
	return num, ok
}

func boolLiteral(value bool) ast.Expr {
	return &ast.Literal{Kind: ast.LiteralBool, Value: value}
}

func nullLiteral() ast.Expr {
	return &ast.Literal{Kind: ast.LiteralNull}
}

func isBoolLiteral(expr ast.Expr, value bool) bool {
	lit, ok := expr.(*ast.Literal)
	return ok && lit.Kind == ast.LiteralBool && lit.Value == value
}

func isNullLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.Literal)
	return ok && lit.Kind == ast.LiteralNull
}

func invertedComparison(op string) (string, bool) {
	switch op {
	case "==":
		return "!=", true
	case "!=":
		return "==", true
	case "<":
		return ">=", true
	case "<=":
		return ">", true
	case ">":
		return "<=", true
	case ">=":
		return "<", true
	default:
		return "", false
	}
}
