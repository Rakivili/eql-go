package parser

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/diagnostic"
)

// ParseError reports a syntax or MVP-compatibility parse failure.
type ParseError struct {
	Message string
	Pos     int
	Line    int
	Column  int
	Source  string
	Caret   string
	Width   int
}

// SourceMap stores parser source spans for selected AST nodes.
type SourceMap struct {
	spans map[any]diagnostic.Span
}

// Span returns the source span recorded for node.
func (m *SourceMap) Span(node any) (diagnostic.Span, bool) {
	if m == nil || node == nil {
		return diagnostic.Span{}, false
	}
	span, ok := m.spans[node]
	return span, ok
}

// Options configures parser feature gates.
type Options struct {
	AllowSample           bool
	AllowNegation         bool
	AllowRuns             bool
	ElasticsearchSyntax   bool
	ElasticEndpointSyntax bool
}

// Error formats the parse failure with its byte position.
func (e *ParseError) Error() string {
	if e.Line > 0 && e.Column > 0 {
		return fmt.Sprintf("Error at line:%d,column:%d\n%s\n%s\n%s", e.Line, e.Column, e.Message, e.Source, e.Caret)
	}
	return fmt.Sprintf("parse error at %d: %s", e.Pos, e.Message)
}

// ParseQuery parses the supported EQL query forms.
func ParseQuery(input string) (*ast.Query, error) {
	return ParseQueryWithOptions(input, Options{})
}

// ParseQueryWithOptions parses an EQL query with explicit feature gates.
func ParseQueryWithOptions(input string, opts Options) (*ast.Query, error) {
	q, _, err := parseQueryWithSourceMap(input, opts, false)
	return q, err
}

// ParseQueryWithSourceMap parses an EQL query and returns selected source spans.
func ParseQueryWithSourceMap(input string, opts Options) (*ast.Query, *SourceMap, error) {
	return parseQueryWithSourceMap(input, opts, true)
}

func parseQueryWithSourceMap(input string, opts Options, collectSource bool) (*ast.Query, *SourceMap, error) {
	p := newParser(input)
	p.opts = opts
	if collectSource {
		p.sourceMap = &SourceMap{spans: map[any]diagnostic.Span{}}
	}
	q, err := p.parseQuery()
	if err != nil {
		return nil, p.sourceMap, err
	}
	if p.peek().typ != tokEOF {
		t := p.peek()
		return nil, p.sourceMap, p.errAt(t, "unexpected token %q", t.lit)
	}
	if len(q.Sequence) == 0 && len(q.Join) == 0 && len(q.Sample) == 0 && !isWhereCompatible(q.Expr) {
		return nil, p.sourceMap, p.errAt(p.firstExprTok, "expected boolean not %s", ast.ExprKind(q.Expr))
	}
	return q, p.sourceMap, nil
}

// ParseExpression parses an expression without an event_type/where wrapper.
func ParseExpression(input string) (ast.Expr, error) {
	p := newParser(input)
	p.firstExprTok = p.peek()
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().typ != tokEOF {
		t := p.peek()
		return nil, p.errAt(t, "unexpected token %q", t.lit)
	}
	return expr, nil
}

func isWhereCompatible(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Comparison, *ast.IsNull, *ast.IsNotNull, *ast.InSet, *ast.Logical, *ast.Not, *ast.Field, *ast.FunctionCall, *ast.NamedSubquery:
		return true
	case *ast.Literal:
		return v.Kind == ast.LiteralBool || v.Kind == ast.LiteralNull
	default:
		return false
	}
}

type tokenType int

const (
	tokEOF tokenType = iota
	tokInvalid
	tokIdent
	tokEscapedIdent
	tokNumber
	tokString
	tokWhere
	tokAnd
	tokOr
	tokNot
	tokTrue
	tokFalse
	tokNull
	tokIn
	tokOp
	tokLParen
	tokRParen
	tokDot
	tokLBracket
	tokRBracket
	tokComma
	tokMath
	tokPipe
	tokColon
	tokQuestion
	tokDollar
	tokMissingLBracket
)

type token struct {
	typ tokenType
	lit string
	pos int
}

type parser struct {
	toks         []token
	pos          int
	firstExprTok token
	opts         Options
	input        string
	lineStarts   []int
	sourceMap    *SourceMap
}

func newParser(input string) *parser {
	return &parser{
		toks:       lex(input),
		input:      input,
		lineStarts: lineStarts(input),
	}
}

func (p *parser) elasticsearchSyntax() bool {
	return p.opts.ElasticsearchSyntax || p.opts.ElasticEndpointSyntax
}

func (p *parser) parseQuery() (*ast.Query, error) {
	if p.peek().typ == tokIdent {
		switch p.peek().lit {
		case "sequence":
			p.next()
			return p.parseSequence()
		case "join":
			p.next()
			return p.parseJoin()
		case "sample":
			if !p.opts.AllowSample || !p.elasticsearchSyntax() {
				event := p.peek()
				return nil, p.errAt(event, "%s is not supported in MVP parser", event.lit)
			}
			p.next()
			return p.parseSample()
		}
	}
	eventQuery, err := p.parseEventQuery()
	if err != nil {
		return nil, err
	}
	pipes, err := p.parsePipes()
	if err != nil {
		return nil, err
	}
	return &ast.Query{EventType: eventQuery.EventType, Expr: eventQuery.Expr, Pipes: pipes}, nil
}

func (p *parser) parseEventQuery() (ast.EventQuery, error) {
	event := p.peek()
	if event.typ != tokIdent {
		return ast.EventQuery{}, p.errAt(event, "expected event type")
	}
	if isReservedKeyword(event.lit) {
		return ast.EventQuery{}, p.errAt(event, "Invalid use of keyword")
	}
	if event.lit == "sequence" || event.lit == "join" || event.lit == "sample" {
		return ast.EventQuery{}, p.errAt(event, "%s is not supported in event query", event.lit)
	}
	p.next()
	if _, err := p.expect(tokWhere, "expected where"); err != nil {
		return ast.EventQuery{}, err
	}
	p.firstExprTok = p.peek()
	expr, err := p.parseOr()
	if err != nil {
		return ast.EventQuery{}, err
	}
	if !isWhereCompatible(expr) {
		return ast.EventQuery{}, p.errAt(p.firstExprTok, "expected boolean not %s", ast.ExprKind(expr))
	}
	return ast.EventQuery{EventType: event.lit, Expr: expr}, nil
}

func (p *parser) parseSequence() (*ast.Query, error) {
	by, maxSpan, hasMaxSpan, err := p.parseSequenceOptions()
	if err != nil {
		return nil, err
	}
	var parts []ast.EventQuery
	for p.peek().typ == tokLBracket || p.peek().typ == tokMissingLBracket {
		part, err := p.parseSequenceSubquery()
		if err != nil {
			return nil, err
		}
		if err := p.parseOptionalSequenceFork(&part); err != nil {
			return nil, err
		}
		by, err := p.parseOptionalSequenceBy()
		if err != nil {
			return nil, err
		}
		part.By = by
		runs, err := p.parseOptionalSequenceRuns()
		if err != nil {
			return nil, err
		}
		if err := p.parseOptionalSequenceAlias(&part); err != nil {
			return nil, err
		}
		for i := 0; i < runs; i++ {
			parts = append(parts, part)
		}
	}
	if len(parts) < 2 && !p.elasticsearchSyntax() {
		return nil, p.errAt(p.peek(), "sequence expects at least two event queries")
	}
	until, err := p.parseOptionalSequenceUntil()
	if err != nil {
		return nil, err
	}
	pipes, err := p.parsePipes()
	if err != nil {
		return nil, err
	}
	return &ast.Query{
		Sequence:      parts,
		SequenceBy:    by,
		MaxSpan:       maxSpan,
		HasMaxSpan:    hasMaxSpan,
		SequenceUntil: until,
		Pipes:         pipes,
	}, nil
}

func (p *parser) parseSequenceSubquery() (ast.EventQuery, error) {
	negated := false
	switch p.peek().typ {
	case tokLBracket:
		p.next()
	case tokMissingLBracket:
		if !p.elasticsearchSyntax() || !p.opts.AllowNegation {
			return ast.EventQuery{}, p.errAt(p.peek(), "Negative subquery used")
		}
		negated = true
		p.next()
	default:
		return ast.EventQuery{}, p.errAt(p.peek(), "expected sequence event query")
	}
	part, err := p.parseEventQuery()
	if err != nil {
		return ast.EventQuery{}, err
	}
	if _, err := p.expect(tokRBracket, "expected ] after sequence event query"); err != nil {
		return ast.EventQuery{}, err
	}
	part.Negated = negated
	return part, nil
}

func (p *parser) parseSample() (*ast.Query, error) {
	by, err := p.parseOptionalSequenceBy()
	if err != nil {
		return nil, err
	}
	var parts []ast.EventQuery
	for p.peek().typ == tokLBracket {
		p.next()
		part, err := p.parseEventQuery()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRBracket, "expected ] after sample event query"); err != nil {
			return nil, err
		}
		if err := p.parseOptionalSequenceFork(&part); err != nil {
			return nil, err
		}
		stageBy, err := p.parseOptionalSequenceBy()
		if err != nil {
			return nil, err
		}
		part.By = stageBy
		if err := p.parseOptionalSequenceAlias(&part); err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	if len(parts) < 2 {
		return nil, p.errAt(p.peek(), "sample expects at least two event queries")
	}
	pipes, err := p.parsePipes()
	if err != nil {
		return nil, err
	}
	return &ast.Query{Sample: parts, SampleBy: by, Pipes: pipes}, nil
}

func (p *parser) parseJoin() (*ast.Query, error) {
	by, err := p.parseOptionalSequenceBy()
	if err != nil {
		return nil, err
	}
	var parts []ast.EventQuery
	for p.peek().typ == tokLBracket {
		p.next()
		part, err := p.parseEventQuery()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRBracket, "expected ] after join event query"); err != nil {
			return nil, err
		}
		if err := p.parseOptionalSequenceFork(&part); err != nil {
			return nil, err
		}
		stageBy, err := p.parseOptionalSequenceBy()
		if err != nil {
			return nil, err
		}
		part.By = stageBy
		if err := p.parseOptionalSequenceAlias(&part); err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	if len(parts) < 2 {
		return nil, p.errAt(p.peek(), "join expects at least two event queries")
	}
	until, err := p.parseOptionalSequenceUntil()
	if err != nil {
		return nil, err
	}
	pipes, err := p.parsePipes()
	if err != nil {
		return nil, err
	}
	return &ast.Query{Join: parts, JoinBy: by, JoinUntil: until, Pipes: pipes}, nil
}

func (p *parser) parseSequenceOptions() ([]ast.Expr, int64, bool, error) {
	var by []ast.Expr
	var maxSpan int64
	hasMaxSpan := false
	for p.peek().typ == tokIdent {
		switch p.peek().lit {
		case "by":
			if len(by) > 0 {
				return nil, 0, false, p.errAt(p.peek(), "duplicate sequence by")
			}
			nextBy, err := p.parseOptionalSequenceBy()
			if err != nil {
				return nil, 0, false, err
			}
			by = nextBy
		case "with":
			if hasMaxSpan {
				return nil, 0, false, p.errAt(p.peek(), "duplicate sequence maxspan")
			}
			nextMaxSpan, err := p.parseSequenceMaxSpan()
			if err != nil {
				return nil, 0, false, err
			}
			maxSpan = nextMaxSpan
			hasMaxSpan = true
		default:
			return by, maxSpan, hasMaxSpan, nil
		}
	}
	return by, maxSpan, hasMaxSpan, nil
}

func (p *parser) parseSequenceMaxSpan() (int64, error) {
	withTok, err := p.expect(tokIdent, "expected with")
	if err != nil {
		return 0, err
	}
	if withTok.lit != "with" {
		return 0, p.errAt(withTok, "expected with")
	}
	maxspanTok, err := p.expect(tokIdent, "expected maxspan")
	if err != nil {
		return 0, err
	}
	if maxspanTok.lit != "maxspan" {
		return 0, p.errAt(maxspanTok, "expected maxspan")
	}
	opTok, err := p.expect(tokOp, "expected = after maxspan")
	if err != nil {
		return 0, err
	}
	if opTok.lit != "=" && opTok.lit != "==" {
		return 0, p.errAt(opTok, "expected = after maxspan")
	}
	numberTok, err := p.expect(tokNumber, "expected maxspan duration")
	if err != nil {
		return 0, err
	}
	unitTok, err := p.expect(tokIdent, "expected time unit after maxspan duration")
	if err != nil {
		return 0, err
	}
	duration, err := parseMaxSpanDuration(numberTok.lit, unitTok.lit)
	if err != nil {
		return 0, p.errAt(numberTok, "%s", err)
	}
	return duration, nil
}

func parseMaxSpanDuration(quantityText string, unit string) (int64, error) {
	quantity, err := ast.ParseNum(quantityText)
	if err != nil {
		return 0, fmt.Errorf("invalid maxspan duration")
	}
	if quantity.Float64() < 0 {
		return 0, fmt.Errorf("maxspan duration must be positive")
	}
	if !quantity.IsInt {
		return 0, fmt.Errorf("only integer values allowed for maxspan")
	}
	unitMS, ok := maxSpanUnitMilliseconds(unit)
	if !ok {
		return 0, fmt.Errorf("invalid maxspan time unit %q", unit)
	}
	if quantity.I > (1<<63-1)/unitMS {
		return 0, fmt.Errorf("maxspan duration is too large")
	}
	milliseconds := quantity.I * unitMS
	seconds := milliseconds / 1000
	const ticksPerSecond int64 = 10_000_000
	if seconds > (1<<63-1)/ticksPerSecond {
		return 0, fmt.Errorf("maxspan duration is too large")
	}
	return seconds * ticksPerSecond, nil
}

func maxSpanUnitMilliseconds(unit string) (int64, bool) {
	switch unit {
	case "ms":
		return 1, true
	case "s":
		return 1000, true
	case "m":
		return 60 * 1000, true
	case "h":
		return 60 * 60 * 1000, true
	case "d":
		return 24 * 60 * 60 * 1000, true
	default:
		return 0, false
	}
}

func (p *parser) parseOptionalSequenceBy() ([]ast.Expr, error) {
	if p.peek().typ != tokIdent || p.peek().lit != "by" {
		return nil, nil
	}
	p.next()
	if p.peek().typ == tokLBracket {
		return nil, p.errAt(p.peek(), "expected sequence key after by")
	}
	var by []ast.Expr
	for {
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		by = append(by, expr)
		if p.peek().typ != tokComma {
			break
		}
		p.next()
		if p.peek().typ == tokLBracket {
			break
		}
	}
	return by, nil
}

func (p *parser) parseOptionalSequenceRuns() (int, error) {
	if p.peek().typ != tokIdent || p.peek().lit != "with" {
		return 1, nil
	}
	withTok := p.next()
	runsTok, err := p.expect(tokIdent, "expected runs after with")
	if err != nil {
		return 0, err
	}
	if runsTok.lit != "runs" {
		return 0, p.errAt(runsTok, "expected runs after with")
	}
	if !p.elasticsearchSyntax() || !p.opts.AllowRuns {
		return 0, p.errAt(withTok, "Unsupported usage of repeated syntax")
	}
	opTok, err := p.expect(tokOp, "expected = after runs")
	if err != nil {
		return 0, err
	}
	if opTok.lit != "=" && opTok.lit != "==" {
		return 0, p.errAt(opTok, "expected = after runs")
	}
	numberTok, err := p.expect(tokNumber, "expected runs count")
	if err != nil {
		return 0, err
	}
	countNum, err := ast.ParseNum(numberTok.lit)
	if err != nil || !countNum.IsInt {
		return 0, p.errAt(numberTok, "invalid runs count")
	}
	if countNum.I <= 1 {
		return 0, p.errAt(numberTok, "Repeated sequence runs must be greater than 1")
	}
	if countNum.I > int64(^uint(0)>>1) {
		return 0, p.errAt(numberTok, "runs count is too large")
	}
	return int(countNum.I), nil
}

func (p *parser) parseOptionalSequenceAlias(part *ast.EventQuery) error {
	if p.peek().typ != tokIdent || p.peek().lit != "as" {
		return nil
	}
	asTok := p.next()
	if !p.opts.ElasticEndpointSyntax {
		return p.errAt(asTok, "Unsupported usage of alias syntax")
	}
	name, err := p.expect(tokIdent, "expected alias name after as")
	if err != nil {
		return err
	}
	part.Alias = name.lit
	return nil
}

func (p *parser) parseOptionalSequenceUntil() (*ast.EventQuery, error) {
	if p.peek().typ != tokIdent || p.peek().lit != "until" {
		return nil, nil
	}
	p.next()
	if _, err := p.expect(tokLBracket, "expected [ after until"); err != nil {
		return nil, err
	}
	part, err := p.parseEventQuery()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tokRBracket, "expected ] after until event query"); err != nil {
		return nil, err
	}
	if err := p.parseOptionalSequenceFork(&part); err != nil {
		return nil, err
	}
	by, err := p.parseOptionalSequenceBy()
	if err != nil {
		return nil, err
	}
	part.By = by
	if p.peek().typ == tokIdent && p.peek().lit == "with" {
		return nil, p.errAt(p.peek(), "Unsupported usage of repeated syntax")
	}
	if err := p.parseOptionalSequenceAlias(&part); err != nil {
		return nil, err
	}
	return &part, nil
}

func (p *parser) parseOptionalSequenceFork(part *ast.EventQuery) error {
	if p.peek().typ != tokIdent || p.peek().lit != "fork" {
		return nil
	}
	p.next()
	part.HasFork = true
	part.Fork = true
	if p.peek().typ != tokOp {
		return nil
	}
	op := p.next()
	if op.lit != "=" && op.lit != "==" {
		return p.errAt(op, "expected = after fork")
	}
	switch p.peek().typ {
	case tokTrue:
		p.next()
		part.Fork = true
	case tokFalse:
		p.next()
		part.Fork = false
	default:
		return p.errAt(p.peek(), "expected boolean after fork")
	}
	return nil
}

func (p *parser) parseOr() (ast.Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	terms := []ast.Expr{left}
	for p.peek().typ == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		terms = append(terms, right)
	}
	if len(terms) == 1 {
		return left, nil
	}
	return &ast.Logical{Op: "or", Terms: terms}, nil
}

func (p *parser) parseAnd() (ast.Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	terms := []ast.Expr{left}
	for p.peek().typ == tokAnd {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		terms = append(terms, right)
	}
	if len(terms) == 1 {
		return left, nil
	}
	return &ast.Logical{Op: "and", Terms: terms}, nil
}

func (p *parser) parseNot() (ast.Expr, error) {
	count := 0
	for p.peek().typ == tokNot {
		p.next()
		count++
	}
	expr, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	if count%2 == 1 {
		return &ast.Not{Term: expr}, nil
	}
	return expr, nil
}

func (p *parser) parseComparison() (ast.Expr, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}
	if isStringPredicateToken(p.peek()) {
		return p.parseStringPredicate(left)
	}
	if p.peek().typ == tokIn {
		if err := p.validateInOperator(p.peek()); err != nil {
			return nil, err
		}
		p.next()
		values, err := p.parseSetValues()
		if err != nil {
			return nil, err
		}
		return &ast.InSet{Expr: left, Values: values}, nil
	}
	if p.peek().typ == tokNot && p.peekN(1).typ == tokIn {
		p.next()
		if err := p.validateInOperator(p.peek()); err != nil {
			return nil, err
		}
		p.next()
		values, err := p.parseSetValues()
		if err != nil {
			return nil, err
		}
		return &ast.Not{Term: &ast.InSet{Expr: left, Values: values}}, nil
	}
	if p.peek().typ != tokOp {
		return left, nil
	}
	op := p.next()
	if op.lit == "=" {
		if p.elasticsearchSyntax() {
			return nil, p.errAt(op, "Invalid syntax. Compare with == instead of =")
		}
		op.lit = "=="
	}
	right, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}
	if nullTest, ok := nullComparison(left, op.lit, right); ok {
		return nullTest, nil
	}
	cmp := &ast.Comparison{Left: left, Op: op.lit, Right: right}
	if p.sourceMap != nil {
		p.sourceMap.spans[cmp] = diagnostic.Span{Pos: op.pos, Width: tokenDiagnosticWidth(op)}
	}
	return cmp, nil
}

func nullComparison(left ast.Expr, op string, right ast.Expr) (ast.Expr, bool) {
	if op != "==" && op != "!=" {
		return nil, false
	}
	switch {
	case isNullLiteral(left):
		return nullTest(right, op), true
	case isNullLiteral(right):
		return nullTest(left, op), true
	default:
		return nil, false
	}
}

func nullTest(expr ast.Expr, op string) ast.Expr {
	if op == "!=" {
		return &ast.IsNotNull{Expr: expr}
	}
	return &ast.IsNull{Expr: expr}
}

func isNullLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.Literal)
	return ok && lit.Kind == ast.LiteralNull
}

func (p *parser) validateInOperator(op token) error {
	if op.lit == "in~" && !p.elasticsearchSyntax() {
		return p.errAt(op, "Invalid syntax. Explicit case-insensitivity is not supported.")
	}
	return nil
}

func (p *parser) parseStringPredicate(left ast.Expr) (ast.Expr, error) {
	predicate := p.next()
	functionName := stringPredicateFunction(predicate.lit)
	if functionName == "" {
		return nil, p.errAt(predicate, "invalid string predicate")
	}
	if !p.elasticsearchSyntax() {
		return nil, p.errAt(predicate, "Invalid syntax. Try: %s(...)", functionName)
	}
	patterns, err := p.parseStringPredicatePatterns()
	if err != nil {
		return nil, err
	}
	args := make([]ast.Expr, 0, len(patterns)+1)
	args = append(args, left)
	args = append(args, patterns...)
	return p.functionCall(predicate, functionName, args), nil
}

func (p *parser) parseStringPredicatePatterns() ([]ast.Expr, error) {
	if p.peek().typ == tokString {
		pattern, err := p.parseStringPredicateLiteral()
		if err != nil {
			return nil, err
		}
		return []ast.Expr{pattern}, nil
	}
	if p.peek().typ != tokLParen {
		return nil, p.errAt(p.peek(), "expected string literal after string predicate")
	}
	p.next()
	if p.peek().typ == tokRParen {
		return nil, p.errAt(p.peek(), "expected string literal in string predicate")
	}
	var patterns []ast.Expr
	for {
		pattern, err := p.parseStringPredicateLiteral()
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
		if p.peek().typ != tokComma {
			break
		}
		p.next()
		if p.peek().typ == tokRParen {
			return nil, p.errAt(p.peek(), "expected string literal in string predicate")
		}
	}
	if _, err := p.expect(tokRParen, "expected ) after string predicate"); err != nil {
		return nil, err
	}
	return patterns, nil
}

func (p *parser) parseStringPredicateLiteral() (ast.Expr, error) {
	t := p.peek()
	if t.typ != tokString {
		return nil, p.errAt(t, "expected string literal in string predicate")
	}
	p.next()
	if err := validateStringLiteralSyntax(t.lit, p.opts); err != nil {
		return nil, p.errAt(t, "invalid string literal")
	}
	s, err := unquote(t.lit)
	if err != nil {
		return nil, p.errAt(t, "invalid string literal")
	}
	return &ast.Literal{Kind: ast.LiteralString, Value: s}, nil
}

func isStringPredicateToken(t token) bool {
	if t.typ == tokColon {
		return true
	}
	return t.typ == tokIdent && stringPredicateFunction(t.lit) != ""
}

func stringPredicateFunction(predicate string) string {
	switch predicate {
	case ":", "like", "like~":
		return "wildcard"
	case "regex", "regex~":
		return "match"
	default:
		return ""
	}
}

func (p *parser) parseAdditive() (ast.Expr, error) {
	left, err := p.parseMultiplicative()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokMath && (p.peek().lit == "+" || p.peek().lit == "-") {
		op := p.next()
		right, err := p.parseMultiplicative()
		if err != nil {
			return nil, err
		}
		left = &ast.MathOperation{Left: left, Op: op.lit, Right: right}
	}
	return left, nil
}

func (p *parser) parseMultiplicative() (ast.Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokMath && (p.peek().lit == "*" || p.peek().lit == "/" || p.peek().lit == "%") {
		op := p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &ast.MathOperation{Left: left, Op: op.lit, Right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (ast.Expr, error) {
	if p.peek().typ == tokMath && (p.peek().lit == "-" || p.peek().lit == "+") {
		op := p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if op.lit == "+" {
			return right, nil
		}
		return &ast.MathOperation{
			Left:  &ast.Literal{Kind: ast.LiteralNumber, Value: ast.Int(0)},
			Op:    "-",
			Right: right,
		}, nil
	}
	return p.parseMethodChain()
}

func (p *parser) parseMethodChain() (ast.Expr, error) {
	expr, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokColon {
		if !p.hasTightMethodCall() {
			break
		}
		colon := p.next()
		name, err := p.expect(tokIdent, "expected method name after :")
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokLParen, "expected ( after method name"); err != nil {
			return nil, err
		}
		open := p.toks[p.pos-1]
		if colon.pos+1 != name.pos || name.pos+len(name.lit) != open.pos {
			return nil, p.errAt(colon, "expected method syntax :name(")
		}
		if strings.HasSuffix(name.lit, "~") {
			return nil, p.errAt(name, "Invalid syntax. Explicit case-insensitivity is not supported.")
		}
		args, err := p.parseCallArgs()
		if err != nil {
			return nil, err
		}
		expr = p.functionCall(name, name.lit, append([]ast.Expr{expr}, args...))
	}
	return expr, nil
}

func (p *parser) hasTightMethodCall() bool {
	colon := p.peek()
	name := p.peekN(1)
	open := p.peekN(2)
	return name.typ == tokIdent &&
		open.typ == tokLParen &&
		colon.pos+1 == name.pos &&
		name.pos+len(name.lit) == open.pos
}

func (p *parser) parseSetValues() ([]ast.Expr, error) {
	if _, err := p.expect(tokLParen, "expected ( after in"); err != nil {
		return nil, err
	}
	if p.peek().typ == tokRParen {
		return nil, p.errAt(p.peek(), "expected expression in set")
	}
	var values []ast.Expr
	for {
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		values = append(values, expr)
		if p.peek().typ != tokComma {
			break
		}
		p.next()
		if p.peek().typ == tokRParen {
			break
		}
	}
	if _, err := p.expect(tokRParen, "expected ) after set"); err != nil {
		return nil, err
	}
	return values, nil
}

func (p *parser) parsePipes() ([]ast.Pipe, error) {
	var pipes []ast.Pipe
	for p.peek().typ == tokPipe {
		p.next()
		name, err := p.expect(tokIdent, "expected pipe name after |")
		if err != nil {
			return nil, err
		}
		pipe := ast.Pipe{Name: name.lit}
		switch name.lit {
		case "head", "tail":
			if p.peek().typ != tokPipe && p.peek().typ != tokEOF {
				arg, err := p.parseOr()
				if err != nil {
					return nil, err
				}
				pipe.Args = append(pipe.Args, arg)
			}
		case "filter":
			arg, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			pipe.Args = append(pipe.Args, arg)
		case "count", "sort", "unique", "unique_count":
			for p.peek().typ != tokPipe && p.peek().typ != tokEOF {
				arg, err := p.parseOr()
				if err != nil {
					return nil, err
				}
				pipe.Args = append(pipe.Args, arg)
				if p.peek().typ == tokComma {
					p.next()
				}
			}
		default:
			return nil, p.errAt(name, "%s pipe is not supported in MVP parser", name.lit)
		}
		pipes = append(pipes, pipe)
	}
	return pipes, nil
}

func (p *parser) parsePrimary() (ast.Expr, error) {
	t := p.peek()
	switch t.typ {
	case tokTrue:
		p.next()
		return p.registerLiteralSpan(&ast.Literal{Kind: ast.LiteralBool, Value: true}, t), nil
	case tokFalse:
		p.next()
		return p.registerLiteralSpan(&ast.Literal{Kind: ast.LiteralBool, Value: false}, t), nil
	case tokNull:
		p.next()
		return p.registerLiteralSpan(&ast.Literal{Kind: ast.LiteralNull}, t), nil
	case tokString:
		p.next()
		if err := validateStringLiteralSyntax(t.lit, p.opts); err != nil {
			return nil, p.errAt(t, "invalid string literal")
		}
		s, err := unquote(t.lit)
		if err != nil {
			return nil, p.errAt(t, "invalid string literal")
		}
		return p.registerLiteralSpan(&ast.Literal{Kind: ast.LiteralString, Value: s}, t), nil
	case tokNumber:
		p.next()
		if !validNumberLiteralSyntax(t.lit) {
			return nil, p.errAt(t, "invalid number")
		}
		n, err := ast.ParseNum(t.lit)
		if err != nil {
			return nil, p.errAt(t, "invalid number")
		}
		return p.registerLiteralSpan(&ast.Literal{Kind: ast.LiteralNumber, Value: n}, t), nil
	case tokIdent:
		if p.peekN(1).typ == tokIdent && p.peekN(1).lit == "of" {
			return p.parseNamedSubquery()
		}
		if p.peekN(1).typ == tokLParen {
			return p.parseFunctionCall()
		}
		return p.parseField(false, false)
	case tokEscapedIdent:
		return p.parseField(false, false)
	case tokQuestion:
		if !p.elasticsearchSyntax() {
			return nil, p.errAt(t, "Optional fields are not supported.")
		}
		return p.parseField(true, false)
	case tokDollar:
		if !p.opts.ElasticEndpointSyntax {
			return nil, p.errAt(t, "Invalid syntax")
		}
		return p.parseField(false, true)
	case tokLParen:
		p.next()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRParen, "expected )"); err != nil {
			return nil, err
		}
		return expr, nil
	default:
		return nil, p.errAt(t, "expected expression")
	}
}

func (p *parser) parseNamedSubquery() (ast.Expr, error) {
	name := p.next()
	if name.lit != "event" && name.lit != "child" && name.lit != "descendant" {
		return nil, p.errAt(name, "%s of is not supported in current feature set", name.lit)
	}
	p.next()
	if _, err := p.expect(tokLBracket, "expected [ after named subquery"); err != nil {
		return nil, err
	}
	query, err := p.parseEventQuery()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tokRBracket, "expected ] after named subquery"); err != nil {
		return nil, err
	}
	return &ast.NamedSubquery{QueryType: name.lit, Query: query}, nil
}

func (p *parser) parseFunctionCall() (ast.Expr, error) {
	name := p.next()
	if _, err := p.expect(tokLParen, "expected ( after function name"); err != nil {
		return nil, err
	}
	args, err := p.parseCallArgs()
	if err != nil {
		return nil, err
	}
	functionName, err := p.normalizeFunctionName(name)
	if err != nil {
		return nil, err
	}
	return p.functionCall(name, functionName, args), nil
}

func (p *parser) normalizeFunctionName(name token) (string, error) {
	if !strings.HasSuffix(name.lit, "~") {
		return name.lit, nil
	}
	if !p.elasticsearchSyntax() {
		return "", p.errAt(name, "Invalid syntax. Explicit case-insensitivity is not supported.")
	}
	return strings.TrimSuffix(name.lit, "~"), nil
}

func (p *parser) functionCall(name token, functionName string, args []ast.Expr) *ast.FunctionCall {
	call := &ast.FunctionCall{Name: functionName, Args: args}
	if p.sourceMap != nil {
		p.sourceMap.spans[call] = diagnostic.Span{Pos: name.pos, Width: tokenDiagnosticWidth(name)}
	}
	return call
}

func (p *parser) parseCallArgs() ([]ast.Expr, error) {
	var args []ast.Expr
	if p.peek().typ != tokRParen {
		for {
			arg, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
			if p.peek().typ != tokComma {
				break
			}
			p.next()
			if p.peek().typ == tokRParen {
				break
			}
		}
	}
	if _, err := p.expect(tokRParen, "expected ) after function arguments"); err != nil {
		return nil, err
	}
	return args, nil
}

func (p *parser) parseField(optional bool, scoped bool) (ast.Expr, error) {
	if optional {
		p.next()
	}
	if scoped {
		p.next()
	}
	base, err := p.expectFieldIdent("expected field name")
	if err != nil {
		return nil, err
	}
	f := &ast.Field{Base: base.lit}
	if optional {
		f.Optional = true
	}
	if scoped {
		f.Scoped = true
	}
	lastTok := base
	for {
		switch p.peek().typ {
		case tokDot:
			p.next()
			name, err := p.expectFieldIdent("expected field name after .")
			if err != nil {
				return nil, err
			}
			f.Path = append(f.Path, ast.PathPart{Name: name.lit})
			lastTok = name
		case tokLBracket:
			if p.peekN(1).typ != tokNumber {
				p.registerFieldSpan(f, base, lastTok)
				return f, nil
			}
			p.next()
			idxTok, err := p.expect(tokNumber, "expected array index")
			if err != nil {
				return nil, err
			}
			idx, err := strconv.Atoi(idxTok.lit)
			if err != nil {
				return nil, p.errAt(idxTok, "invalid array index")
			}
			rbrack, err := p.expect(tokRBracket, "expected ]")
			if err != nil {
				return nil, err
			}
			f.Path = append(f.Path, ast.PathPart{Index: idx, IsIdx: true})
			lastTok = rbrack
		default:
			p.registerFieldSpan(f, base, lastTok)
			return f, nil
		}
	}
}

func (p *parser) registerFieldSpan(f *ast.Field, base, last token) {
	if p.sourceMap == nil {
		return
	}
	end := last.pos + tokenDiagnosticWidth(last)
	if end <= base.pos {
		end = base.pos + 1
	}
	p.sourceMap.spans[f] = diagnostic.Span{Pos: base.pos, Width: end - base.pos}
}

func (p *parser) registerLiteralSpan(lit *ast.Literal, t token) *ast.Literal {
	if p.sourceMap != nil {
		p.sourceMap.spans[lit] = diagnostic.Span{Pos: t.pos, Width: tokenDiagnosticWidth(t)}
	}
	return lit
}

func (p *parser) peek() token {
	return p.peekN(0)
}

func (p *parser) peekN(offset int) token {
	pos := p.pos + offset
	if pos >= len(p.toks) {
		return token{typ: tokEOF, pos: len(p.input)}
	}
	return p.toks[pos]
}

func (p *parser) next() token {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *parser) expect(tt tokenType, msg string) (token, error) {
	t := p.peek()
	if t.typ != tt {
		return t, p.errAt(t, msg)
	}
	p.next()
	return t, nil
}

func (p *parser) expectFieldIdent(msg string) (token, error) {
	t := p.peek()
	if t.typ != tokIdent && t.typ != tokEscapedIdent {
		return t, p.errAt(t, msg)
	}
	if t.typ == tokIdent && isReservedKeyword(t.lit) {
		return t, p.errAt(t, "Invalid use of keyword")
	}
	p.next()
	return t, nil
}

func (p *parser) errAt(t token, format string, args ...any) error {
	line, column, source, caret, width := p.diagnosticAt(t)
	return &ParseError{
		Message: fmt.Sprintf(format, args...),
		Pos:     t.pos,
		Line:    line,
		Column:  column,
		Source:  source,
		Caret:   caret,
		Width:   width,
	}
}

func (p *parser) diagnosticAt(t token) (line int, column int, source string, caret string, width int) {
	pos := t.pos
	if pos < 0 {
		pos = 0
	}
	if pos > len(p.input) {
		pos = len(p.input)
	}
	lineIdx := 0
	if len(p.lineStarts) > 0 {
		lineIdx = sort.Search(len(p.lineStarts), func(i int) bool {
			return p.lineStarts[i] > pos
		}) - 1
		if lineIdx < 0 {
			lineIdx = 0
		}
	}
	lineStart := 0
	if lineIdx < len(p.lineStarts) {
		lineStart = p.lineStarts[lineIdx]
	}
	lineEnd := len(p.input)
	if lineIdx+1 < len(p.lineStarts) {
		lineEnd = p.lineStarts[lineIdx+1] - 1
	}
	if lineEnd > lineStart && p.input[lineEnd-1] == '\r' {
		lineEnd--
	}
	if lineEnd < lineStart {
		lineEnd = lineStart
	}
	source = p.input[lineStart:lineEnd]
	column0 := pos - lineStart
	if column0 < 0 {
		column0 = 0
	}
	if column0 > len(source) {
		column0 = len(source)
	}
	width = tokenDiagnosticWidth(t)
	if remaining := len(source) - column0; remaining > 0 && width > remaining {
		width = remaining
	}
	if width < 1 {
		width = 1
	}
	return lineIdx + 1, column0 + 1, source, caretLine(source, column0, width), width
}

func tokenDiagnosticWidth(t token) int {
	if t.typ == tokEOF || len(t.lit) == 0 {
		return 1
	}
	if t.typ == tokEscapedIdent {
		return len(t.lit) + 2
	}
	if idx := strings.IndexAny(t.lit, "\r\n"); idx >= 0 {
		if idx == 0 {
			return 1
		}
		return idx
	}
	return len(t.lit)
}

func caretLine(source string, column0 int, width int) string {
	if column0 < 0 {
		column0 = 0
	}
	if column0 > len(source) {
		column0 = len(source)
	}
	if width < 1 {
		width = 1
	}
	var b strings.Builder
	for i := 0; i < column0; i++ {
		if source[i] == '\t' {
			b.WriteByte('\t')
		} else {
			b.WriteByte(' ')
		}
	}
	b.WriteString(strings.Repeat("^", width))
	return b.String()
}

func lineStarts(input string) []int {
	starts := []int{0}
	for i := 0; i < len(input); i++ {
		if input[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lex(input string) []token {
	var toks []token
	for i := 0; i < len(input); {
		r := rune(input[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}
		if input[i] == '/' && i+1 < len(input) {
			switch input[i+1] {
			case '/':
				i += 2
				for i < len(input) && input[i] != '\n' && input[i] != '\r' {
					i++
				}
				continue
			case '*':
				start := i
				i += 2
				end := strings.Index(input[i:], "*/")
				if end < 0 {
					toks = append(toks, token{typ: tokInvalid, lit: input[start:], pos: start})
					return toks
				}
				i += end + 2
				continue
			}
		}
		if isIdentStart(r) {
			start := i
			i++
			for i < len(input) && isIdentPart(rune(input[i])) {
				i++
			}
			lit := input[start:i]
			if i < len(input) && input[i] == '~' && ((lit == "in" || lit == "like" || lit == "regex") || hasFollowingOpenParen(input, i+1)) {
				i++
				lit = input[start:i]
			}
			tt := tokIdent
			switch lit {
			case "where":
				tt = tokWhere
			case "and":
				tt = tokAnd
			case "or":
				tt = tokOr
			case "not":
				tt = tokNot
			case "true":
				tt = tokTrue
			case "false":
				tt = tokFalse
			case "null":
				tt = tokNull
			case "in", "in~":
				tt = tokIn
			}
			toks = append(toks, token{typ: tt, lit: lit, pos: start})
			continue
		}
		if input[i] == '`' {
			start := i
			i++
			closed := false
			for i < len(input) {
				if input[i] == '\n' || input[i] == '\r' {
					toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
					return toks
				}
				if input[i] == '`' {
					closed = true
					break
				}
				i++
			}
			if !closed || i == start+1 {
				toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
				return toks
			}
			toks = append(toks, token{typ: tokEscapedIdent, lit: input[start+1 : i], pos: start})
			i++
			continue
		}
		if isDigit(r) || (input[i] == '.' && i+1 < len(input) && isDigit(rune(input[i+1]))) {
			start := i
			i++
			for i < len(input) && (isDigit(rune(input[i])) || strings.ContainsRune(".eE+-", rune(input[i]))) {
				if (input[i] == '+' || input[i] == '-') && !(input[i-1] == 'e' || input[i-1] == 'E') {
					break
				}
				i++
			}
			toks = append(toks, token{typ: tokNumber, lit: input[start:i], pos: start})
			continue
		}
		switch input[i] {
		case '?':
			if i+1 < len(input) && (isIdentStart(rune(input[i+1])) || input[i+1] == '`') {
				toks = append(toks, token{typ: tokQuestion, lit: "?", pos: i})
				i++
				continue
			}
			if i+1 >= len(input) || (input[i+1] != '\'' && input[i+1] != '"') {
				toks = append(toks, token{typ: tokInvalid, lit: string(input[i]), pos: i})
				return toks
			}
			start := i
			i++
			quote := input[i]
			i++
			escaped := false
			closed := false
			for i < len(input) {
				c := input[i]
				i++
				if c == '\n' || c == '\r' {
					toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
					return toks
				}
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == quote {
					closed = true
					break
				}
			}
			if !closed {
				toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
				return toks
			}
			toks = append(toks, token{typ: tokString, lit: input[start:i], pos: start})
		case '\'', '"':
			start := i
			quote := input[i]
			if quote == '"' && i+2 < len(input) && input[i+1] == '"' && input[i+2] == '"' {
				i += 3
				closed := false
				for i < len(input) {
					if input[i] == '\n' || input[i] == '\r' {
						toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
						return toks
					}
					if input[i] == '"' && i+2 < len(input) && input[i+1] == '"' && input[i+2] == '"' {
						i += 3
						for i < len(input) && input[i] == '"' {
							i++
						}
						closed = true
						break
					}
					i++
				}
				if !closed {
					toks = append(toks, token{typ: tokInvalid, lit: input[start:], pos: start})
					return toks
				}
				toks = append(toks, token{typ: tokString, lit: input[start:i], pos: start})
				continue
			}
			i++
			escaped := false
			closed := false
			for i < len(input) {
				c := input[i]
				i++
				if c == '\n' || c == '\r' {
					toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
					return toks
				}
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == quote {
					closed = true
					break
				}
			}
			if !closed {
				toks = append(toks, token{typ: tokInvalid, lit: input[start:i], pos: start})
				return toks
			}
			toks = append(toks, token{typ: tokString, lit: input[start:i], pos: start})
		case '$':
			if i+1 < len(input) && (isIdentStart(rune(input[i+1])) || input[i+1] == '`') {
				toks = append(toks, token{typ: tokDollar, lit: "$", pos: i})
				i++
				continue
			}
			toks = append(toks, token{typ: tokInvalid, lit: string(input[i]), pos: i})
			return toks
		case '(':
			toks = append(toks, token{typ: tokLParen, lit: "(", pos: i})
			i++
		case ')':
			toks = append(toks, token{typ: tokRParen, lit: ")", pos: i})
			i++
		case '.':
			toks = append(toks, token{typ: tokDot, lit: ".", pos: i})
			i++
		case '[':
			toks = append(toks, token{typ: tokLBracket, lit: "[", pos: i})
			i++
		case ']':
			toks = append(toks, token{typ: tokRBracket, lit: "]", pos: i})
			i++
		case ',':
			toks = append(toks, token{typ: tokComma, lit: ",", pos: i})
			i++
		case '|':
			toks = append(toks, token{typ: tokPipe, lit: "|", pos: i})
			i++
		case ':':
			toks = append(toks, token{typ: tokColon, lit: ":", pos: i})
			i++
		case '+', '-', '*', '/', '%':
			toks = append(toks, token{typ: tokMath, lit: string(input[i]), pos: i})
			i++
		case '=', '!', '<', '>':
			start := i
			if input[i] == '!' && i+1 < len(input) && input[i+1] == '[' {
				toks = append(toks, token{typ: tokMissingLBracket, lit: "![", pos: i})
				i += 2
				continue
			}
			i++
			if i < len(input) && input[i] == '=' {
				i++
			}
			toks = append(toks, token{typ: tokOp, lit: input[start:i], pos: start})
		default:
			toks = append(toks, token{typ: tokInvalid, lit: string(input[i]), pos: i})
			return toks
		}
	}
	toks = append(toks, token{typ: tokEOF, pos: len(input)})
	return toks
}

func hasFollowingOpenParen(input string, pos int) bool {
	for pos < len(input) && unicode.IsSpace(rune(input[pos])) {
		pos++
	}
	return pos < len(input) && input[pos] == '('
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || isDigit(r)
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func isReservedKeyword(name string) bool {
	switch name {
	case "and", "by", "const", "false", "in", "join", "macro", "not", "null", "of", "or", "sample", "sequence", "true", "until", "with", "where":
		return true
	default:
		return false
	}
}

func validNumberLiteralSyntax(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' && (i+1 >= len(s) || !isDigit(rune(s[i+1]))) {
			return false
		}
	}
	return true
}

func unquote(s string) (string, error) {
	if len(s) >= 3 && s[0] == '?' {
		quote := s[1]
		body := s[2 : len(s)-1]
		if quote == '\'' {
			return strings.ReplaceAll(body, `\'`, `'`), nil
		}
		return strings.ReplaceAll(body, `\"`, `"`), nil
	}
	if len(s) < 2 || (s[0] != '\'' && s[0] != '"') {
		return "", fmt.Errorf("invalid quoted string")
	}
	if strings.HasPrefix(s, `"""`) {
		if !strings.HasSuffix(s, `"""`) || len(s) < 6 {
			return "", fmt.Errorf("invalid quoted string")
		}
		return s[3 : len(s)-3], nil
	}
	return unescapeStringBody(s[1:len(s)-1], s[0] == '"')
}

func validateStringLiteralSyntax(s string, opts Options) error {
	esSyntax := opts.ElasticsearchSyntax || opts.ElasticEndpointSyntax
	if !esSyntax {
		if strings.HasPrefix(s, `"""`) {
			return fmt.Errorf("invalid quoted string")
		}
		return nil
	}
	if strings.HasPrefix(s, "?") || strings.HasPrefix(s, "'") {
		return fmt.Errorf("invalid quoted string")
	}
	return nil
}

func unescapeStringBody(body string, allowUnicode bool) (string, error) {
	var out strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			out.WriteByte(body[i])
			continue
		}
		if i+1 >= len(body) {
			return "", fmt.Errorf("trailing escape")
		}
		i++
		switch body[i] {
		case 'b':
			out.WriteByte('\b')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case 'n':
			out.WriteByte('\n')
		case 'f':
			out.WriteByte('\f')
		case '\\', '"', '\'':
			out.WriteByte(body[i])
		case 'u':
			if !allowUnicode {
				return "", fmt.Errorf("invalid unicode escape")
			}
			if i+1 >= len(body) || body[i+1] != '{' {
				return "", fmt.Errorf("invalid unicode escape")
			}
			end := strings.IndexByte(body[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("invalid unicode escape")
			}
			hexDigits := body[i+2 : i+2+end]
			if len(hexDigits) < 2 || len(hexDigits) > 8 {
				return "", fmt.Errorf("invalid unicode escape")
			}
			value, err := strconv.ParseInt(hexDigits, 16, 32)
			if err != nil || value > unicode.MaxRune {
				return "", fmt.Errorf("invalid unicode escape")
			}
			out.WriteRune(rune(value))
			i += 2 + end
		default:
			return "", fmt.Errorf("unknown escape")
		}
	}
	return out.String(), nil
}
