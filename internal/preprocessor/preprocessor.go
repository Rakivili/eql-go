// Package preprocessor expands the currently supported subset of EQL
// definitions before semantic validation.
package preprocessor

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/parser"
	"github.com/Rakivili/eql-go/internal/validator"
)

// Preprocessor stores parsed EQL definitions.
type Preprocessor struct {
	constants map[string]*ast.Literal
	macros    map[string]*Macro
}

// Macro stores a parsed EQL macro definition.
type Macro struct {
	Name   string
	Params []string
	Expr   ast.Expr
}

// ParseDefinitions parses the supported subset of EQL definitions.
func ParseDefinitions(input string) (*Preprocessor, error) {
	pp := &Preprocessor{
		constants: map[string]*ast.Literal{},
		macros:    map[string]*Macro{},
	}
	lines := strings.Split(input, "\n")
	for i := 0; i < len(lines); {
		lineNo := i + 1
		raw := lines[i]
		line := strings.TrimSpace(raw)
		if line == "" || isDefinitionLineComment(line) {
			i++
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			i++
			continue
		}
		switch fields[0] {
		case "macro":
			parts := []string{strings.TrimSpace(line[len("macro"):])}
			i++
			for i < len(lines) {
				next := strings.TrimSpace(lines[i])
				if next != "" && !isDefinitionLineComment(next) && isDefinitionStart(next) {
					break
				}
				if next != "" && !isDefinitionLineComment(next) {
					parts = append(parts, next)
				}
				i++
			}
			if err := pp.parseMacro(lineNo, strings.Join(parts, "\n")); err != nil {
				return nil, err
			}
		case "const":
			if err := pp.parseConstant(lineNo, strings.TrimSpace(line[len("const"):])); err != nil {
				return nil, err
			}
			i++
		default:
			return nil, fmt.Errorf("line %d: expected const or macro definition", lineNo)
		}
	}
	return pp, nil
}

func (p *Preprocessor) parseConstant(lineNo int, text string) error {
	nameText, valueText, ok := cutConstAssignment(text)
	if !ok {
		return fmt.Errorf("line %d: expected = in const definition", lineNo)
	}
	name := strings.TrimSpace(nameText)
	if !validName(name) {
		return fmt.Errorf("line %d: invalid const name %q", lineNo, name)
	}
	if _, exists := p.constants[name]; exists {
		return fmt.Errorf("line %d: constant %s already defined", lineNo, name)
	}
	expr, err := parser.ParseExpression(strings.TrimSpace(valueText))
	if err != nil {
		return fmt.Errorf("line %d: parse const %s: %w", lineNo, name, err)
	}
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return fmt.Errorf("line %d: const %s must be a literal", lineNo, name)
	}
	p.constants[name] = cloneLiteral(lit)
	return nil
}

func cutConstAssignment(text string) (string, string, bool) {
	i := strings.IndexByte(text, '=')
	if i < 0 {
		return "", "", false
	}
	end := i + 1
	if end < len(text) && text[end] == '=' {
		end++
	}
	return text[:i], text[end:], true
}

func (p *Preprocessor) parseMacro(lineNo int, text string) error {
	text = strings.TrimSpace(text)
	open := strings.IndexByte(text, '(')
	if open <= 0 {
		return fmt.Errorf("line %d: expected macro name and parameters", lineNo)
	}
	name := strings.TrimSpace(text[:open])
	if !validName(name) {
		return fmt.Errorf("line %d: invalid macro name %q", lineNo, name)
	}
	closeOffset := strings.IndexByte(text[open+1:], ')')
	if closeOffset < 0 {
		return fmt.Errorf("line %d: expected ) in macro definition", lineNo)
	}
	close := open + 1 + closeOffset
	params, err := parseMacroParams(lineNo, text[open+1:close])
	if err != nil {
		return err
	}
	body := strings.TrimSpace(text[close+1:])
	if body == "" {
		return fmt.Errorf("line %d: expected macro expression", lineNo)
	}
	expr, err := parser.ParseExpression(body)
	if err != nil {
		return fmt.Errorf("line %d: parse macro %s: %w", lineNo, name, err)
	}
	expanded, err := p.expandExpr(expr)
	if err != nil {
		return fmt.Errorf("line %d: expand macro %s: %w", lineNo, name, err)
	}
	if err := validator.Validate(&ast.Query{Expr: expanded}); err != nil {
		return fmt.Errorf("line %d: validate macro %s: %w", lineNo, name, err)
	}
	p.macros[name] = &Macro{Name: name, Params: params, Expr: expanded}
	return nil
}

func parseMacroParams(lineNo int, input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	parts := strings.Split(input, ",")
	params := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if !validName(name) {
			return nil, fmt.Errorf("line %d: invalid macro parameter %q", lineNo, name)
		}
		params = append(params, name)
	}
	return params, nil
}

// ExpandQuery returns a copy of q with supported definitions expanded.
func (p *Preprocessor) ExpandQuery(q *ast.Query) (*ast.Query, error) {
	if p == nil || !p.hasDefinitions() || q == nil {
		return q, nil
	}
	out := *q
	if len(q.Sequence) > 0 {
		out.Sequence = make([]ast.EventQuery, 0, len(q.Sequence))
		for _, part := range q.Sequence {
			expr, err := p.expandExpr(part.Expr)
			if err != nil {
				return nil, err
			}
			next := ast.EventQuery{EventType: part.EventType, Expr: expr, Fork: part.Fork, HasFork: part.HasFork, Negated: part.Negated, Alias: part.Alias}
			next.By = make([]ast.Expr, 0, len(part.By))
			for _, by := range part.By {
				expr, err := p.expandExpr(by)
				if err != nil {
					return nil, err
				}
				next.By = append(next.By, expr)
			}
			out.Sequence = append(out.Sequence, next)
		}
		out.SequenceBy = make([]ast.Expr, 0, len(q.SequenceBy))
		for _, by := range q.SequenceBy {
			expr, err := p.expandExpr(by)
			if err != nil {
				return nil, err
			}
			out.SequenceBy = append(out.SequenceBy, expr)
		}
		if q.SequenceUntil != nil {
			expr, err := p.expandExpr(q.SequenceUntil.Expr)
			if err != nil {
				return nil, err
			}
			next := ast.EventQuery{
				EventType: q.SequenceUntil.EventType,
				Expr:      expr,
				Fork:      q.SequenceUntil.Fork,
				HasFork:   q.SequenceUntil.HasFork,
				Negated:   q.SequenceUntil.Negated,
				Alias:     q.SequenceUntil.Alias,
			}
			next.By = make([]ast.Expr, 0, len(q.SequenceUntil.By))
			for _, by := range q.SequenceUntil.By {
				expr, err := p.expandExpr(by)
				if err != nil {
					return nil, err
				}
				next.By = append(next.By, expr)
			}
			out.SequenceUntil = &next
		}
	} else if len(q.Sample) > 0 {
		out.Sample = make([]ast.EventQuery, 0, len(q.Sample))
		for _, part := range q.Sample {
			expr, err := p.expandExpr(part.Expr)
			if err != nil {
				return nil, err
			}
			next := ast.EventQuery{EventType: part.EventType, Expr: expr, Fork: part.Fork, HasFork: part.HasFork, Negated: part.Negated, Alias: part.Alias}
			next.By = make([]ast.Expr, 0, len(part.By))
			for _, by := range part.By {
				expr, err := p.expandExpr(by)
				if err != nil {
					return nil, err
				}
				next.By = append(next.By, expr)
			}
			out.Sample = append(out.Sample, next)
		}
		out.SampleBy = make([]ast.Expr, 0, len(q.SampleBy))
		for _, by := range q.SampleBy {
			expr, err := p.expandExpr(by)
			if err != nil {
				return nil, err
			}
			out.SampleBy = append(out.SampleBy, expr)
		}
	} else if len(q.Join) > 0 {
		out.Join = make([]ast.EventQuery, 0, len(q.Join))
		for _, part := range q.Join {
			expr, err := p.expandExpr(part.Expr)
			if err != nil {
				return nil, err
			}
			next := ast.EventQuery{EventType: part.EventType, Expr: expr, Fork: part.Fork, HasFork: part.HasFork, Negated: part.Negated, Alias: part.Alias}
			next.By = make([]ast.Expr, 0, len(part.By))
			for _, by := range part.By {
				expr, err := p.expandExpr(by)
				if err != nil {
					return nil, err
				}
				next.By = append(next.By, expr)
			}
			out.Join = append(out.Join, next)
		}
		out.JoinBy = make([]ast.Expr, 0, len(q.JoinBy))
		for _, by := range q.JoinBy {
			expr, err := p.expandExpr(by)
			if err != nil {
				return nil, err
			}
			out.JoinBy = append(out.JoinBy, expr)
		}
		if q.JoinUntil != nil {
			expr, err := p.expandExpr(q.JoinUntil.Expr)
			if err != nil {
				return nil, err
			}
			next := ast.EventQuery{
				EventType: q.JoinUntil.EventType,
				Expr:      expr,
				Fork:      q.JoinUntil.Fork,
				HasFork:   q.JoinUntil.HasFork,
				Negated:   q.JoinUntil.Negated,
				Alias:     q.JoinUntil.Alias,
			}
			next.By = make([]ast.Expr, 0, len(q.JoinUntil.By))
			for _, by := range q.JoinUntil.By {
				expr, err := p.expandExpr(by)
				if err != nil {
					return nil, err
				}
				next.By = append(next.By, expr)
			}
			out.JoinUntil = &next
		}
	} else {
		expr, err := p.expandExpr(q.Expr)
		if err != nil {
			return nil, err
		}
		out.Expr = expr
	}
	out.Pipes = make([]ast.Pipe, 0, len(q.Pipes))
	for _, pipe := range q.Pipes {
		next := ast.Pipe{Name: pipe.Name, Args: make([]ast.Expr, 0, len(pipe.Args))}
		for _, arg := range pipe.Args {
			expandedArg, err := p.expandExpr(arg)
			if err != nil {
				return nil, err
			}
			next.Args = append(next.Args, expandedArg)
		}
		out.Pipes = append(out.Pipes, next)
	}
	return &out, nil
}

func (p *Preprocessor) hasDefinitions() bool {
	return len(p.constants) != 0 || len(p.macros) != 0
}

func (p *Preprocessor) expandExpr(expr ast.Expr) (ast.Expr, error) {
	switch n := expr.(type) {
	case *ast.Literal:
		return cloneLiteral(n), nil
	case *ast.Field:
		if !n.Optional && !n.Scoped && len(n.Path) == 0 {
			if lit, ok := p.constants[n.Base]; ok {
				return cloneLiteral(lit), nil
			}
		}
		return cloneField(n), nil
	case *ast.FunctionCall:
		args := make([]ast.Expr, 0, len(n.Args))
		for _, arg := range n.Args {
			expandedArg, err := p.expandExpr(arg)
			if err != nil {
				return nil, err
			}
			args = append(args, expandedArg)
		}
		if macro, ok := p.macros[n.Name]; ok {
			return expandMacro(macro, args)
		}
		return &ast.FunctionCall{Name: n.Name, Args: args}, nil
	case *ast.NamedSubquery:
		expr, err := p.expandExpr(n.Query.Expr)
		if err != nil {
			return nil, err
		}
		by := make([]ast.Expr, 0, len(n.Query.By))
		for _, item := range n.Query.By {
			next, err := p.expandExpr(item)
			if err != nil {
				return nil, err
			}
			by = append(by, next)
		}
		query := n.Query
		query.Expr = expr
		query.By = by
		return &ast.NamedSubquery{
			QueryType: n.QueryType,
			Query:     query,
		}, nil
	case *ast.MathOperation:
		left, err := p.expandExpr(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := p.expandExpr(n.Right)
		if err != nil {
			return nil, err
		}
		return &ast.MathOperation{Left: left, Op: n.Op, Right: right}, nil
	case *ast.Comparison:
		left, err := p.expandExpr(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := p.expandExpr(n.Right)
		if err != nil {
			return nil, err
		}
		return nullComparisonOrComparison(left, n.Op, right), nil
	case *ast.IsNull:
		expr, err := p.expandExpr(n.Expr)
		if err != nil {
			return nil, err
		}
		return &ast.IsNull{Expr: expr}, nil
	case *ast.IsNotNull:
		expr, err := p.expandExpr(n.Expr)
		if err != nil {
			return nil, err
		}
		return &ast.IsNotNull{Expr: expr}, nil
	case *ast.InSet:
		expr, err := p.expandExpr(n.Expr)
		if err != nil {
			return nil, err
		}
		values := make([]ast.Expr, 0, len(n.Values))
		for _, value := range n.Values {
			expandedValue, err := p.expandExpr(value)
			if err != nil {
				return nil, err
			}
			values = append(values, expandedValue)
		}
		return &ast.InSet{Expr: expr, Values: values}, nil
	case *ast.Logical:
		terms := make([]ast.Expr, 0, len(n.Terms))
		for _, term := range n.Terms {
			expandedTerm, err := p.expandExpr(term)
			if err != nil {
				return nil, err
			}
			terms = append(terms, expandedTerm)
		}
		return &ast.Logical{Op: n.Op, Terms: terms}, nil
	case *ast.Not:
		term, err := p.expandExpr(n.Term)
		if err != nil {
			return nil, err
		}
		return &ast.Not{Term: term}, nil
	default:
		return expr, nil
	}
}

func expandMacro(macro *Macro, args []ast.Expr) (ast.Expr, error) {
	if len(args) != len(macro.Params) {
		return nil, fmt.Errorf("macro %s expected %d arguments but received %d", macro.Name, len(macro.Params), len(args))
	}
	lookup := make(map[string]ast.Expr, len(macro.Params))
	for i, param := range macro.Params {
		lookup[param] = args[i]
	}
	return substituteExpr(macro.Expr, lookup)
}

func substituteExpr(expr ast.Expr, lookup map[string]ast.Expr) (ast.Expr, error) {
	switch n := expr.(type) {
	case *ast.Literal:
		return cloneLiteral(n), nil
	case *ast.Field:
		if n.Scoped {
			return cloneField(n), nil
		}
		arg, ok := lookup[n.Base]
		if !ok {
			return cloneField(n), nil
		}
		if len(n.Path) == 0 {
			return cloneExpr(arg)
		}
		field, ok := arg.(*ast.Field)
		if !ok {
			return nil, fmt.Errorf("invalid expansion for %s.%s", n.Base, renderPath(n.Path))
		}
		out := cloneField(field)
		out.Path = append(out.Path, n.Path...)
		return out, nil
	case *ast.FunctionCall:
		args := make([]ast.Expr, 0, len(n.Args))
		for _, arg := range n.Args {
			next, err := substituteExpr(arg, lookup)
			if err != nil {
				return nil, err
			}
			args = append(args, next)
		}
		return &ast.FunctionCall{Name: n.Name, Args: args}, nil
	case *ast.NamedSubquery:
		expr, err := substituteExpr(n.Query.Expr, lookup)
		if err != nil {
			return nil, err
		}
		by := make([]ast.Expr, 0, len(n.Query.By))
		for _, item := range n.Query.By {
			next, err := substituteExpr(item, lookup)
			if err != nil {
				return nil, err
			}
			by = append(by, next)
		}
		query := n.Query
		query.Expr = expr
		query.By = by
		return &ast.NamedSubquery{
			QueryType: n.QueryType,
			Query:     query,
		}, nil
	case *ast.MathOperation:
		left, err := substituteExpr(n.Left, lookup)
		if err != nil {
			return nil, err
		}
		right, err := substituteExpr(n.Right, lookup)
		if err != nil {
			return nil, err
		}
		return &ast.MathOperation{Left: left, Op: n.Op, Right: right}, nil
	case *ast.Comparison:
		left, err := substituteExpr(n.Left, lookup)
		if err != nil {
			return nil, err
		}
		right, err := substituteExpr(n.Right, lookup)
		if err != nil {
			return nil, err
		}
		return &ast.Comparison{Left: left, Op: n.Op, Right: right}, nil
	case *ast.IsNull:
		expr, err := substituteExpr(n.Expr, lookup)
		if err != nil {
			return nil, err
		}
		return &ast.IsNull{Expr: expr}, nil
	case *ast.IsNotNull:
		expr, err := substituteExpr(n.Expr, lookup)
		if err != nil {
			return nil, err
		}
		return &ast.IsNotNull{Expr: expr}, nil
	case *ast.InSet:
		source, err := substituteExpr(n.Expr, lookup)
		if err != nil {
			return nil, err
		}
		values := make([]ast.Expr, 0, len(n.Values))
		for _, value := range n.Values {
			next, err := substituteExpr(value, lookup)
			if err != nil {
				return nil, err
			}
			values = append(values, next)
		}
		return &ast.InSet{Expr: source, Values: values}, nil
	case *ast.Logical:
		terms := make([]ast.Expr, 0, len(n.Terms))
		for _, term := range n.Terms {
			next, err := substituteExpr(term, lookup)
			if err != nil {
				return nil, err
			}
			terms = append(terms, next)
		}
		return &ast.Logical{Op: n.Op, Terms: terms}, nil
	case *ast.Not:
		term, err := substituteExpr(n.Term, lookup)
		if err != nil {
			return nil, err
		}
		return &ast.Not{Term: term}, nil
	default:
		return expr, nil
	}
}

func cloneExpr(expr ast.Expr) (ast.Expr, error) {
	return substituteExpr(expr, nil)
}

func nullComparisonOrComparison(left ast.Expr, op string, right ast.Expr) ast.Expr {
	if op != "==" && op != "!=" {
		return &ast.Comparison{Left: left, Op: op, Right: right}
	}
	switch {
	case isNullLiteral(left):
		return nullTest(right, op)
	case isNullLiteral(right):
		return nullTest(left, op)
	default:
		return &ast.Comparison{Left: left, Op: op, Right: right}
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

func cloneLiteral(lit *ast.Literal) *ast.Literal {
	if lit == nil {
		return nil
	}
	return &ast.Literal{Kind: lit.Kind, Value: lit.Value}
}

func cloneField(field *ast.Field) *ast.Field {
	out := &ast.Field{Base: field.Base, Optional: field.Optional, Scoped: field.Scoped}
	if len(field.Path) > 0 {
		out.Path = append([]ast.PathPart(nil), field.Path...)
	}
	return out
}

func renderPath(path []ast.PathPart) string {
	var parts []string
	for _, part := range path {
		if part.IsIdx {
			parts = append(parts, fmt.Sprintf("[%d]", part.Index))
			continue
		}
		parts = append(parts, part.Name)
	}
	return strings.Join(parts, ".")
}

func isDefinitionStart(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	return fields[0] == "const" || fields[0] == "macro"
}

func isDefinitionLineComment(line string) bool {
	return strings.HasPrefix(line, "//")
}

func validName(name string) bool {
	if name == "" || isKeyword(name) {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isKeyword(name string) bool {
	switch name {
	case "and", "by", "const", "false", "in", "join", "macro", "not", "null", "of", "or", "sample", "sequence", "true", "until", "with", "where":
		return true
	default:
		return false
	}
}
