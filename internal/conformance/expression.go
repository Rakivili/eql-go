package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/engine"
	"github.com/Rakivili/eql-go/internal/optimizer"
	"github.com/Rakivili/eql-go/internal/parser"
	"github.com/Rakivili/eql-go/internal/validator"
)

// ExpressionResult contains canonical unoptimized and folded expression values.
type ExpressionResult struct {
	Expression string
	Runtime    string
	Folded     string
}

// ExpressionCompareResult contains canonical Python and Go expression values.
type ExpressionCompareResult struct {
	Expression string
	Python     ExpressionResult
	Go         ExpressionResult
}

// Equal reports whether Python and Go returned the same runtime and folded values.
func (r ExpressionCompareResult) Equal() bool {
	return r.Python.Runtime == r.Go.Runtime && r.Python.Folded == r.Go.Folded
}

// CompareExpression evaluates one expression with Python EQL and this Go implementation.
func CompareExpression(ctx context.Context, pythonRepo string, expression string, caseSensitive bool) (ExpressionCompareResult, error) {
	pythonResult, err := PythonExpressionValues(ctx, pythonRepo, expression, caseSensitive)
	if err != nil {
		return ExpressionCompareResult{}, err
	}
	goResult, err := GoExpressionValues(expression, caseSensitive)
	if err != nil {
		return ExpressionCompareResult{}, err
	}
	return ExpressionCompareResult{Expression: expression, Python: pythonResult, Go: goResult}, nil
}

// ExpressionEquivalentResult contains Python and Go expression equivalence checks.
type ExpressionEquivalentResult struct {
	Expression string
	Alternate  string
	Python     bool
	Go         bool
}

// Equal reports whether Python and Go agree that two expressions are equivalent.
func (r ExpressionEquivalentResult) Equal() bool {
	return r.Python == r.Go
}

// ExpressionOptimizedResult contains Python and Go optimizer checks.
type ExpressionOptimizedResult struct {
	Expression string
	Optimized  string
	Python     bool
	Go         bool
}

// Equal reports whether Python and Go agree that expression optimizes to Optimized.
func (r ExpressionOptimizedResult) Equal() bool {
	return r.Python == r.Go
}

// CompareExpressionEquivalent checks expression equivalence with Python EQL and Go.
func CompareExpressionEquivalent(ctx context.Context, pythonRepo string, expression string, alternate string) (ExpressionEquivalentResult, error) {
	pythonEqual, err := PythonExpressionEquivalent(ctx, pythonRepo, expression, alternate)
	if err != nil {
		return ExpressionEquivalentResult{}, err
	}
	goEqual, err := GoExpressionEquivalent(expression, alternate)
	if err != nil {
		return ExpressionEquivalentResult{}, err
	}
	return ExpressionEquivalentResult{Expression: expression, Alternate: alternate, Python: pythonEqual, Go: goEqual}, nil
}

// CompareExpressionOptimized checks optimizer output with Python EQL and this Go implementation.
func CompareExpressionOptimized(ctx context.Context, pythonRepo string, expression string, optimized string) (ExpressionOptimizedResult, error) {
	pythonEqual, err := PythonExpressionOptimized(ctx, pythonRepo, expression, optimized)
	if err != nil {
		return ExpressionOptimizedResult{}, err
	}
	goEqual, err := GoExpressionOptimized(expression, optimized)
	if err != nil {
		return ExpressionOptimizedResult{}, err
	}
	return ExpressionOptimizedResult{Expression: expression, Optimized: optimized, Python: pythonEqual, Go: goEqual}, nil
}

// PythonExpressionParseError returns Python's parse/semantic error text for one expression, or an empty string when accepted.
func PythonExpressionParseError(ctx context.Context, pythonRepo string, expression string) (string, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]string{"expression": expression}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	script := `
import json, sys
from eql import parse_expression

payload = json.load(sys.stdin)
try:
    parse_expression(payload["expression"])
    error = ""
except Exception as e:
    error = str(e)
print(json.dumps({"error": error}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("python expression parse error oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var result struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return "", err
	}
	return result.Error, nil
}

// GoExpressionParseError returns Go parse/validation error text for one expression, or an empty string when accepted.
func GoExpressionParseError(expression string) string {
	source, err := parser.ParseExpression(expression)
	if err != nil {
		return err.Error()
	}
	if err := validator.Validate(&ast.Query{EventType: engine.EventTypeGeneric, Expr: source}); err != nil {
		return err.Error()
	}
	return ""
}

// GoExpressionEquivalent reports whether optimizing expression produces alternate.
func GoExpressionEquivalent(expression string, alternate string) (bool, error) {
	return GoExpressionOptimized(expression, alternate)
}

// GoExpressionOptimized reports whether optimizing expression produces optimized.
func GoExpressionOptimized(expression string, optimized string) (bool, error) {
	source, err := parser.ParseExpression(expression)
	if err != nil {
		return false, err
	}
	if err := validator.Validate(&ast.Query{EventType: engine.EventTypeGeneric, Expr: source}); err != nil {
		return false, err
	}
	target, err := parser.ParseExpression(optimized)
	if err != nil {
		return false, err
	}
	if err := validator.Validate(&ast.Query{EventType: engine.EventTypeGeneric, Expr: target}); err != nil {
		return false, err
	}
	optimizedExpr := optimizer.OptimizeExpr(source, optimizer.Options{CaseInsensitive: true})
	return reflect.DeepEqual(optimizedExpr, target), nil
}

// GoExpressionValues returns canonical runtime and folded values for a Go expression.
func GoExpressionValues(expression string, caseSensitive bool) (ExpressionResult, error) {
	parsed, err := parser.ParseExpression(expression)
	if err != nil {
		return ExpressionResult{}, err
	}
	if err := validator.Validate(&ast.Query{EventType: engine.EventTypeGeneric, Expr: parsed}); err != nil {
		return ExpressionResult{}, err
	}
	opts := optimizer.Options{CaseInsensitive: !caseSensitive}
	var engineOpts []engine.RuleOption
	if caseSensitive {
		engineOpts = append(engineOpts, engine.CaseSensitive())
	}
	runtimeValue, err := engine.EvalExpression(parsed, nil, engineOpts...)
	if err != nil {
		return ExpressionResult{}, err
	}
	foldedExpr := optimizer.OptimizeExpr(parsed, opts)
	if err := validator.Validate(&ast.Query{EventType: engine.EventTypeGeneric, Expr: foldedExpr}); err != nil {
		return ExpressionResult{}, err
	}
	foldedValue, ok := foldedLiteralValue(foldedExpr)
	if !ok {
		return ExpressionResult{}, fmt.Errorf("optimized expression did not fold to a literal: %T", foldedExpr)
	}
	runtimeRow, err := canonicalExpressionJSON(runtimeValue)
	if err != nil {
		return ExpressionResult{}, err
	}
	foldedRow, err := canonicalExpressionJSON(foldedValue)
	if err != nil {
		return ExpressionResult{}, err
	}
	return ExpressionResult{Expression: expression, Runtime: runtimeRow, Folded: foldedRow}, nil
}

func foldedLiteralValue(expr ast.Expr) (any, bool) {
	lit, ok := expr.(*ast.Literal)
	if !ok {
		return nil, false
	}
	switch lit.Kind {
	case ast.LiteralNull:
		return nil, true
	case ast.LiteralBool, ast.LiteralNumber, ast.LiteralString:
		return lit.Value, true
	default:
		return nil, false
	}
}

func canonicalExpressionJSON(value any) (string, error) {
	switch v := value.(type) {
	case ast.Num:
		if v.IsInt {
			return strconv.FormatInt(v.I, 10), nil
		}
		text := strconv.FormatFloat(v.F, 'g', -1, 64)
		if !strings.ContainsAny(text, ".eE") {
			text += ".0"
		}
		return text, nil
	default:
		return canonicalJSON(value)
	}
}

// PythonExpressionEquivalent reports Python AST equality for two expressions.
func PythonExpressionEquivalent(ctx context.Context, pythonRepo string, expression string, alternate string) (bool, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]any{"expression": expression, "alternate": alternate}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	script := `
import json, sys
from eql import parse_expression
from eql.parser import skip_optimizations

payload = json.load(sys.stdin)
with skip_optimizations:
    source = parse_expression(payload["expression"])
    alternate = parse_expression(payload["alternate"])
print(json.dumps({"equal": source == alternate}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("python expression equivalence oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var result struct {
		Equal bool `json:"equal"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return false, err
	}
	return result.Equal, nil
}

// PythonExpressionOptimized reports whether Python optimizer produces optimized.
func PythonExpressionOptimized(ctx context.Context, pythonRepo string, expression string, optimized string) (bool, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]any{"expression": expression, "optimized": optimized}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	script := `
import json, sys
from eql import parse_expression
from eql.parser import skip_optimizations

payload = json.load(sys.stdin)
with skip_optimizations:
    source = parse_expression(payload["expression"])
    optimized = parse_expression(payload["optimized"])
print(json.dumps({"equal": source.optimize(recursive=True) == optimized}, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("python expression optimizer oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var result struct {
		Equal bool `json:"equal"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return false, err
	}
	return result.Equal, nil
}

// PythonExpressionValues returns canonical runtime and folded values from Python EQL.
func PythonExpressionValues(ctx context.Context, pythonRepo string, expression string, caseSensitive bool) (ExpressionResult, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]any{"expression": expression, "case_sensitive": caseSensitive}
	body, err := json.Marshal(payload)
	if err != nil {
		return ExpressionResult{}, err
	}
	script := `
import contextlib, json, sys
import eql
from eql import PythonEngine, parse_expression
from eql.parser import skip_optimizations

payload = json.load(sys.stdin)
prev = eql.utils.CASE_INSENSITIVE
try:
    eql.utils.CASE_INSENSITIVE = not payload["case_sensitive"]
    with skip_optimizations:
        parsed = parse_expression(payload["expression"])
    runtime = PythonEngine().convert(parsed)(None)
    folded = parsed.fold()
    print(json.dumps({"runtime": runtime, "folded": folded}, sort_keys=True, separators=(",", ":")))
finally:
    eql.utils.CASE_INSENSITIVE = prev
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ExpressionResult{}, fmt.Errorf("python expression oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	var result struct {
		Runtime json.RawMessage `json:"runtime"`
		Folded  json.RawMessage `json:"folded"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &result); err != nil {
		return ExpressionResult{}, err
	}
	return ExpressionResult{
		Expression: expression,
		Runtime:    string(result.Runtime),
		Folded:     string(result.Folded),
	}, nil
}
