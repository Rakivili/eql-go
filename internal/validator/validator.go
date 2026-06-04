package validator

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/diagnostic"
	"github.com/Rakivili/eql-go/internal/pycompat"
)

type functionSpec struct {
	minArgs int
	maxArgs int
}

const variadicArgs = -1

var functionSpecs = map[string]functionSpec{
	"length":         {minArgs: 1, maxArgs: 1},
	"wildcard":       {minArgs: 2, maxArgs: variadicArgs},
	"startsWith":     {minArgs: 2, maxArgs: 2},
	"endsWith":       {minArgs: 2, maxArgs: 2},
	"stringContains": {minArgs: 2, maxArgs: 2},
	"match":          {minArgs: 2, maxArgs: variadicArgs},
	"matchLite":      {minArgs: 2, maxArgs: variadicArgs},
	"string":         {minArgs: 1, maxArgs: 1},
	"number":         {minArgs: 1, maxArgs: 2},
	"concat":         {minArgs: 1, maxArgs: variadicArgs},
	"add":            {minArgs: 2, maxArgs: 2},
	"subtract":       {minArgs: 2, maxArgs: 2},
	"multiply":       {minArgs: 2, maxArgs: 2},
	"divide":         {minArgs: 2, maxArgs: 2},
	"modulo":         {minArgs: 2, maxArgs: 2},
	"arrayContains":  {minArgs: 2, maxArgs: variadicArgs},
	"arraySearch":    {minArgs: 3, maxArgs: 3},
	"arrayCount":     {minArgs: 3, maxArgs: 3},
	"safe":           {minArgs: 1, maxArgs: 1},
	"indexOf":        {minArgs: 2, maxArgs: 3},
	"substring":      {minArgs: 2, maxArgs: 3},
	"between":        {minArgs: 3, maxArgs: 4},
	"cidrMatch":      {minArgs: 2, maxArgs: variadicArgs},
}

// Validate performs compile-time semantic checks that the MVP parser cannot
// express without a full schema/type system.
func Validate(q *ast.Query) error {
	if q == nil {
		return nil
	}
	if len(q.Sequence) > 0 {
		hasNegated := false
		stageByCount := -1
		for i, part := range q.Sequence {
			if i == 0 && part.HasFork {
				return diagnostic.Semantic("sequence fork is not allowed on first event query")
			}
			if part.Negated {
				hasNegated = true
			}
			if err := validateExpr(part.Expr); err != nil {
				return err
			}
			for _, by := range part.By {
				if err := validateExpr(by); err != nil {
					return err
				}
			}
			if len(part.By) > 0 {
				if stageByCount < 0 {
					stageByCount = len(part.By)
				} else if len(part.By) != stageByCount {
					return diagnostic.Semantic("sequence stage by argument count must match across event queries")
				}
			}
		}
		if stageByCount > 0 {
			for _, part := range q.Sequence {
				if len(part.By) == 0 {
					return diagnostic.Semantic("sequence stage by must be present on every event query")
				}
			}
		}
		if hasNegated && !q.HasMaxSpan {
			return diagnostic.Semantic("negative subquery used without maxspan")
		}
		for _, by := range q.SequenceBy {
			if err := validateExpr(by); err != nil {
				return err
			}
		}
		if q.SequenceUntil != nil {
			if err := validateExpr(q.SequenceUntil.Expr); err != nil {
				return err
			}
			for _, by := range q.SequenceUntil.By {
				if err := validateExpr(by); err != nil {
					return err
				}
			}
			if stageByCount > 0 {
				if len(q.SequenceUntil.By) == 0 {
					return diagnostic.Semantic("sequence until by must be present when event queries use stage by")
				}
				if len(q.SequenceUntil.By) != stageByCount {
					return diagnostic.Semantic("sequence until by argument count must match event queries")
				}
			} else if len(q.SequenceUntil.By) > 0 {
				return diagnostic.Semantic("sequence until by argument count must match event queries")
			}
		}
	} else if len(q.Sample) > 0 {
		if len(q.Sample) < 2 {
			return diagnostic.Semantic("sample expects at least two event queries")
		}
		stageByCount := -1
		for i, part := range q.Sample {
			if i == 0 && part.HasFork {
				return diagnostic.Semantic("sample fork is not allowed on first event query")
			}
			if err := validateExpr(part.Expr); err != nil {
				return err
			}
			for _, by := range part.By {
				if err := validateExpr(by); err != nil {
					return err
				}
			}
			if len(part.By) > 0 {
				if stageByCount < 0 {
					stageByCount = len(part.By)
				} else if len(part.By) != stageByCount {
					return diagnostic.Semantic("sample stage by argument count must match across event queries")
				}
			}
		}
		if stageByCount > 0 {
			for _, part := range q.Sample {
				if len(part.By) == 0 {
					return diagnostic.Semantic("sample stage by must be present on every event query")
				}
			}
		}
		for _, by := range q.SampleBy {
			if err := validateExpr(by); err != nil {
				return err
			}
		}
	} else if len(q.Join) > 0 {
		if len(q.Join) < 2 {
			return diagnostic.Semantic("join expects at least two event queries")
		}
		stageByCount := -1
		for _, part := range q.Join {
			if part.HasFork {
				return diagnostic.Semantic("join fork is not supported")
			}
			if err := validateExpr(part.Expr); err != nil {
				return err
			}
			for _, by := range part.By {
				if err := validateExpr(by); err != nil {
					return err
				}
			}
			if len(part.By) > 0 {
				if stageByCount < 0 {
					stageByCount = len(part.By)
				} else if len(part.By) != stageByCount {
					return diagnostic.Semantic("join stage by argument count must match across event queries")
				}
			}
		}
		if stageByCount > 0 {
			for _, part := range q.Join {
				if len(part.By) == 0 {
					return diagnostic.Semantic("join stage by must be present on every event query")
				}
			}
		}
		for _, by := range q.JoinBy {
			if err := validateExpr(by); err != nil {
				return err
			}
		}
		if q.JoinUntil != nil {
			if q.JoinUntil.HasFork {
				return diagnostic.Semantic("join fork is not supported")
			}
			if err := validateExpr(q.JoinUntil.Expr); err != nil {
				return err
			}
			for _, by := range q.JoinUntil.By {
				if err := validateExpr(by); err != nil {
					return err
				}
			}
			if stageByCount > 0 {
				if len(q.JoinUntil.By) == 0 {
					return diagnostic.Semantic("join until by must be present when event queries use stage by")
				}
				if len(q.JoinUntil.By) != stageByCount {
					return diagnostic.Semantic("join until by argument count must match event queries")
				}
			} else if len(q.JoinUntil.By) > 0 {
				return diagnostic.Semantic("join until by argument count must match event queries")
			}
		}
	} else {
		if err := validateExpr(q.Expr); err != nil {
			return err
		}
	}
	for _, pipe := range q.Pipes {
		if err := validatePipe(pipe); err != nil {
			return err
		}
	}
	return nil
}

// ValidateQuery performs full query validation, including the top-level where
// expression type. Expression conformance helpers use Validate directly so
// folded scalar expressions can still be checked outside a query context.
func ValidateQuery(q *ast.Query) error {
	if err := Validate(q); err != nil {
		return err
	}
	if q == nil {
		return nil
	}
	if len(q.Sequence) > 0 {
		for _, part := range q.Sequence {
			if err := validateWhereExpr(part.Expr); err != nil {
				return err
			}
		}
		if q.SequenceUntil != nil {
			if err := validateWhereExpr(q.SequenceUntil.Expr); err != nil {
				return err
			}
		}
		return nil
	}
	if len(q.Sample) > 0 {
		for _, part := range q.Sample {
			if err := validateWhereExpr(part.Expr); err != nil {
				return err
			}
		}
		return nil
	}
	if len(q.Join) > 0 {
		for _, part := range q.Join {
			if err := validateWhereExpr(part.Expr); err != nil {
				return err
			}
		}
		if q.JoinUntil != nil {
			if err := validateWhereExpr(q.JoinUntil.Expr); err != nil {
				return err
			}
		}
		return nil
	}
	return validateWhereExpr(q.Expr)
}

func validateWhereExpr(expr ast.Expr) error {
	return validateBooleanExpr(expr, "expected")
}

func validateExpr(expr ast.Expr) error {
	switch n := expr.(type) {
	case *ast.Comparison:
		if err := validateExpr(n.Left); err != nil {
			return err
		}
		if err := validateExpr(n.Right); err != nil {
			return err
		}
		if err := validateOrderedComparison(n); err != nil {
			return err
		}
		return diagnostic.AttachNode(validateComparisonLiteralTypes(n), n)
	case *ast.IsNull:
		return validateExpr(n.Expr)
	case *ast.IsNotNull:
		return validateExpr(n.Expr)
	case *ast.MathOperation:
		if err := validateExpr(n.Left); err != nil {
			return err
		}
		if err := validateExpr(n.Right); err != nil {
			return err
		}
		return validateMathRightOperand(n)
	case *ast.InSet:
		if err := validateExpr(n.Expr); err != nil {
			return err
		}
		for _, item := range n.Values {
			if err := validateExpr(item); err != nil {
				return err
			}
			if err := validateInSetLiteralTypes(n.Expr, item); err != nil {
				return err
			}
		}
	case *ast.Logical:
		for _, term := range n.Terms {
			if err := validateExpr(term); err != nil {
				return err
			}
			if err := validateBooleanExpr(term, "expected"); err != nil {
				return err
			}
		}
	case *ast.Not:
		if err := validateExpr(n.Term); err != nil {
			return err
		}
		return validateBooleanExpr(n.Term, "expected")
	case *ast.FunctionCall:
		return validateFunctionCall(n)
	case *ast.NamedSubquery:
		if n.QueryType != "event" && n.QueryType != "child" && n.QueryType != "descendant" {
			return diagnostic.Semanticf("%s of is not supported in current feature set", n.QueryType)
		}
		if err := validateExpr(n.Query.Expr); err != nil {
			return err
		}
		return validateWhereExpr(n.Query.Expr)
	}
	return nil
}

type staticType string

const (
	staticUnknown staticType = "unknown"
	staticNull    staticType = "null"
	staticBoolean staticType = "boolean"
	staticNumber  staticType = "number"
	staticString  staticType = "string"
)

func validateBooleanExpr(expr ast.Expr, prefix string) error {
	typ := staticExprType(expr)
	if typ == staticBoolean || typ == staticNull || typ == staticUnknown {
		return nil
	}
	return diagnostic.TypeMismatchf("%s boolean not %s", prefix, typ).WithNode(expr)
}

func validateOrderedComparison(cmp *ast.Comparison) error {
	if cmp.Op == "==" || cmp.Op == "!=" {
		return nil
	}
	left := staticExprType(cmp.Left)
	right := staticExprType(cmp.Right)
	if left != staticBoolean && right != staticBoolean {
		return nil
	}
	return comparisonStaticTypeError(left, right).WithNode(cmp)
}

func validateMathRightOperand(math *ast.MathOperation) error {
	right := staticExprType(math.Right)
	if right == staticUnknown || right == staticNull || right == staticNumber {
		return nil
	}
	return diagnostic.TypeMismatchf("math right operand expected number not %s", right).WithNode(math.Right)
}

func validateInSetLiteralTypes(left ast.Expr, right ast.Expr) error {
	leftType := staticExprType(left)
	rightType := staticExprType(right)
	if comparableStaticTypes(leftType, rightType) {
		return nil
	}
	return comparisonStaticTypeError(leftType, rightType).WithNode(right)
}

func comparableStaticTypes(left staticType, right staticType) bool {
	if left == staticUnknown || right == staticUnknown {
		return true
	}
	if left == staticNull || right == staticNull {
		return true
	}
	return left == right
}

func comparisonStaticTypeError(left staticType, right staticType) *diagnostic.Error {
	return diagnostic.TypeMismatchf("invalid comparison of %s to %s", left, right)
}

func staticExprType(expr ast.Expr) staticType {
	switch n := expr.(type) {
	case *ast.Literal:
		return staticLiteralType(n.Kind)
	case *ast.Comparison, *ast.IsNull, *ast.IsNotNull, *ast.InSet, *ast.Logical, *ast.Not, *ast.NamedSubquery:
		return staticBoolean
	case *ast.MathOperation:
		return staticNumber
	case *ast.FunctionCall:
		return staticFunctionReturnType(n.Name)
	default:
		return staticUnknown
	}
}

func staticLiteralType(kind ast.LiteralKind) staticType {
	switch kind {
	case ast.LiteralNull:
		return staticNull
	case ast.LiteralBool:
		return staticBoolean
	case ast.LiteralNumber:
		return staticNumber
	case ast.LiteralString:
		return staticString
	default:
		return staticUnknown
	}
}

func staticFunctionReturnType(name string) staticType {
	switch name {
	case "wildcard", "startsWith", "endsWith", "stringContains", "match", "matchLite", "arrayContains", "arraySearch", "cidrMatch":
		return staticBoolean
	case "length", "number", "add", "subtract", "multiply", "divide", "modulo", "arrayCount", "indexOf":
		return staticNumber
	case "string", "concat", "substring", "between":
		return staticString
	default:
		return staticUnknown
	}
}

func validateFunctionCall(call *ast.FunctionCall) error {
	if err := validateFunctionSignature(call); err != nil {
		return err
	}
	rewriteLegacyMatchCall(call)
	if err := validateFunctionLiteralTypes(call); err != nil {
		return err
	}
	switch call.Name {
	case "cidrMatch":
		if err := validateCidrMatch(call); err != nil {
			return err
		}
	case "arraySearch", "arrayCount":
		if err := validateDynamicArrayFunction(call); err != nil {
			return err
		}
	}
	for _, arg := range call.Args {
		if err := validateExpr(arg); err != nil {
			return err
		}
	}
	return nil
}

func rewriteLegacyMatchCall(call *ast.FunctionCall) {
	if call.Name != "match" && call.Name != "matchLite" {
		return
	}
	if len(call.Args) != 2 {
		return
	}
	first, ok := call.Args[0].(*ast.Literal)
	if !ok || first.Kind != ast.LiteralString {
		return
	}
	if _, isLiteral := call.Args[1].(*ast.Literal); isLiteral {
		return
	}
	call.Args[0], call.Args[1] = call.Args[1], call.Args[0]
}

func validateFunctionSignature(call *ast.FunctionCall) error {
	spec, ok := functionSpecs[call.Name]
	if !ok {
		return diagnostic.Semanticf("unknown function %s", call.Name).WithNode(call)
	}
	got := len(call.Args)
	if got < spec.minArgs || (spec.maxArgs != variadicArgs && got > spec.maxArgs) {
		return functionArityError(call.Name, spec, got).WithNode(call)
	}
	return nil
}

func validateFunctionLiteralTypes(call *ast.FunctionCall) error {
	switch call.Name {
	case "length":
		return validateStringLiteralArg(call, 0, true)
	case "wildcard":
		if err := validateStringLiteralArg(call, 0, true); err != nil {
			return err
		}
		for i := 1; i < len(call.Args); i++ {
			if err := validateRequiredStringLiteralArg(call, i, false); err != nil {
				return err
			}
		}
	case "startsWith", "endsWith", "stringContains":
		for i := range call.Args {
			if err := validateStringLiteralArg(call, i, true); err != nil {
				return err
			}
		}
	case "match", "matchLite":
		if err := validateStringLiteralArg(call, 0, true); err != nil {
			return err
		}
		for i := 1; i < len(call.Args); i++ {
			if err := validateRequiredStringLiteralArg(call, i, true); err != nil {
				return err
			}
			if err := validateRegexLiteralArg(call, i); err != nil {
				return err
			}
		}
	case "number":
		if err := validateStringLiteralArg(call, 0, true); err != nil {
			return err
		}
		if len(call.Args) == 2 {
			if err := validateNumberBaseLiteralArg(call, 1); err != nil {
				return err
			}
		}
		return validateNumberLiteralValue(call)
	case "add", "subtract", "multiply", "divide", "modulo":
		for i := range call.Args {
			if err := validateNumberLiteralArg(call, i, true); err != nil {
				return err
			}
		}
	case "arrayContains":
		return validateArrayLiteralArg(call, 0, true)
	case "indexOf":
		if err := validateStringLiteralArg(call, 0, true); err != nil {
			return err
		}
		if err := validateStringLiteralArg(call, 1, true); err != nil {
			return err
		}
		if len(call.Args) == 3 {
			return validateIntegerLiteralArg(call, 2, true)
		}
	case "substring":
		if err := validateStringLiteralArg(call, 0, true); err != nil {
			return err
		}
		if err := validateIntegerLiteralArg(call, 1, true); err != nil {
			return err
		}
		if len(call.Args) == 3 {
			return validateIntegerLiteralArg(call, 2, true)
		}
	case "between":
		for i := 0; i < 3; i++ {
			if err := validateStringLiteralArg(call, i, true); err != nil {
				return err
			}
		}
		if len(call.Args) == 4 {
			return validateBoolLiteralArg(call, 3, true)
		}
	case "cidrMatch":
		return validateStringLiteralArg(call, 0, true)
	}
	return nil
}

func functionArityError(name string, spec functionSpec, got int) *diagnostic.Error {
	switch {
	case spec.maxArgs == variadicArgs:
		return diagnostic.Semanticf("%s expects at least %d %s, got %d", name, spec.minArgs, argumentWord(spec.minArgs), got)
	case spec.minArgs == spec.maxArgs:
		return diagnostic.Semanticf("%s expects %d %s, got %d", name, spec.minArgs, argumentWord(spec.minArgs), got)
	default:
		return diagnostic.Semanticf("%s expects %d or %d arguments, got %d", name, spec.minArgs, spec.maxArgs, got)
	}
}

func argumentWord(n int) string {
	if n == 1 {
		return "argument"
	}
	return "arguments"
}

func validateStringLiteralArg(call *ast.FunctionCall, index int, allowNull bool) error {
	return validateLiteralArg(call, index, allowNull, "string", func(lit *ast.Literal) bool {
		return lit.Kind == ast.LiteralString
	})
}

func validateRequiredStringLiteralArg(call *ast.FunctionCall, index int, allowNull bool) error {
	lit, ok := call.Args[index].(*ast.Literal)
	if !ok {
		return diagnostic.TypeMismatchf("%s argument %d must be a string literal", call.Name, index+1).WithNode(call.Args[index])
	}
	if lit.Kind == ast.LiteralNull && allowNull {
		return nil
	}
	if lit.Kind != ast.LiteralString {
		return diagnostic.AttachNode(literalArgError(call, index, "string"), lit)
	}
	return nil
}

func validateRegexLiteralArg(call *ast.FunctionCall, index int) error {
	lit, ok := call.Args[index].(*ast.Literal)
	if !ok || lit.Kind == ast.LiteralNull {
		return nil
	}
	pattern, ok := lit.Value.(string)
	if !ok {
		return nil
	}
	if _, err := pycompat.CompileRegex(pattern, true); err != nil {
		return diagnostic.TypeMismatchf("%s argument %d is not a valid regular expression: %v", call.Name, index+1, err)
	}
	return nil
}

func validateNumberLiteralArg(call *ast.FunctionCall, index int, allowNull bool) error {
	return validateLiteralArg(call, index, allowNull, "number", func(lit *ast.Literal) bool {
		return lit.Kind == ast.LiteralNumber
	})
}

func validateIntegerLiteralArg(call *ast.FunctionCall, index int, allowNull bool) error {
	return validateLiteralArg(call, index, allowNull, "integer", func(lit *ast.Literal) bool {
		num, ok := lit.Value.(ast.Num)
		return lit.Kind == ast.LiteralNumber && ok && num.IsInt
	})
}

func validateBoolLiteralArg(call *ast.FunctionCall, index int, allowNull bool) error {
	return validateLiteralArg(call, index, allowNull, "boolean", func(lit *ast.Literal) bool {
		return lit.Kind == ast.LiteralBool
	})
}

func validateArrayLiteralArg(call *ast.FunctionCall, index int, allowNull bool) error {
	return validateLiteralArg(call, index, allowNull, "array", func(*ast.Literal) bool {
		return false
	})
}

func validateNumberBaseLiteralArg(call *ast.FunctionCall, index int) error {
	lit, ok := call.Args[index].(*ast.Literal)
	if !ok {
		return nil
	}
	if lit.Kind == ast.LiteralNull {
		return nil
	}
	num, ok := lit.Value.(ast.Num)
	if lit.Kind != ast.LiteralNumber || !ok || !num.IsInt {
		return literalArgError(call, index, "integer base")
	}
	if num.I != 0 && (num.I < 2 || num.I > 36) {
		return diagnostic.TypeMismatchf("%s argument %d must be integer base 0 or 2 through 36", call.Name, index+1)
	}
	return nil
}

func validateNumberLiteralValue(call *ast.FunctionCall) error {
	lit, ok := call.Args[0].(*ast.Literal)
	if !ok || lit.Kind == ast.LiteralNull {
		return nil
	}
	source, ok := lit.Value.(string)
	if !ok {
		return nil
	}
	base := int64(10)
	explicitBase := false
	if len(call.Args) == 2 {
		baseLit, ok := call.Args[1].(*ast.Literal)
		if !ok {
			return nil
		}
		if baseLit.Kind != ast.LiteralNull {
			num, ok := baseLit.Value.(ast.Num)
			if !ok || !num.IsInt {
				return nil
			}
			base = num.I
			explicitBase = true
		}
	}
	if err := validateNumberParse(source, base, explicitBase); err != nil {
		return diagnostic.TypeMismatchf("number literal is invalid: %v", err)
	}
	return nil
}

func validateNumberParse(source string, base int64, explicitBase bool) error {
	if base < 0 || base == 1 || base > 36 {
		return nil
	}
	parseBase := base
	if parseBase == 0 {
		parseBase = 10
	}
	if strings.Count(source, ".") == 1 && (!explicitBase || base == 10) {
		_, err := strconv.ParseFloat(source, 64)
		return err
	}
	if strings.HasPrefix(source, "0x") && (!explicitBase || base == 16) {
		_, err := strconv.ParseInt(source[2:], 16, 64)
		return err
	}
	if isSignedDigits(source) {
		_, err := strconv.ParseInt(source, int(parseBase), 64)
		return err
	}
	return nil
}

func validateLiteralArg(call *ast.FunctionCall, index int, allowNull bool, expected string, ok func(*ast.Literal) bool) error {
	lit, isLiteral := call.Args[index].(*ast.Literal)
	if !isLiteral {
		return nil
	}
	if lit.Kind == ast.LiteralNull && allowNull {
		return nil
	}
	if ok(lit) {
		return nil
	}
	return diagnostic.AttachNode(literalArgError(call, index, expected), lit)
}

func literalArgError(call *ast.FunctionCall, index int, expected string) error {
	return diagnostic.TypeMismatchf("%s argument %d must be %s literal", call.Name, index+1, expected)
}

func validateComparisonLiteralTypes(cmp *ast.Comparison) error {
	left, leftOK := cmp.Left.(*ast.Literal)
	right, rightOK := cmp.Right.(*ast.Literal)
	if !leftOK || !rightOK {
		return nil
	}
	if cmp.Op == "==" || cmp.Op == "!=" {
		if comparableLiteralKinds(left.Kind, right.Kind) {
			return nil
		}
		return comparisonLiteralError(left.Kind, right.Kind)
	}
	if orderedLiteralKinds(left.Kind, right.Kind) {
		return nil
	}
	return comparisonLiteralError(left.Kind, right.Kind)
}

func comparableLiteralKinds(left ast.LiteralKind, right ast.LiteralKind) bool {
	if left == ast.LiteralNull || right == ast.LiteralNull {
		return true
	}
	return orderedLiteralKinds(left, right) || (left == ast.LiteralBool && right == ast.LiteralBool)
}

func orderedLiteralKinds(left ast.LiteralKind, right ast.LiteralKind) bool {
	if left == ast.LiteralNull && right != ast.LiteralBool {
		return true
	}
	if right == ast.LiteralNull && left != ast.LiteralBool {
		return true
	}
	if left == ast.LiteralNumber && right == ast.LiteralNumber {
		return true
	}
	return left == ast.LiteralString && right == ast.LiteralString
}

func comparisonLiteralError(left ast.LiteralKind, right ast.LiteralKind) error {
	return diagnostic.TypeMismatchf("invalid comparison of %s to %s", literalKindName(left), literalKindName(right))
}

func literalKindName(kind ast.LiteralKind) string {
	switch kind {
	case ast.LiteralNull:
		return "null"
	case ast.LiteralBool:
		return "boolean"
	case ast.LiteralString:
		return "string"
	case ast.LiteralNumber:
		return "number"
	default:
		return "unknown"
	}
}

func validatePipe(pipe ast.Pipe) error {
	switch pipe.Name {
	case "filter":
		if len(pipe.Args) != 1 {
			return diagnostic.Semanticf("filter expects 1 argument, got %d", len(pipe.Args))
		}
		return validateExpr(pipe.Args[0])
	case "head", "tail":
		if len(pipe.Args) > 1 {
			return diagnostic.Semanticf("%s expects 0 or 1 arguments, got %d", pipe.Name, len(pipe.Args))
		}
		if len(pipe.Args) == 1 {
			value, ok := literalInt(pipe.Args[0])
			if !ok || value <= 0 {
				return diagnostic.TypeMismatchf("%s argument must be a positive integer literal", pipe.Name).WithNode(pipe.Args[0])
			}
		}
	case "count":
		return validateDynamicPipeArgs(pipe)
	case "sort", "unique", "unique_count":
		if len(pipe.Args) == 0 {
			return diagnostic.Semanticf("%s expects at least 1 argument, got 0", pipe.Name)
		}
		return validateDynamicPipeArgs(pipe)
	default:
		return diagnostic.Semanticf("%s pipe is not supported", pipe.Name)
	}
	return nil
}

func validateDynamicPipeArgs(pipe ast.Pipe) error {
	for i, arg := range pipe.Args {
		if err := validateExpr(arg); err != nil {
			return err
		}
		if isLiteralFoldedExpr(arg) {
			return diagnostic.TypeMismatchf("%s argument %d must be dynamic", pipe.Name, i+1).WithNode(arg)
		}
	}
	return nil
}

func isLiteralFoldedExpr(expr ast.Expr) bool {
	switch n := expr.(type) {
	case *ast.Literal:
		return true
	case *ast.MathOperation:
		return isLiteralFoldedExpr(n.Left) && isLiteralFoldedExpr(n.Right)
	case *ast.Comparison:
		return isLiteralFoldedExpr(n.Left) && isLiteralFoldedExpr(n.Right)
	case *ast.IsNull:
		return isLiteralFoldedExpr(n.Expr)
	case *ast.IsNotNull:
		return isLiteralFoldedExpr(n.Expr)
	case *ast.InSet:
		if !isLiteralFoldedExpr(n.Expr) {
			return false
		}
		for _, value := range n.Values {
			if !isLiteralFoldedExpr(value) {
				return false
			}
		}
		return true
	case *ast.Logical:
		allLiteral := true
		for _, term := range n.Terms {
			if literalBoolValue(term, n.Op == "or") {
				return true
			}
			if !isLiteralFoldedExpr(term) {
				allLiteral = false
			}
		}
		return allLiteral
	case *ast.Not:
		return isLiteralFoldedExpr(n.Term)
	case *ast.FunctionCall:
		if !isFoldableFunctionForDynamicPipe(n.Name) {
			return false
		}
		for _, arg := range n.Args {
			if !isLiteralFoldedExpr(arg) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func literalBoolValue(expr ast.Expr, value bool) bool {
	lit, ok := expr.(*ast.Literal)
	return ok && lit.Kind == ast.LiteralBool && lit.Value == value
}

func isFoldableFunctionForDynamicPipe(name string) bool {
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

func literalInt(expr ast.Expr) (int64, bool) {
	literal, ok := expr.(*ast.Literal)
	if !ok || literal.Kind != ast.LiteralNumber {
		return 0, false
	}
	num, ok := literal.Value.(ast.Num)
	if !ok || !num.IsInt {
		return 0, false
	}
	return num.I, true
}

func validateDynamicArrayFunction(call *ast.FunctionCall) error {
	if len(call.Args) != 3 {
		return diagnostic.Semanticf("%s expects 3 arguments, got %d", call.Name, len(call.Args))
	}
	field, ok := call.Args[1].(*ast.Field)
	if !ok || field.Base == "" || len(field.Path) != 0 {
		return diagnostic.TypeMismatchf("%s argument 2 must be a variable name", call.Name).WithNode(call.Args[1])
	}
	return nil
}

func validateCidrMatch(call *ast.FunctionCall) error {
	if len(call.Args) < 2 {
		return diagnostic.Semanticf("cidrMatch expects at least 2 arguments, got %d", len(call.Args))
	}
	if literal, ok := call.Args[0].(*ast.Literal); ok && literal.Kind == ast.LiteralString {
		source, ok := literal.Value.(string)
		if !ok || !validIP(source) {
			return diagnostic.TypeMismatch("cidrMatch argument 1 is not a valid IP address").WithNode(call.Args[0])
		}
	}
	for pos, arg := range call.Args[1:] {
		literal, ok := arg.(*ast.Literal)
		if !ok || literal.Kind != ast.LiteralString {
			return diagnostic.TypeMismatchf("cidrMatch argument %d must be a string literal", pos+2).WithNode(arg)
		}
		cidr, ok := literal.Value.(string)
		if !ok || !validCIDR(cidr) {
			return diagnostic.TypeMismatchf("cidrMatch argument %d is not a valid CIDR pattern", pos+2).WithNode(literal)
		}
	}
	return nil
}

func validIP(source string) bool {
	_, err := netip.ParseAddr(source)
	return err == nil
}

func isSignedDigits(source string) bool {
	digits := strings.TrimLeft(source, "-+")
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validCIDR(cidr string) bool {
	text := strings.TrimSpace(cidr)
	if !strings.Contains(text, "/") {
		return false
	}
	_, err := netip.ParsePrefix(text)
	return err == nil
}
