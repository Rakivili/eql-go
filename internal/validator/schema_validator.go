package validator

import (
	"fmt"

	"github.com/Rakivili/eql-go/internal/ast"
	"github.com/Rakivili/eql-go/internal/diagnostic"
	schemapkg "github.com/Rakivili/eql-go/internal/schema"
	"github.com/Rakivili/eql-go/internal/types"
)

type schemaContext struct {
	schema       *schemapkg.Schema
	eventType    string
	eventSchemas []map[string]any
	vars         map[string]types.NodeInfo
	aliases      map[string]string
	opts         schemaValidationOptions
	enumFields   bool
}

type schemaValidationOptions struct {
	elasticEndpointSyntax  bool
	validateOptionalFields bool
	allowEnumFields        bool
	strictBooleans         bool
	nonNullableFields      bool
}

// SchemaValidationOption configures internal schema validation.
type SchemaValidationOption func(*schemaValidationOptions)

// SchemaElasticEndpointSyntax configures Endpoint-specific schema validation rules.
func SchemaElasticEndpointSyntax(enabled bool) SchemaValidationOption {
	return func(o *schemaValidationOptions) {
		o.elasticEndpointSyntax = enabled
	}
}

// SchemaValidateOptionalFields configures whether optional fields must exist in schema.
func SchemaValidateOptionalFields(validate bool) SchemaValidationOption {
	return func(o *schemaValidationOptions) {
		o.validateOptionalFields = validate
	}
}

// SchemaAllowEnumFields configures enum field rewriting from field.value to field == "value".
func SchemaAllowEnumFields(allow bool) SchemaValidationOption {
	return func(o *schemaValidationOptions) {
		o.allowEnumFields = allow
	}
}

// SchemaStrictBooleans configures whether conditions must be boolean under schema validation.
func SchemaStrictBooleans(strict bool) SchemaValidationOption {
	return func(o *schemaValidationOptions) {
		o.strictBooleans = strict
	}
}

// SchemaNonNullableFields configures whether fields and literals are treated as non-nullable.
func SchemaNonNullableFields(nonNullable bool) SchemaValidationOption {
	return func(o *schemaValidationOptions) {
		o.nonNullableFields = nonNullable
	}
}

type schemaFunctionSpec struct {
	args          []types.Expectation
	minArgs       int
	additional    types.Expectation
	returnType    types.TypeHint
	sometimesNull bool
	validate      func(*ast.FunctionCall, []types.NodeInfo) error
	description   string
}

var schemaFunctionSpecs = map[string]schemaFunctionSpec{
	"length": {
		args:       []types.Expectation{types.Expect(types.TypeString, types.TypeArray)},
		returnType: types.TypeNumeric,
	},
	"wildcard": {
		args:       []types.Expectation{types.TypeString.Expect(), types.TypeString.RequireLiteral().Expect()},
		additional: types.TypeString.RequireLiteral().Expect(),
		returnType: types.TypeBoolean,
	},
	"startsWith":     stringBoolFunctionSpec(),
	"endsWith":       stringBoolFunctionSpec(),
	"stringContains": stringBoolFunctionSpec(),
	"match": {
		args:       []types.Expectation{types.TypeString.Expect(), types.TypeString.RequireLiteral().Expect()},
		additional: types.TypeString.RequireLiteral().Expect(),
		returnType: types.TypeBoolean,
	},
	"matchLite": {
		args:       []types.Expectation{types.TypeString.Expect(), types.TypeString.RequireLiteral().Expect()},
		additional: types.TypeString.RequireLiteral().Expect(),
		returnType: types.TypeBoolean,
	},
	"string": {
		args:       []types.Expectation{types.Expect(types.PrimitiveHints()...)},
		returnType: types.TypeString,
	},
	"number": {
		args:          []types.Expectation{types.TypeString.Expect(), types.TypeNumeric.Expect()},
		minArgs:       1,
		returnType:    types.TypeNumeric,
		sometimesNull: true,
	},
	"concat": {
		minArgs:    1,
		additional: types.Expect(types.PrimitiveHints()...),
		returnType: types.TypeString,
	},
	"add":      mathFunctionSpec(),
	"subtract": mathFunctionSpec(),
	"multiply": mathFunctionSpec(),
	"divide":   mathFunctionSpec(),
	"modulo":   mathFunctionSpec(),
	"arrayContains": {
		args:       []types.Expectation{types.TypeArray.Expect(), types.Expect(types.PrimitiveHints()...)},
		additional: types.Expect(types.PrimitiveHints()...),
		returnType: types.TypeBoolean,
		validate:   validateArrayContainsSchema,
	},
	"arraySearch": {
		args:       []types.Expectation{types.TypeArray.Expect(), types.TypeVariable.Expect(), types.TypeBoolean.Expect()},
		returnType: types.TypeBoolean,
	},
	"arrayCount": {
		args:       []types.Expectation{types.TypeArray.Expect(), types.TypeVariable.Expect(), types.TypeBoolean.Expect()},
		returnType: types.TypeNumeric,
	},
	"safe": {
		args:       []types.Expectation{types.TypeUnknown.Expect()},
		returnType: types.TypeUnknown,
	},
	"indexOf": {
		args:          []types.Expectation{types.TypeString.Expect(), types.TypeString.Expect(), types.TypeNumeric.Expect()},
		minArgs:       2,
		returnType:    types.TypeNumeric,
		sometimesNull: true,
	},
	"substring": {
		args:       []types.Expectation{types.TypeString.Expect(), types.TypeNumeric.Expect(), types.TypeNumeric.Expect()},
		minArgs:    2,
		returnType: types.TypeString,
	},
	"between": {
		args:          []types.Expectation{types.TypeString.Expect(), types.TypeString.Expect(), types.TypeString.Expect(), types.TypeBoolean.Expect()},
		minArgs:       3,
		returnType:    types.TypeString,
		sometimesNull: true,
	},
	"cidrMatch": {
		args:       []types.Expectation{types.TypeString.Expect(), types.TypeString.RequireLiteral().Expect()},
		additional: types.TypeString.RequireLiteral().Expect(),
		returnType: types.TypeBoolean,
	},
}

// ValidateQuerySchema performs schema and type validation for a parsed query.
func ValidateQuerySchema(q *ast.Query, schema *schemapkg.Schema, opts ...SchemaValidationOption) error {
	if q == nil || schema == nil {
		return nil
	}
	cfg := schemaValidationOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	ctx, err := validateBaseQuerySchema(q, schema, cfg)
	if err != nil {
		return err
	}
	for i := range q.Pipes {
		next, err := validatePipeSchema(ctx, &q.Pipes[i])
		if err != nil {
			return err
		}
		ctx = next
	}
	return nil
}

func validateBaseQuerySchema(q *ast.Query, schema *schemapkg.Schema, opts schemaValidationOptions) (schemaContext, error) {
	if len(q.Sequence) > 0 {
		aliases := map[string]string{}
		for i := range q.Sequence {
			if err := validateEventQuerySchema(schema, &q.Sequence[i], opts, aliases); err != nil {
				return schemaContext{}, err
			}
			recordEventAlias(aliases, q.Sequence[i])
		}
		if q.SequenceUntil != nil {
			if err := validateEventQuerySchema(schema, q.SequenceUntil, opts, aliases); err != nil {
				return schemaContext{}, err
			}
		}
		return multiEventSchemaContext(schema, q.Sequence, opts), nil
	}
	if len(q.Sample) > 0 {
		aliases := map[string]string{}
		for i := range q.Sample {
			if err := validateEventQuerySchema(schema, &q.Sample[i], opts, aliases); err != nil {
				return schemaContext{}, err
			}
			recordEventAlias(aliases, q.Sample[i])
		}
		return multiEventSchemaContext(schema, q.Sample, opts), nil
	}
	if len(q.Join) > 0 {
		aliases := map[string]string{}
		for i := range q.Join {
			if err := validateEventQuerySchema(schema, &q.Join[i], opts, aliases); err != nil {
				return schemaContext{}, err
			}
			recordEventAlias(aliases, q.Join[i])
		}
		if q.JoinUntil != nil {
			if err := validateEventQuerySchema(schema, q.JoinUntil, opts, aliases); err != nil {
				return schemaContext{}, err
			}
		}
		return multiEventSchemaContext(schema, q.Join, opts), nil
	}
	query := ast.EventQuery{EventType: q.EventType, Expr: q.Expr}
	if err := validateEventQuerySchema(schema, &query, opts, nil); err != nil {
		return schemaContext{}, err
	}
	q.Expr = query.Expr
	return schemaContext{schema: schema, eventType: q.EventType, opts: opts}, nil
}

func recordEventAlias(aliases map[string]string, q ast.EventQuery) {
	if aliases != nil && q.Alias != "" {
		aliases[q.Alias] = q.EventType
	}
}

func validateEventQuerySchema(schema *schemapkg.Schema, q *ast.EventQuery, opts schemaValidationOptions, aliases map[string]string) error {
	if !schema.ValidateEventType(q.EventType) {
		return diagnostic.Schemaf("event type %s is not in schema", q.EventType)
	}
	ctx := schemaContext{schema: schema, eventType: q.EventType, aliases: aliases, opts: opts, enumFields: true}
	info, err := inferSchemaExpr(ctx, q.Expr)
	if err != nil {
		return err
	}
	q.Expr = info.Node
	if err := validateStrictBoolean(ctx, info, "where"); err != nil {
		return err
	}
	for i := range q.By {
		info, err := inferSchemaExpr(ctx, q.By[i])
		if err != nil {
			return err
		}
		q.By[i] = info.Node
	}
	return nil
}

func validatePipeSchema(ctx schemaContext, pipe *ast.Pipe) (schemaContext, error) {
	if pipe == nil {
		return ctx, nil
	}
	switch pipe.Name {
	case "filter":
		if len(pipe.Args) == 1 {
			info, err := inferSchemaExpr(ctx, pipe.Args[0])
			if err != nil {
				return schemaContext{}, err
			}
			pipe.Args[0] = info.Node
			if !info.Validate(types.Expect(types.PrimitiveHints()...)) {
				return schemaContext{}, diagnostic.TypeMismatchf("filter argument expected primitive not %s", info.Type())
			}
		}
		return ctx, nil
	case "head", "tail", "sort":
		if err := validatePipeArgumentsSchema(ctx, pipe); err != nil {
			return schemaContext{}, err
		}
		return ctx, nil
	case "unique":
		if err := validatePipeArgumentsSchema(ctx, pipe); err != nil {
			return schemaContext{}, err
		}
		return ctx, nil
	case "count":
		args, err := inferPipeArgumentTypes(ctx, pipe)
		if err != nil {
			return schemaContext{}, err
		}
		return countPipeSchemaContext(args, ctx.opts), nil
	case "unique_count":
		if err := validatePipeArgumentsSchema(ctx, pipe); err != nil {
			return schemaContext{}, err
		}
		return uniqueCountPipeSchemaContext(ctx), nil
	default:
		return ctx, nil
	}
}

func validatePipeArgumentsSchema(ctx schemaContext, pipe *ast.Pipe) error {
	_, err := inferPipeArgumentTypes(ctx, pipe)
	return err
}

func inferPipeArgumentTypes(ctx schemaContext, pipe *ast.Pipe) ([]types.NodeInfo, error) {
	args := make([]types.NodeInfo, 0, len(pipe.Args))
	for i, arg := range pipe.Args {
		info, err := inferSchemaExpr(ctx, arg)
		if err != nil {
			return nil, err
		}
		pipe.Args[i] = info.Node
		if !info.Validate(types.Expect(types.PrimitiveHints()...)) {
			return nil, diagnostic.TypeMismatchf("%s argument %d expected primitive not %s", pipe.Name, i+1, info.Type())
		}
		args = append(args, info)
	}
	return args, nil
}

func countPipeSchemaContext(args []types.NodeInfo, opts schemaValidationOptions) schemaContext {
	keySchema := any(string(types.TypeString))
	if len(args) == 1 {
		keySchema = string(args[0].Type())
	} else if len(args) > 1 {
		values := make([]any, 0, len(args))
		for _, arg := range args {
			values = append(values, string(arg.Type()))
		}
		keySchema = values
	}
	eventSchema := countFields()
	eventSchema["key"] = keySchema
	return contextFromEventSchema(schemapkg.EventTypeGeneric, eventSchema, opts)
}

func uniqueCountPipeSchemaContext(ctx schemaContext) schemaContext {
	if len(ctx.eventSchemas) > 0 {
		eventSchemas := cloneEventSchemas(ctx.eventSchemas)
		if len(eventSchemas[0]) == 0 {
			return contextFromEventSchemas(eventSchemas, ctx.opts)
		}
		for key, value := range countSummaryFields() {
			eventSchemas[0][key] = value
		}
		return contextFromEventSchemas(eventSchemas, ctx.opts)
	}
	eventSchema := cloneEventSchema(ctx.currentEventSchema())
	if len(eventSchema) == 0 {
		return contextFromEventSchema(ctx.eventType, eventSchema, ctx.opts)
	}
	for key, value := range countSummaryFields() {
		eventSchema[key] = value
	}
	return contextFromEventSchema(ctx.eventType, eventSchema, ctx.opts)
}

func multiEventSchemaContext(schema *schemapkg.Schema, queries []ast.EventQuery, opts schemaValidationOptions) schemaContext {
	eventSchemas := make([]map[string]any, 0, len(queries))
	for _, query := range queries {
		eventSchemas = append(eventSchemas, cloneEventSchema(schemaForEvent(schema, query.EventType)))
	}
	return contextFromEventSchemas(eventSchemas, opts)
}

func contextFromEventSchemas(eventSchemas []map[string]any, opts schemaValidationOptions) schemaContext {
	eventType := schemapkg.EventTypeGeneric
	current := map[string]any{}
	if len(eventSchemas) > 0 {
		current = cloneEventSchema(eventSchemas[0])
	}
	s, err := schemapkg.New(
		map[string]map[string]any{eventType: current},
		schemapkg.WithAllowGeneric(true),
		schemapkg.WithAllowAny(false),
	)
	if err != nil {
		return schemaContext{}
	}
	return schemaContext{schema: s, eventType: eventType, eventSchemas: eventSchemas, opts: opts}
}

func contextFromEventSchema(eventType string, eventSchema map[string]any, opts schemaValidationOptions) schemaContext {
	s, err := schemapkg.New(
		map[string]map[string]any{eventType: eventSchema},
		schemapkg.WithAllowGeneric(eventType == schemapkg.EventTypeGeneric),
		schemapkg.WithAllowAny(false),
	)
	if err != nil {
		return schemaContext{}
	}
	return schemaContext{schema: s, eventType: eventType, opts: opts}
}

func (ctx schemaContext) currentEventSchema() map[string]any {
	if len(ctx.eventSchemas) > 0 {
		return ctx.eventSchemas[0]
	}
	return schemaForEvent(ctx.schema, ctx.eventType)
}

func schemaForEvent(schema *schemapkg.Schema, eventType string) map[string]any {
	if schema == nil {
		return map[string]any{}
	}
	return schema.EventSchema(eventType)
}

func countFields() map[string]any {
	fields := countSummaryFields()
	fields["key"] = string(types.TypeString)
	return fields
}

func countSummaryFields() map[string]any {
	return map[string]any{
		"count":       string(types.TypeNumeric),
		"percent":     string(types.TypeNumeric),
		"total_hosts": string(types.TypeNumeric),
		"hosts":       []any{string(types.TypeString)},
	}
}

func cloneEventSchemas(eventSchemas []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(eventSchemas))
	for _, eventSchema := range eventSchemas {
		out = append(out, cloneEventSchema(eventSchema))
	}
	return out
}

func cloneEventSchema(eventSchema map[string]any) map[string]any {
	out := make(map[string]any, len(eventSchema))
	for key, value := range eventSchema {
		out[key] = cloneSchemaValue(value)
	}
	return out
}

func cloneSchemaValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneEventSchema(v)
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, cloneSchemaValue(item))
		}
		return out
	default:
		return v
	}
}

func (ctx schemaContext) defaultNullable() bool {
	return !ctx.opts.nonNullableFields
}

func (ctx schemaContext) nodeInfo(node ast.Expr, hint types.TypeHint, opts ...types.NodeOption) types.NodeInfo {
	return schemaNodeInfo(node, hint, ctx.defaultNullable(), opts...)
}

func schemaNodeInfo(node ast.Expr, hint types.TypeHint, nullable bool, opts ...types.NodeOption) types.NodeInfo {
	all := make([]types.NodeOption, 0, len(opts)+1)
	all = append(all, types.WithNullable(nullable))
	all = append(all, opts...)
	return types.NewNodeInfo(node, hint, all...)
}

func nullableFrom(infos ...types.NodeInfo) bool {
	for _, info := range infos {
		if info.IsNullable() {
			return true
		}
	}
	return false
}

func validateStrictBoolean(ctx schemaContext, info types.NodeInfo, context string) error {
	if !ctx.opts.strictBooleans || info.ValidateType(types.TypeBoolean.Expect()) {
		return nil
	}
	return diagnostic.TypeMismatchf("%s expected boolean not %s", context, info.Type())
}

func inferSchemaExpr(ctx schemaContext, expr ast.Expr) (types.NodeInfo, error) {
	switch n := expr.(type) {
	case *ast.Literal:
		return literalNodeInfo(ctx, n), nil
	case *ast.Field:
		return inferSchemaField(ctx, n)
	case *ast.Comparison:
		return inferSchemaComparison(ctx, n)
	case *ast.IsNull:
		return inferSchemaNullTest(ctx, n, n.Expr, func(expr ast.Expr) {
			n.Expr = expr
		})
	case *ast.IsNotNull:
		return inferSchemaNullTest(ctx, n, n.Expr, func(expr ast.Expr) {
			n.Expr = expr
		})
	case *ast.MathOperation:
		return inferSchemaMath(ctx, n)
	case *ast.InSet:
		return inferSchemaInSet(ctx, n)
	case *ast.Logical:
		terms := make([]types.NodeInfo, 0, len(n.Terms))
		for i, term := range n.Terms {
			info, err := inferSchemaExpr(ctx, term)
			if err != nil {
				return types.NodeInfo{}, err
			}
			n.Terms[i] = info.Node
			if err := validateStrictBoolean(ctx, info, "logical"); err != nil {
				return types.NodeInfo{}, err
			}
			terms = append(terms, info)
		}
		return schemaNodeInfo(expr, types.TypeBoolean, nullableFrom(terms...)), nil
	case *ast.Not:
		info, err := inferSchemaExpr(ctx, n.Term)
		if err != nil {
			return types.NodeInfo{}, err
		}
		n.Term = info.Node
		if err := validateStrictBoolean(ctx, info, "not"); err != nil {
			return types.NodeInfo{}, err
		}
		return schemaNodeInfo(expr, types.TypeBoolean, info.IsNullable()), nil
	case *ast.FunctionCall:
		return inferSchemaFunction(ctx, n)
	case *ast.NamedSubquery:
		if err := validateEventQuerySchema(ctx.schema, &n.Query, ctx.opts, ctx.aliases); err != nil {
			return types.NodeInfo{}, err
		}
		return ctx.nodeInfo(expr, types.TypeBoolean), nil
	default:
		return ctx.nodeInfo(expr, types.TypeUnknown), nil
	}
}

func literalNodeInfo(ctx schemaContext, lit *ast.Literal) types.NodeInfo {
	switch lit.Kind {
	case ast.LiteralBool:
		return ctx.nodeInfo(lit, types.TypeBoolean)
	case ast.LiteralNumber:
		return ctx.nodeInfo(lit, types.TypeNumeric)
	case ast.LiteralString:
		return ctx.nodeInfo(lit, types.TypeString)
	case ast.LiteralNull:
		return ctx.nodeInfo(lit, types.TypeNull)
	default:
		return ctx.nodeInfo(lit, types.TypeUnknown)
	}
}

func inferSchemaField(ctx schemaContext, field *ast.Field) (types.NodeInfo, error) {
	if variable, ok := ctx.vars[field.Base]; ok && ctx.variableReferenceAllowed(field) {
		return inferSchemaVariableField(ctx, field, variable)
	}
	if field.Base == "events" && len(field.Path) > 0 && field.Path[0].IsIdx {
		return inferSchemaEventArrayField(ctx, field)
	}
	if field.Scoped {
		return ctx.nodeInfo(field, types.TypeUnknown), nil
	}
	if aliasEventType, ok := ctx.aliasEventType(field); ok {
		return inferSchemaAliasField(ctx, field, aliasEventType)
	}
	hint, fieldSchema, ok := ctx.schema.GetEventTypeHint(ctx.eventType, schemaPathWithBase(field))
	if !ok {
		if info, rewritten, err := inferSchemaEnumField(ctx, field, ctx.eventType); rewritten || err != nil {
			return info, err
		}
		if field.Optional && !ctx.opts.validateOptionalFields {
			return ctx.nodeInfo(field, types.TypeUnknown), nil
		}
		return types.NodeInfo{}, diagnostic.Schemaf("field %s is not in schema for %s", fieldName(field), ctx.eventType).WithNode(field)
	}
	return ctx.nodeInfo(field, hint, types.WithSchema(fieldSchema)), nil
}

func (ctx schemaContext) variableReferenceAllowed(field *ast.Field) bool {
	return !ctx.opts.elasticEndpointSyntax || field.Scoped
}

func (ctx schemaContext) aliasEventType(field *ast.Field) (string, bool) {
	if !ctx.opts.elasticEndpointSyntax || len(field.Path) == 0 {
		return "", false
	}
	eventType, ok := ctx.aliases[field.Base]
	return eventType, ok
}

func inferSchemaAliasField(ctx schemaContext, field *ast.Field, eventType string) (types.NodeInfo, error) {
	hint, fieldSchema, ok := ctx.schema.GetEventTypeHint(eventType, schemaPath(field.Path))
	if !ok {
		aliasField, valid := aliasFieldForSchema(field)
		if valid {
			if info, rewritten, err := inferSchemaEnumField(ctx, aliasField, eventType); rewritten || err != nil {
				return info, err
			}
		}
		return types.NodeInfo{}, diagnostic.Schemaf("field %s is not in schema for alias %s", fieldName(field), field.Base).WithNode(field)
	}
	return ctx.nodeInfo(field, hint, types.WithSchema(fieldSchema)), nil
}

func inferSchemaEnumField(ctx schemaContext, field *ast.Field, eventType string) (types.NodeInfo, bool, error) {
	if !ctx.enumFields || !ctx.opts.allowEnumFields || len(field.Path) == 0 {
		return types.NodeInfo{}, false, nil
	}
	last := field.Path[len(field.Path)-1]
	if last.IsIdx {
		return types.NodeInfo{}, false, nil
	}
	baseField := &ast.Field{
		Base:     field.Base,
		Path:     clonePathParts(field.Path[:len(field.Path)-1]),
		Optional: field.Optional,
		Scoped:   field.Scoped,
	}
	baseHint, _, ok := ctx.schema.GetEventTypeHint(eventType, schemaPathWithBase(baseField))
	if !ok || baseHint != types.TypeString {
		return types.NodeInfo{}, false, nil
	}
	comparison := &ast.Comparison{
		Left: baseField,
		Op:   "==",
		Right: &ast.Literal{
			Kind:  ast.LiteralString,
			Value: last.Name,
		},
	}
	return ctx.nodeInfo(comparison, types.TypeBoolean, types.WithSource(field)), true, nil
}

func aliasFieldForSchema(field *ast.Field) (*ast.Field, bool) {
	if field == nil || len(field.Path) == 0 || field.Path[0].IsIdx {
		return nil, false
	}
	return &ast.Field{
		Base: field.Path[0].Name,
		Path: clonePathParts(field.Path[1:]),
	}, true
}

func inferSchemaEventArrayField(ctx schemaContext, field *ast.Field) (types.NodeInfo, error) {
	index := field.Path[0].Index
	if index < 0 || index >= len(ctx.eventSchemas) {
		return types.NodeInfo{}, diagnostic.Schemaf("field %s is not in pipe event schema", fieldName(field)).WithNode(field)
	}
	eventSchema := ctx.eventSchemas[index]
	if len(field.Path) == 1 {
		return ctx.nodeInfo(field, types.TypeObject, types.WithSchema(eventSchema)), nil
	}
	hint, nestedSchema, ok := schemapkg.GetRelativePath(eventSchema, schemaPath(field.Path[1:]))
	if !ok {
		return types.NodeInfo{}, diagnostic.Schemaf("field %s is not in pipe event schema", fieldName(field)).WithNode(field)
	}
	return ctx.nodeInfo(field, hint, types.WithSchema(nestedSchema)), nil
}

func inferSchemaVariableField(ctx schemaContext, field *ast.Field, variable types.NodeInfo) (types.NodeInfo, error) {
	if len(field.Path) == 0 {
		return variable, nil
	}
	if variable.Schema != nil {
		hint, nestedSchema, ok := schemapkg.GetRelativePath(variable.Schema, schemaPath(field.Path))
		if ok {
			return ctx.nodeInfo(field, hint, types.WithSchema(nestedSchema)), nil
		}
		if variable.Type() != types.TypeUnknown {
			return types.NodeInfo{}, diagnostic.Schemaf("field %s is not recognized on scoped %s", fieldName(field), variable.Type()).WithNode(field)
		}
	}
	switch variable.Type() {
	case types.TypeUnknown, types.TypeObject, types.TypeArray:
		return ctx.nodeInfo(field, types.TypeUnknown), nil
	default:
		return types.NodeInfo{}, diagnostic.TypeMismatchf("field %s is not valid for scoped %s", fieldName(field), variable.Type())
	}
}

func inferSchemaComparison(ctx schemaContext, cmp *ast.Comparison) (types.NodeInfo, error) {
	left, err := inferSchemaExpr(ctx, cmp.Left)
	if err != nil {
		return types.NodeInfo{}, err
	}
	cmp.Left = left.Node
	right, err := inferSchemaExpr(ctx, cmp.Right)
	if err != nil {
		return types.NodeInfo{}, err
	}
	cmp.Right = right.Node
	if err := validateComparableTypes(left, right, cmp.Op); err != nil {
		return types.NodeInfo{}, diagnostic.AttachNode(err, cmp)
	}
	nullable := left.IsNullable() || right.IsNullable()
	if isNullEqualityComparison(left, right, cmp.Op) {
		nullable = ctx.defaultNullable()
	}
	return schemaNodeInfo(cmp, types.TypeBoolean, nullable), nil
}

func inferSchemaNullTest(ctx schemaContext, node ast.Expr, expr ast.Expr, set func(ast.Expr)) (types.NodeInfo, error) {
	info, err := inferSchemaExpr(ctx, expr)
	if err != nil {
		return types.NodeInfo{}, err
	}
	set(info.Node)
	if !info.Validate(types.TypeNull.Expect()) {
		return types.NodeInfo{}, diagnostic.TypeMismatchf("invalid comparison of %s to non-null null", info.Type()).WithNode(info.Node)
	}
	return schemaNodeInfo(node, types.TypeBoolean, ctx.defaultNullable()), nil
}

func isNullEqualityComparison(left types.NodeInfo, right types.NodeInfo, op string) bool {
	if op != "==" && op != "=" && op != "!=" {
		return false
	}
	return left.Type() == types.TypeNull || right.Type() == types.TypeNull
}

func validateComparableTypes(left types.NodeInfo, right types.NodeInfo, op string) error {
	leftType := left.Type()
	rightType := right.Type()
	if leftType == types.TypeUnknown || rightType == types.TypeUnknown {
		return nil
	}
	if leftType == types.TypeNull {
		if right.IsNullable() {
			return nil
		}
		return diagnostic.TypeMismatchf("invalid comparison of null to non-null %s", rightType)
	}
	if rightType == types.TypeNull {
		if left.IsNullable() {
			return nil
		}
		return diagnostic.TypeMismatchf("invalid comparison of %s to non-null null", leftType)
	}
	if leftType != rightType {
		return diagnostic.TypeMismatchf("invalid comparison of %s to %s", leftType, rightType)
	}
	if leftType == types.TypeBoolean && op != "==" && op != "!=" {
		return diagnostic.TypeMismatch("invalid ordered comparison of boolean values")
	}
	return nil
}

func inferSchemaMath(ctx schemaContext, math *ast.MathOperation) (types.NodeInfo, error) {
	left, err := inferSchemaExpr(ctx, math.Left)
	if err != nil {
		return types.NodeInfo{}, err
	}
	math.Left = left.Node
	right, err := inferSchemaExpr(ctx, math.Right)
	if err != nil {
		return types.NodeInfo{}, err
	}
	math.Right = right.Node
	if !right.Validate(types.TypeNumeric.Expect()) {
		return types.NodeInfo{}, diagnostic.TypeMismatchf("math right operand expected number not %s", right.Type()).WithNode(right.Node)
	}
	return schemaNodeInfo(math, types.TypeNumeric, left.IsNullable() || right.IsNullable()), nil
}

func inferSchemaInSet(ctx schemaContext, set *ast.InSet) (types.NodeInfo, error) {
	source, err := inferSchemaExpr(ctx, set.Expr)
	if err != nil {
		return types.NodeInfo{}, err
	}
	set.Expr = source.Node
	values := make([]types.NodeInfo, 0, len(set.Values)+1)
	values = append(values, source)
	for i, value := range set.Values {
		info, err := inferSchemaExpr(ctx, value)
		if err != nil {
			return types.NodeInfo{}, err
		}
		set.Values[i] = info.Node
		if err := validateComparableTypes(source, info, "=="); err != nil {
			return types.NodeInfo{}, err
		}
		values = append(values, info)
	}
	return schemaNodeInfo(set, types.TypeBoolean, nullableFrom(values...)), nil
}

func inferSchemaFunction(ctx schemaContext, call *ast.FunctionCall) (types.NodeInfo, error) {
	if call.Name == "arraySearch" || call.Name == "arrayCount" {
		return inferDynamicArrayFunction(ctx, call)
	}
	args := make([]types.NodeInfo, 0, len(call.Args))
	for i, arg := range call.Args {
		info, err := inferSchemaExpr(ctx, arg)
		if err != nil {
			return types.NodeInfo{}, err
		}
		call.Args[i] = info.Node
		args = append(args, info)
	}
	spec, ok := schemaFunctionSpecs[call.Name]
	if !ok {
		return types.NodeInfo{}, diagnostic.Semanticf("unknown function %s", call.Name)
	}
	if err := validateSchemaFunctionArgs(call, spec, args); err != nil {
		return types.NodeInfo{}, err
	}
	if spec.validate != nil {
		if err := spec.validate(call, args); err != nil {
			return types.NodeInfo{}, err
		}
	}
	return schemaNodeInfo(call, spec.returnType, spec.sometimesNull || nullableFrom(args...)), nil
}

func inferDynamicArrayFunction(ctx schemaContext, call *ast.FunctionCall) (types.NodeInfo, error) {
	arrayInfo, err := inferSchemaExpr(ctx, call.Args[0])
	if err != nil {
		return types.NodeInfo{}, err
	}
	call.Args[0] = arrayInfo.Node
	if !arrayInfo.Validate(types.TypeArray.Expect()) {
		return types.NodeInfo{}, diagnostic.TypeMismatchf("%s argument 1 expected array not %s", call.Name, arrayInfo.Type())
	}
	variable, ok := schemaVariableName(call.Args[1])
	if !ok {
		return types.NodeInfo{}, diagnostic.TypeMismatchf("%s argument 2 must be a variable name", call.Name)
	}
	bodyCtx := ctx.withVariable(variable, arrayElementInfo(ctx, call.Args[1], arrayInfo))
	bodyInfo, err := inferSchemaExpr(bodyCtx, call.Args[2])
	if err != nil {
		return types.NodeInfo{}, err
	}
	call.Args[2] = bodyInfo.Node
	if !bodyInfo.Validate(types.TypeBoolean.Expect()) {
		return types.NodeInfo{}, diagnostic.TypeMismatchf("%s argument 3 expected boolean not %s", call.Name, bodyInfo.Type())
	}
	returnType := types.TypeBoolean
	if call.Name == "arrayCount" {
		returnType = types.TypeNumeric
	}
	return schemaNodeInfo(call, returnType, true), nil
}

func (ctx schemaContext) withVariable(name string, info types.NodeInfo) schemaContext {
	next := schemaContext{
		schema:       ctx.schema,
		eventType:    ctx.eventType,
		eventSchemas: ctx.eventSchemas,
		vars:         make(map[string]types.NodeInfo, len(ctx.vars)+1),
		aliases:      ctx.aliases,
		opts:         ctx.opts,
		enumFields:   ctx.enumFields,
	}
	for key, value := range ctx.vars {
		next.vars[key] = value
	}
	next.vars[name] = info
	return next
}

func arrayElementInfo(ctx schemaContext, node ast.Expr, arrayInfo types.NodeInfo) types.NodeInfo {
	items, ok := arrayInfo.Schema.([]any)
	if !ok || len(items) != 1 {
		return ctx.nodeInfo(node, types.TypeUnknown)
	}
	itemSchema := items[0]
	hint, nestedSchema, ok := schemapkg.ConvertToType(itemSchema)
	if !ok {
		return ctx.nodeInfo(node, types.TypeUnknown)
	}
	if nestedSchema == nil {
		nestedSchema = itemSchema
	}
	return ctx.nodeInfo(node, hint, types.WithSchema(nestedSchema))
}

func schemaVariableName(expr ast.Expr) (string, bool) {
	field, ok := expr.(*ast.Field)
	if !ok || field.Base == "" || len(field.Path) != 0 {
		return "", false
	}
	return field.Base, true
}

func schemaPath(parts []ast.PathPart) []schemapkg.PathPart {
	out := make([]schemapkg.PathPart, 0, len(parts))
	for _, part := range parts {
		if part.IsIdx {
			out = append(out, schemapkg.Index(part.Index))
			continue
		}
		out = append(out, schemapkg.Field(part.Name))
	}
	return out
}

func schemaPathWithBase(field *ast.Field) []schemapkg.PathPart {
	path := make([]schemapkg.PathPart, 0, len(field.Path)+1)
	path = append(path, schemapkg.Field(field.Base))
	path = append(path, schemaPath(field.Path)...)
	return path
}

func clonePathParts(parts []ast.PathPart) []ast.PathPart {
	if len(parts) == 0 {
		return nil
	}
	out := make([]ast.PathPart, len(parts))
	copy(out, parts)
	return out
}

func validateSchemaFunctionArgs(call *ast.FunctionCall, spec schemaFunctionSpec, args []types.NodeInfo) error {
	minArgs := len(spec.args)
	if spec.minArgs > 0 {
		minArgs = spec.minArgs
	}
	for i, arg := range args {
		expected, ok := schemaFunctionExpected(spec, i)
		if !ok {
			return diagnostic.Semanticf("%s argument %d has no schema signature", call.Name, i+1)
		}
		if i < minArgs && !arg.Validate(expected) {
			return diagnostic.TypeMismatchf("%s argument %d expected compatible type not %s", call.Name, i+1, arg.Type()).WithNode(arg.Node)
		}
		if i >= minArgs && !expected.Empty() && !arg.Validate(expected) {
			return diagnostic.TypeMismatchf("%s argument %d expected compatible type not %s", call.Name, i+1, arg.Type()).WithNode(arg.Node)
		}
	}
	return nil
}

func schemaFunctionExpected(spec schemaFunctionSpec, index int) (types.Expectation, bool) {
	if index < len(spec.args) {
		return spec.args[index], true
	}
	if !spec.additional.Empty() {
		return spec.additional, true
	}
	return types.Expectation{}, false
}

func validateArrayContainsSchema(call *ast.FunctionCall, args []types.NodeInfo) error {
	if len(args) < 2 {
		return nil
	}
	items, ok := args[0].Schema.([]any)
	if !ok || len(items) != 1 {
		return nil
	}
	elementType, _, ok := schemapkg.ConvertToType(items[0])
	if !ok {
		return nil
	}
	if !args[1].Validate(elementType.Expect()) {
		return diagnostic.TypeMismatchf("%s argument 2 expected array element type %s not %s", call.Name, elementType, args[1].Type()).WithNode(args[1].Node)
	}
	return nil
}

func stringBoolFunctionSpec() schemaFunctionSpec {
	return schemaFunctionSpec{
		args:       []types.Expectation{types.TypeString.Expect(), types.TypeString.Expect()},
		returnType: types.TypeBoolean,
	}
}

func mathFunctionSpec() schemaFunctionSpec {
	return schemaFunctionSpec{
		args:       []types.Expectation{types.TypeNumeric.Expect(), types.TypeNumeric.Expect()},
		returnType: types.TypeNumeric,
	}
}

func fieldName(field *ast.Field) string {
	name := field.Base
	for _, part := range field.Path {
		if part.IsIdx {
			name += fmt.Sprintf("[%d]", part.Index)
			continue
		}
		name += "." + part.Name
	}
	return name
}
