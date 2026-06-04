package eql

import (
	"errors"
	"strings"

	"github.com/Rakivili/eql-go/internal/diagnostic"
	"github.com/Rakivili/eql-go/internal/engine"
	"github.com/Rakivili/eql-go/internal/optimizer"
	"github.com/Rakivili/eql-go/internal/parser"
	"github.com/Rakivili/eql-go/internal/preprocessor"
	schemapkg "github.com/Rakivili/eql-go/internal/schema"
	"github.com/Rakivili/eql-go/internal/validator"
)

// Event is the normalized runtime representation consumed by Engine.Feed.
type Event = engine.Event

// Match is one rule match emitted by the engine.
type Match = engine.Match

// Rule is an opaque compiled EQL query.
type Rule struct {
	inner *engine.Rule
}

// Engine evaluates one or more compiled rules against streaming events.
type Engine struct {
	inner *engine.Engine
}

// RuleOption configures query execution semantics at compile time.
type RuleOption func(*ruleOptions)

type ruleOptions struct {
	caseSensitive          bool
	definitions            string
	allowSample            bool
	allowNegation          bool
	allowRuns              bool
	allowEnumFields        bool
	elasticsearchSyntax    bool
	elasticEndpointSyntax  bool
	validateOptionalFields bool
	impliedAny             bool
	impliedBase            bool
	dataSource             string
	schemaEvents           map[string]map[string]any
	schemaConfig           schemaOptions
}

// SchemaOption configures schema validation.
type SchemaOption func(*schemaOptions)

type schemaOptions struct {
	allowGeneric      bool
	allowAny          bool
	allowMissing      bool
	strictBooleans    bool
	nonNullableFields bool
}

// EventNormalizer converts raw event maps into runtime events.
type EventNormalizer = engine.EventNormalizer

// Compile parses and compiles a query into an opaque rule.
func Compile(query string, opts ...RuleOption) (*Rule, error) {
	cfg := ruleOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	query = applyImpliedPrefixes(query, cfg.impliedAny, cfg.impliedBase)
	parsed, sourceMap, err := parser.ParseQueryWithSourceMap(query, parser.Options{
		AllowSample:           cfg.allowSample,
		AllowNegation:         cfg.allowNegation,
		AllowRuns:             cfg.allowRuns,
		ElasticsearchSyntax:   cfg.elasticsearchSyntax,
		ElasticEndpointSyntax: cfg.elasticEndpointSyntax,
	})
	if err != nil {
		return nil, WrapError(CodeParse, "parse query", err)
	}
	if cfg.definitions != "" {
		pp, err := preprocessor.ParseDefinitions(cfg.definitions)
		if err != nil {
			return nil, WrapError(CodeParse, "parse definitions", err)
		}
		parsed, err = pp.ExpandQuery(parsed)
		if err != nil {
			return nil, WrapError(CodeParse, "expand definitions", err)
		}
	}
	if err := validator.ValidateQuery(parsed); err != nil {
		return nil, WrapError(CodeParse, "validate query", enrichSourceDiagnostic(err, query, sourceMap))
	}
	if cfg.schemaEvents != nil {
		schema, err := schemapkg.New(
			cfg.schemaEvents,
			schemapkg.WithAllowGeneric(cfg.schemaConfig.allowGeneric),
			schemapkg.WithAllowAny(cfg.schemaConfig.allowAny),
			schemapkg.WithAllowMissing(cfg.schemaConfig.allowMissing),
		)
		if err != nil {
			return nil, WrapError(CodeParse, "validate schema", diagnostic.Schema(err.Error()))
		}
		if err := validator.ValidateQuerySchema(
			parsed,
			schema,
			validator.SchemaElasticEndpointSyntax(cfg.elasticEndpointSyntax),
			validator.SchemaValidateOptionalFields(cfg.validateOptionalFields),
			validator.SchemaAllowEnumFields(cfg.allowEnumFields),
			validator.SchemaStrictBooleans(cfg.schemaConfig.strictBooleans),
			validator.SchemaNonNullableFields(cfg.schemaConfig.nonNullableFields),
		); err != nil {
			return nil, WrapError(CodeParse, "validate query schema", enrichSourceDiagnostic(err, query, sourceMap))
		}
	}
	parsed = optimizer.OptimizeQuery(parsed, optimizer.Options{
		CaseInsensitive:     !cfg.caseSensitive,
		ElasticsearchSyntax: cfg.elasticsearchSyntax,
	})
	if err := validator.ValidateQuery(parsed); err != nil {
		return nil, WrapError(CodeParse, "validate optimized query", enrichSourceDiagnostic(err, query, sourceMap))
	}
	var engineOpts []engine.RuleOption
	if cfg.caseSensitive {
		engineOpts = append(engineOpts, engine.CaseSensitive())
	}
	if cfg.elasticsearchSyntax {
		engineOpts = append(engineOpts, engine.ElasticsearchSyntax())
	}
	if cfg.dataSource != "" {
		engineOpts = append(engineOpts, engine.DataSource(cfg.dataSource))
	}
	return &Rule{inner: engine.NewRule(parsed, engineOpts...)}, nil
}

func enrichSourceDiagnostic(err error, source string, sourceMap *parser.SourceMap) error {
	var diagnosticErr *diagnostic.Error
	if !errors.As(err, &diagnosticErr) {
		return err
	}
	if diagnosticErr.Line > 0 && diagnosticErr.Column > 0 {
		return err
	}
	span, ok := sourceMap.Span(diagnosticErr.Node)
	if !ok {
		return err
	}
	return diagnosticErr.WithSourceSpan(source, span)
}

// NewEngine creates a streaming engine for one or more compiled rules.
func NewEngine(rules ...*Rule) *Engine {
	innerRules := make([]*engine.Rule, 0, len(rules))
	for _, rule := range rules {
		if rule != nil && rule.inner != nil {
			innerRules = append(innerRules, rule.inner)
		}
	}
	return &Engine{inner: engine.New(innerRules...)}
}

// Feed evaluates one event against the engine's rules.
func (e *Engine) Feed(ev *Event) ([]Match, error) {
	if e == nil || e.inner == nil {
		return nil, nil
	}
	matches, err := e.inner.Feed(ev)
	if err != nil {
		return nil, WrapError(CodeRuntime, "feed event", err)
	}
	return matches, nil
}

// Finalize flushes any buffered engine state.
func (e *Engine) Finalize() ([]Match, error) {
	if e == nil || e.inner == nil {
		return nil, nil
	}
	matches, err := e.inner.Finalize()
	if err != nil {
		return nil, WrapError(CodeRuntime, "finalize engine", err)
	}
	return matches, nil
}

// EventFromData normalizes a raw JSON-like event map using Python EQL-compatible defaults.
func EventFromData(data map[string]any) *Event {
	return engine.EventFromData(data)
}

// EventFromDataWithNormalizer normalizes a raw event map with caller-supplied logic.
func EventFromDataWithNormalizer(data map[string]any, normalizer EventNormalizer) *Event {
	return engine.EventFromDataWithNormalizer(data, normalizer)
}

// CaseSensitive disables the default case-insensitive string comparison behavior.
func CaseSensitive() RuleOption {
	return func(o *ruleOptions) {
		o.caseSensitive = true
	}
}

// WithDefinitions applies EQL preprocessor definitions before validation.
func WithDefinitions(defs string) RuleOption {
	return func(o *ruleOptions) {
		o.definitions = defs
	}
}

// WithSchema enables compile-time schema and type validation.
func WithSchema(events map[string]map[string]any, opts ...SchemaOption) RuleOption {
	return func(o *ruleOptions) {
		o.schemaEvents = events
		o.schemaConfig = schemaOptions{allowGeneric: true, allowAny: true, strictBooleans: true}
		for _, opt := range opts {
			if opt != nil {
				opt(&o.schemaConfig)
			}
		}
	}
}

// SchemaAllowGeneric configures whether schema validation accepts generic queries.
func SchemaAllowGeneric(allow bool) SchemaOption {
	return func(o *schemaOptions) {
		o.allowGeneric = allow
	}
}

// SchemaAllowAny configures whether schema validation accepts any-event queries.
func SchemaAllowAny(allow bool) SchemaOption {
	return func(o *schemaOptions) {
		o.allowAny = allow
	}
}

// SchemaAllowMissing configures whether missing schema fields are treated as mixed.
func SchemaAllowMissing(allow bool) SchemaOption {
	return func(o *schemaOptions) {
		o.allowMissing = allow
	}
}

// SchemaStrictBooleans configures whether schema validation requires boolean conditions.
// WithSchema defaults this to true to match Python EQL's default Schema behavior.
func SchemaStrictBooleans(strict bool) SchemaOption {
	return func(o *schemaOptions) {
		o.strictBooleans = strict
	}
}

// SchemaNonNullableFields configures whether schema fields and literals are non-nullable.
func SchemaNonNullableFields(nonNullable bool) SchemaOption {
	return func(o *schemaOptions) {
		o.nonNullableFields = nonNullable
	}
}

// AllowSample enables the Elasticsearch-gated sample query form.
func AllowSample() RuleOption {
	return func(o *ruleOptions) {
		o.allowSample = true
	}
}

// ElasticsearchSyntax enables Elasticsearch EQL string predicate syntax.
func ElasticsearchSyntax() RuleOption {
	return func(o *ruleOptions) {
		o.elasticsearchSyntax = true
	}
}

// ElasticsearchValidateOptionalFields enables ES optional fields and validates them against schema.
func ElasticsearchValidateOptionalFields() RuleOption {
	return func(o *ruleOptions) {
		o.elasticsearchSyntax = true
		o.validateOptionalFields = true
	}
}

// ElasticEndpointSyntax enables Elastic Endpoint EQL syntax extensions.
func ElasticEndpointSyntax() RuleOption {
	return func(o *ruleOptions) {
		o.elasticsearchSyntax = true
		o.elasticEndpointSyntax = true
	}
}

// AllowNegation enables Elasticsearch negative sequence stages.
func AllowNegation() RuleOption {
	return func(o *ruleOptions) {
		o.allowNegation = true
	}
}

// AllowRuns enables Elasticsearch repeated sequence stages.
func AllowRuns() RuleOption {
	return func(o *ruleOptions) {
		o.allowRuns = true
	}
}

// AllowEnumFields rewrites schema-backed enum field syntax such as field.value.
func AllowEnumFields() RuleOption {
	return func(o *ruleOptions) {
		o.allowEnumFields = true
	}
}

// ImpliedAny allows a bare expression (without an event-type/where prefix) to
// be compiled as "any where <expression>". This matches Python's implied_any=True
// CLI behavior.
func ImpliedAny() RuleOption {
	return func(o *ruleOptions) {
		o.impliedAny = true
	}
}

// ImpliedBase allows a pipe-only query (starting with "|") to be compiled as
// "any where true <pipes>". This matches Python's implied_base=True CLI behavior.
func ImpliedBase() RuleOption {
	return func(o *ruleOptions) {
		o.impliedBase = true
	}
}

// WithDataSource sets the data source mode. Use "endgame" for Endgame endpoint sensor
// data, which uses opcode-based process lifecycle signals instead of ECS subtype strings.
func WithDataSource(ds string) RuleOption {
	return func(o *ruleOptions) { o.dataSource = strings.ToLower(ds) }
}

// applyImpliedPrefixes rewrites the query string when implied_any or implied_base
// is enabled, matching Python EQL's parse_query(implied_any=True, implied_base=True)
// semantics.
//
// Rules (applied in order, at most one transformation):
//  1. impliedBase: if the trimmed query starts with "|", prepend "any where true ".
//  2. impliedAny: if the query does not contain an event-type/where header (i.e.
//     does not start with a keyword followed by "where" or one of the structural
//     keywords sequence/join/sample), prepend "any where ".
func applyImpliedPrefixes(query string, impliedAny, impliedBase bool) string {
	trimmed := strings.TrimSpace(query)
	// Rule 1: pipe-only query → implied base.
	if impliedBase && strings.HasPrefix(trimmed, "|") {
		return "any where true " + trimmed
	}
	// Rule 2: bare expression → implied any where.
	if impliedAny {
		lower := strings.ToLower(trimmed)
		// Structural query forms: do not prepend.
		if strings.HasPrefix(lower, "sequence") ||
			strings.HasPrefix(lower, "join") ||
			strings.HasPrefix(lower, "sample") {
			return query
		}
		// If there is no "where" keyword the query cannot have an event-type header.
		if !strings.Contains(lower, " where ") {
			return "any where " + trimmed
		}
	}
	return query
}
