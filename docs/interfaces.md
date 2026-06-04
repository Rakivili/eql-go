# Module Interfaces

This repository keeps one public client surface and several internal module
contracts. Future rewrites should preserve the contracts here before changing
module internals.

## Public API

Public callers should import only:

```go
import eql "github.com/local/eql-go"
```

Stable entry points:

- `Compile(query string, opts ...RuleOption) (*Rule, error)`
- `NewEngine(rules ...*Rule) *Engine`
- `(*Engine).Feed(ev *Event) ([]Match, error)`
- `(*Engine).Finalize() ([]Match, error)`
- `EventFromData(data map[string]any) *Event`
- `EventFromDataWithNormalizer(data map[string]any, normalizer EventNormalizer) *Event`
- `CaseSensitive() RuleOption`
- `WithDefinitions(defs string) RuleOption`
- `AllowSample() RuleOption`
- `AllowNegation() RuleOption`
- `AllowRuns() RuleOption`
- `AllowEnumFields() RuleOption`
- `ElasticsearchSyntax() RuleOption`
- `ElasticsearchValidateOptionalFields() RuleOption`
- `ElasticEndpointSyntax() RuleOption`
- `WithSchema(events map[string]map[string]any, opts ...SchemaOption) RuleOption`
- `SchemaAllowGeneric(bool) SchemaOption`
- `SchemaAllowAny(bool) SchemaOption`
- `SchemaAllowMissing(bool) SchemaOption`
- `SchemaStrictBooleans(bool) SchemaOption`
- `SchemaNonNullableFields(bool) SchemaOption`
- `(*AppError).Diagnostic() (ErrorDiagnostic, bool)`
- `WrapError(code ErrorCode, msg string, err error) error`

Stable public data contracts:

- `Event.Type` is the normalized event category used for rule selection.
- `Event.Timestamp` is the normalized event timestamp, or `0` when absent.
- `Event.Data` is the event payload emitted back in matches.
- `Match.Events` is the ordered event list that satisfied the rule.
  Single-event queries emit one event; sequence, join, and sample queries emit
  the matched events in order.
- `Match.RuleID` and `Match.AnalyticID` are reserved metadata fields.
- `AppError.Code` is the stable category for parse/runtime failures.
- `ErrorDiagnostic.Class` uses the stable `DiagnosticClass` taxonomy:
  `DiagnosticClassSyntax`, `DiagnosticClassSemantic`,
  `DiagnosticClassSchema`, and `DiagnosticClassTypeMismatch`.

`Rule` internals are opaque. Callers must create rules through `Compile`.
The zero value of `Engine` is usable and emits no matches.
Reducer pipes such as `tail`, `sort`, `count`, and `unique_count` buffer events
during `Feed` and emit their remaining matches from `Finalize`.
`WithDefinitions` currently supports Python-compatible literal `const`
definitions and ordinary macro definitions. Custom Python callback macros
remain unsupported in the MVP and return `CodeParse`.
`WithSchema` enables Python-compatible schema/type validation. Its schema
options expose the Python `Schema(... allow_*)` switches plus strict boolean
conditions and non-nullable field/literal null-comparison behavior.
`AllowEnumFields` enables Python-compatible schema-backed enum field rewrites,
turning expressions such as `process_name.bash` into
`process_name == "bash"` when the base field exists in schema and is a string.
`ElasticsearchSyntax` currently enables optional fields (`?field`), `in~`, and
the ES string predicate forms `:`, `like`, `like~`, `regex`, and `regex~`;
`ElasticsearchValidateOptionalFields` enables Elasticsearch syntax and requires
optional fields to exist when schema validation is active, matching Python's
`elasticsearch_validate_optional_fields` parser context.
`AllowNegation` enables negative sequence stages `![...]` when
`ElasticsearchSyntax` is also enabled. Negative sequence stages require
`maxspan`, matching Python EQL's current parser validation. `AllowRuns` enables
repeated sequence stages `with runs=N` when `ElasticsearchSyntax` is also
enabled. `ElasticEndpointSyntax` enables Endpoint `$variable` callback syntax
and sequence `as alias` syntax, and implies `ElasticsearchSyntax`. Other
ES/Endpoint extensions remain independently gated or unsupported.

## CLI API

The CLI entry point is:

```sh
eql query [-f file] QUERY
```

Input is JSONL. Output is matched events as JSONL. The CLI intentionally
depends only on the public root package.

## Error Contract

Public API methods return explicit `error` values and must not panic for
ordinary parse, compile, or runtime failures. EQL application failures are
wrapped as `AppError` with stable codes:

- `CodeParse`: invalid or unsupported EQL source.
- `CodeRuntime`: evaluation failure while processing events.

Callers should use `errors.As(err, *AppError)` and inspect `Code`.
For source locations, callers can use `AppError.Diagnostic()` to retrieve
underlying compiler diagnostics without importing internal packages. The method
returns `true` only when the `AppError` is `CodeParse` and its underlying error
chain contains either a parser diagnostic or an internal diagnostic carrier.
`Source` is one source line, not the full query. `Pos`, `Column`, and `Width`
are byte-based; `Line` and `Column` are one-based.

The public diagnostic taxonomy covers syntax, semantic, schema, and
type-mismatch failures. Syntax parser diagnostics are populated with source
positions. Function signature semantic diagnostics in public `Compile(...)`,
such as unknown functions and arity mismatches, expose a function-name source
span. Schema missing-field diagnostics and validator type-mismatch diagnostics
also carry source spans through the parser sidecar source map. If a future
diagnostic producer cannot associate a source span, `Line == 0`, `Column == 0`,
`Width == 0`, `Source == ""`, and `Caret == ""` means source span data is not
available for that diagnostic.

## Internal Module Boundaries

Internal packages are implementation modules, not public import targets.

- `internal/parser`: accepts EQL source text and returns the internal query IR.
- `internal/ast`: defines the internal query IR shared by parser and engine.
- `internal/engine`: evaluates compiled IR against normalized streaming events.

The parser must not depend on the engine. The CLI and conformance tests must
exercise behavior through the root `eql` package. This keeps parser rewrites,
engine execution changes, and future sequence-state implementations from
leaking into client code.

## Data Representation Rules

`Event.Data` must not expose internal IR-only types. JSON numbers decoded with
`UseNumber` remain `json.Number`; Go numeric inputs remain normal Go numeric
types. Numeric coercion happens inside expression evaluation.

Python compatibility is enforced at the behavior boundary: for the same JSONL
events and query, Go output must match the Python EQL oracle output in order.

## Test Layout

Unit tests live beside their packages. Python oracle conformance tests are
integration tests under `tests/integration/conformance`.

Conformance fixtures live in `tests/integration/conformance/testdata`. The
`cmd/eqlcompare` tool reads those fixtures and prints Python output, Go output,
and equality status for one query or a query file.
