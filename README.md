# eql-go

Go rewrite of the Python EQL engine, built MVP-first with Python oracle
conformance tests.

The current implementation supports the incremental slices listed below.
Single-event queries use the form:

```eql
event_type where expression
```

It also supports the first classic sequence slice:

```eql
sequence [event_type where expression] [event_type where expression]
sequence by field [event_type where expression] [event_type where expression]
sequence [event_type where expression] by source_field [event_type where expression] by target_field
sequence with maxspan=5s [event_type where expression] [event_type where expression]
sequence [event_type where expression] [event_type where expression] until [event_type where expression]
sequence [event_type where expression] [event_type where expression] fork
sequence by field [event_type where expression] [event_type where expression] | head 1
```

It supports Elasticsearch repeated sequence stages when compiled with both
`ElasticsearchSyntax()` and `AllowRuns()`:

```eql
sequence [file where true] with runs=3
sequence [process where true] [file where true] with runs=2
```

It supports Elasticsearch negative sequence stages when compiled with both
`ElasticsearchSyntax()` and `AllowNegation()`:

```eql
sequence with maxspan=5s [process where true] ![file where file_name == "missing.txt"]
```

It supports a minimal classic join slice, including pipes over join matches:

```eql
join [event_type where expression] [event_type where expression]
join by field [event_type where expression] [event_type where expression]
join [event_type where expression] by source_field [event_type where expression] by target_field
join [event_type where expression] [event_type where expression] until [event_type where expression]
join by field [event_type where expression] [event_type where expression] | head 1
```

It supports minimal sample queries when compiled with `AllowSample()`:

```eql
sample [event_type where expression] [event_type where expression]
sample by field [event_type where expression] [event_type where expression]
sample [event_type where expression] by source_field [event_type where expression] by target_field
sample [event_type where expression] [event_type where expression] | head 1
```

It supports Elasticsearch string predicates when compiled with
`ElasticsearchSyntax()`:

```eql
process where process_name : "cmd*"
process where process_name : ("cmd*", "powershell*")
process where ?process_name : "cmd*"
process where process_name in~ ("cmd.exe", "powershell.exe")
process where process_name like ("cmd*", "power*")
process where process_name regex ("cmd.*", "power.*")
```

It supports Elastic Endpoint `$variable` callback syntax when compiled with
`ElasticEndpointSyntax()`:

```eql
process where arraySearch(items, $item, $item == "a")
process where arraySearch(objects, $sig, $sig.trusted == true)
```

It supports Elastic Endpoint sequence alias syntax when compiled with
`ElasticEndpointSyntax()`:

```eql
sequence [process where true] as p0 [network where p0.pid == pid]
```

Supported MVP expression features:

- field access with dotted paths and array indexes
- string, number, boolean, and null literals
- comparisons: `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`
- math operators: `+`, `-`, `*`, `/`, `%`
- set membership: `in`, `not in`
- streaming pipes: `filter`, `head`, `unique`; reducer pipes: `tail`, `sort`, `count`, `unique_count`
- core functions: `length`, `wildcard`, `startsWith`, `endsWith`, `stringContains`, `match`, `matchLite`, `string`, `number`, `concat`, `add`, `subtract`, `multiply`, `divide`, `modulo`, `arrayContains`, `arraySearch`, `arrayCount`, `safe`, `indexOf`, `substring`, `between`, `cidrMatch`
- method-call function syntax: `field:length()` and `field:stringContains("x")`
- boolean logic: `and`, `or`, `not`
- preprocessor `const` and ordinary `macro` definitions supplied through `WithDefinitions`
- compile-time schema/type validation supplied through `WithSchema`, including
  strict boolean and non-nullable field modes, plus schema-backed enum field
  rewrites such as `process_name.bash` through `AllowEnumFields()`
- Elasticsearch string predicates and `in~` gated by
  `ElasticsearchSyntax()`: `:`, `in~`, `like`, `like~`, `regex`, `regex~`
- Elasticsearch optional fields gated by `ElasticsearchSyntax()`: `?field`,
  `?field.path`; schema validation for optional fields can be made strict with
  `ElasticsearchValidateOptionalFields()`
- Elastic Endpoint `$variable` callback syntax gated by
  `ElasticEndpointSyntax()`
- Elastic Endpoint sequence alias syntax gated by `ElasticEndpointSyntax()`:
  `as alias`
- minimal classic sequences with optional global or stage-level `by` keys, `maxspan`, `until`, `fork`, and pipes
- Elasticsearch repeated sequence stages gated by `ElasticsearchSyntax()` and
  `AllowRuns()`: `with runs=N`
- Elasticsearch negative sequence stages gated by `ElasticsearchSyntax()` and
  `AllowNegation()`: `![event_type where expression]`; negative sequences
  require `maxspan`
- minimal classic joins with optional global or stage-level `by` keys, `until`, and pipes
- minimal `sample` queries gated by `AllowSample()`, with optional global or stage-level `by` keys and pipes
- Python-compatible event normalization for `event_type`, `event_type_full`,
  `data_buffer`, and `timestamp`

Unsupported by design in the MVP:

- remaining sequence ES/Endpoint syntax not listed above
- remaining reducer pipes: none in the MVP scope
- custom Python callback macros
- Elasticsearch translation and remaining ES/Endpoint syntax

The stable client surface is the root package:

```go
import eql "github.com/local/eql-go"
```

Internal implementation modules live under `internal/` and are not public API.
See [docs/interfaces.md](docs/interfaces.md) for the module contracts that
future parser, engine, and sequence rewrites must preserve.
See [docs/progress.md](docs/progress.md) for the current milestone handoff and
M12 final Python-alignment review entry point.

Run tests:

```sh
GOCACHE=/private/tmp/go-build-cache GOMODCACHE=/private/tmp/go-mod-cache go test ./...
```

The conformance suite calls the local Python EQL repository as the oracle and
compares ordered match output.

Compare one query manually:

```sh
GOCACHE=/private/tmp/go-build-cache GOMODCACHE=/private/tmp/go-mod-cache go run ./cmd/eqlcompare \
  -events tests/integration/conformance/testdata/mvp/events.jsonl \
  -query 'process where true'
```

Definitions can be compared with the Python oracle too:

```sh
GOCACHE=/private/tmp/go-build-cache GOMODCACHE=/private/tmp/go-mod-cache go run ./cmd/eqlcompare \
  -events tests/integration/conformance/testdata/mvp/events.jsonl \
  -definitions 'const TARGET = "cmd.exe"' \
  -query 'process where process_name == TARGET'
```
