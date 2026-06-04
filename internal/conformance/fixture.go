package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"

	eql "github.com/Rakivili/eql-go"
)

// Result contains canonical Python and Go outputs for one query.
type Result struct {
	Query      string
	PythonRows []string
	GoRows     []string
}

// CompareOptions configures Python/Go conformance comparison.
type CompareOptions struct {
	CaseSensitive         bool
	Definitions           string
	DataSource            string
	AllowSample           bool
	AllowNegation         bool
	AllowRuns             bool
	ElasticsearchSyntax   bool
	ElasticEndpointSyntax bool
}

// Equal reports whether Python and Go emitted the same ordered rows.
func (r Result) Equal() bool {
	return slices.Equal(r.PythonRows, r.GoRows)
}

// DefaultPythonRepo returns the Python EQL repo path used by local tooling.
func DefaultPythonRepo() string {
	if repo := os.Getenv("EQL_PYTHON_REPO"); repo != "" {
		return repo
	}
	return filepath.Clean("../eql")
}

// ReadJSONL reads JSONL events from disk using json.Number for numeric values.
func ReadJSONL(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []map[string]any
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&event); err != nil {
			return nil, fmt.Errorf("%s:%d: decode jsonl: %w", path, lineNo, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// ReadJSONArray reads a JSON array of events using json.Number for numeric values.
func ReadJSONArray(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []map[string]any
	dec := json.NewDecoder(f)
	dec.UseNumber()
	if err := dec.Decode(&events); err != nil {
		return nil, fmt.Errorf("%s: decode json array: %w", path, err)
	}
	return events, nil
}

// ReadQueries reads one query per line, ignoring blanks and # comments.
func ReadQueries(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var queries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		queries = append(queries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return queries, nil
}

// Compare evaluates one query against Python EQL and this Go implementation.
func Compare(ctx context.Context, pythonRepo string, query string, events []map[string]any) (Result, error) {
	return CompareWithOptions(ctx, pythonRepo, query, events, CompareOptions{})
}

// CompareCaseSensitive evaluates one query in case-sensitive mode against
// Python EQL and this Go implementation.
func CompareCaseSensitive(ctx context.Context, pythonRepo string, query string, events []map[string]any) (Result, error) {
	return CompareWithOptions(ctx, pythonRepo, query, events, CompareOptions{CaseSensitive: true})
}

// CompareWithDefinitions evaluates one query with EQL preprocessor definitions.
func CompareWithDefinitions(ctx context.Context, pythonRepo string, query string, definitions string, events []map[string]any) (Result, error) {
	return CompareWithOptions(ctx, pythonRepo, query, events, CompareOptions{Definitions: definitions})
}

// CompareWithOptions evaluates one query against Python EQL and this Go
// implementation with the supplied compatibility options.
func CompareWithOptions(ctx context.Context, pythonRepo string, query string, events []map[string]any, opts CompareOptions) (Result, error) {
	pythonRows, err := pythonOutputRows(ctx, pythonRepo, query, events, opts)
	if err != nil {
		return Result{}, err
	}
	goRows, err := goOutputRows(query, events, opts)
	if err != nil {
		return Result{}, err
	}
	return Result{Query: query, PythonRows: pythonRows, GoRows: goRows}, nil
}

// GoOutputRows returns canonical JSON rows emitted by the Go engine.
func GoOutputRows(query string, events []map[string]any) ([]string, error) {
	return goOutputRows(query, events, CompareOptions{})
}

// GoOutputRowsCaseSensitive returns canonical JSON rows emitted by the Go
// engine with case-sensitive query semantics.
func GoOutputRowsCaseSensitive(query string, events []map[string]any) ([]string, error) {
	return goOutputRows(query, events, CompareOptions{CaseSensitive: true})
}

// GoOutputRowsWithDefinitions returns canonical JSON rows emitted by the Go
// engine with EQL preprocessor definitions applied at compile time.
func GoOutputRowsWithDefinitions(query string, definitions string, events []map[string]any) ([]string, error) {
	return goOutputRows(query, events, CompareOptions{Definitions: definitions})
}

func goOutputRows(query string, events []map[string]any, opts CompareOptions) ([]string, error) {
	var ruleOpts []eql.RuleOption
	if opts.CaseSensitive {
		ruleOpts = append(ruleOpts, eql.CaseSensitive())
	}
	if opts.Definitions != "" {
		ruleOpts = append(ruleOpts, eql.WithDefinitions(opts.Definitions))
	}
	if opts.AllowSample {
		ruleOpts = append(ruleOpts, eql.AllowSample())
	}
	if opts.AllowNegation {
		ruleOpts = append(ruleOpts, eql.AllowNegation())
	}
	if opts.AllowRuns {
		ruleOpts = append(ruleOpts, eql.AllowRuns())
	}
	if opts.ElasticsearchSyntax {
		ruleOpts = append(ruleOpts, eql.ElasticsearchSyntax())
	}
	if opts.ElasticEndpointSyntax {
		ruleOpts = append(ruleOpts, eql.ElasticEndpointSyntax())
	}
	if opts.DataSource != "" {
		ruleOpts = append(ruleOpts, eql.WithDataSource(opts.DataSource))
	}
	rule, err := eql.Compile(query, ruleOpts...)
	if err != nil {
		return nil, err
	}
	eng := eql.NewEngine(rule)
	var rows []string
	for _, data := range events {
		matches, err := eng.Feed(eql.EventFromData(data))
		if err != nil {
			return nil, err
		}
		rows, err = appendMatchRows(rows, matches)
		if err != nil {
			return nil, err
		}
	}
	matches, err := eng.Finalize()
	if err != nil {
		return nil, err
	}
	rows, err = appendMatchRows(rows, matches)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func appendMatchRows(rows []string, matches []eql.Match) ([]string, error) {
	for _, match := range matches {
		for _, event := range match.Events {
			row, err := canonicalJSON(event.Data)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// PythonOutputRows returns canonical JSON rows emitted by Python EQL.
func PythonOutputRows(ctx context.Context, pythonRepo string, query string, events []map[string]any) ([]string, error) {
	return pythonOutputRows(ctx, pythonRepo, query, events, CompareOptions{})
}

// PythonOutputRowsCaseSensitive returns canonical JSON rows emitted by Python
// EQL with case-sensitive query semantics.
func PythonOutputRowsCaseSensitive(ctx context.Context, pythonRepo string, query string, events []map[string]any) ([]string, error) {
	return pythonOutputRows(ctx, pythonRepo, query, events, CompareOptions{CaseSensitive: true})
}

// PythonOutputRowsWithDefinitions returns canonical JSON rows emitted by
// Python EQL with EQL preprocessor definitions applied at parse time.
func PythonOutputRowsWithDefinitions(ctx context.Context, pythonRepo string, query string, definitions string, events []map[string]any) ([]string, error) {
	return pythonOutputRows(ctx, pythonRepo, query, events, CompareOptions{Definitions: definitions})
}

func pythonOutputRows(ctx context.Context, pythonRepo string, query string, events []map[string]any, opts CompareOptions) ([]string, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]any{
		"query":          query,
		"events":         events,
		"case_sensitive": opts.CaseSensitive,
		"definitions":    opts.Definitions,
		"data_source":    opts.DataSource,
		"allow_sample":   opts.AllowSample,
		"allow_negation": opts.AllowNegation,
		"allow_runs":     opts.AllowRuns,
		"elasticsearch":  opts.ElasticsearchSyntax,
		"endpoint":       opts.ElasticEndpointSyntax,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	script := `
import json, sys
import contextlib
import eql
from eql import PythonEngine, get_preprocessor, parse_query
from eql.parser import allow_negation, allow_runs, allow_sample, elastic_endpoint_syntax, elasticsearch_syntax
payload = json.load(sys.stdin)
prev = eql.utils.CASE_INSENSITIVE
try:
    eql.utils.CASE_INSENSITIVE = not payload["case_sensitive"]
    config = {"flatten": True}
    if payload["data_source"]:
        config["data_source"] = payload["data_source"]
    engine = PythonEngine(config)
    results = []
    engine.add_output_hook(results.append)
    preprocessor = get_preprocessor(payload["definitions"]) if payload["definitions"] else None
    with contextlib.ExitStack() as stack:
        if payload["allow_sample"]:
            stack.enter_context(allow_sample)
        if payload["allow_negation"]:
            stack.enter_context(allow_negation)
        if payload["allow_runs"]:
            stack.enter_context(allow_runs)
        if payload["endpoint"]:
            stack.enter_context(elastic_endpoint_syntax)
        elif payload["allow_sample"] or payload["allow_runs"] or payload["elasticsearch"]:
            stack.enter_context(elasticsearch_syntax)
        engine.add_query(parse_query(payload["query"], preprocessor=preprocessor))
    engine.stream_events(payload["events"])
    for event in results:
        print(json.dumps(event.data, sort_keys=True, separators=(",", ":")))
finally:
    eql.utils.CASE_INSENSITIVE = prev
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python oracle: %w: %s", err, bytes.TrimSpace(out))
	}
	return splitRows(out), nil
}

func canonicalJSON(v any) (string, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return escapeJSONNonASCII(string(body)), nil
}

func escapeJSONNonASCII(row string) string {
	var b strings.Builder
	for _, r := range row {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		if r <= 0xffff {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		hi, lo := utf16.EncodeRune(r)
		fmt.Fprintf(&b, "\\u%04x\\u%04x", hi, lo)
	}
	return b.String()
}

func splitRows(out []byte) []string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// SerialEventIDs extracts ordered serial_event_id values from canonical rows.
func SerialEventIDs(rows []string) ([]int64, error) {
	ids := make([]int64, 0, len(rows))
	for i, row := range rows {
		var data map[string]any
		dec := json.NewDecoder(strings.NewReader(row))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil, fmt.Errorf("row %d: decode event row: %w", i, err)
		}
		raw, ok := data["serial_event_id"]
		if !ok {
			return nil, fmt.Errorf("row %d: missing serial_event_id", i)
		}
		id, err := numberToInt64(raw)
		if err != nil {
			return nil, fmt.Errorf("row %d: serial_event_id: %w", i, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func numberToInt64(value any) (int64, error) {
	switch x := value.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i, nil
		}
		f, err := x.Float64()
		if err != nil {
			return 0, err
		}
		i := int64(f)
		if float64(i) != f {
			return 0, fmt.Errorf("not an integer: %v", x)
		}
		return i, nil
	case float64:
		i := int64(x)
		if float64(i) != x {
			return 0, fmt.Errorf("not an integer: %v", x)
		}
		return i, nil
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("unexpected type %T", value)
	}
}
