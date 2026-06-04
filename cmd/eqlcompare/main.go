package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Rakivili/eql-go/internal/conformance"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(args []string, stdout, stderr io.Writer) int {
	if err := runCompare(args, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runCompare(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("eqlcompare", flag.ContinueOnError)
	eventsPath := fs.String("events", "", "input JSONL events")
	query := fs.String("query", "", "single EQL query")
	queriesPath := fs.String("queries", "", "file containing one query per line")
	pythonRepo := fs.String("python-repo", conformance.DefaultPythonRepo(), "local Python EQL repository path")
	caseSensitive := fs.Bool("case-sensitive", false, "compare with case-sensitive EQL semantics")
	allowSample := fs.Bool("allow-sample", false, "enable sample query parsing")
	allowNegation := fs.Bool("allow-negation", false, "enable negative sequence parsing")
	allowRuns := fs.Bool("allow-runs", false, "enable repeated sequence parsing")
	elasticsearchSyntax := fs.Bool("elasticsearch-syntax", false, "enable Elasticsearch EQL syntax")
	elasticEndpointSyntax := fs.Bool("elastic-endpoint-syntax", false, "enable Elastic Endpoint EQL syntax")
	definitions := fs.String("definitions", "", "EQL preprocessor definitions")
	definitionsPath := fs.String("definitions-file", "", "file containing EQL preprocessor definitions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		return fmt.Errorf("-events is required")
	}
	if (*query == "") == (*queriesPath == "") {
		return fmt.Errorf("provide exactly one of -query or -queries")
	}
	if *definitions != "" && *definitionsPath != "" {
		return fmt.Errorf("provide at most one of -definitions or -definitions-file")
	}

	events, err := conformance.ReadJSONL(*eventsPath)
	if err != nil {
		return err
	}
	defs := *definitions
	if *definitionsPath != "" {
		body, err := os.ReadFile(*definitionsPath)
		if err != nil {
			return err
		}
		defs = string(body)
	}
	queries := []string{*query}
	if *queriesPath != "" {
		queries, err = conformance.ReadQueries(*queriesPath)
		if err != nil {
			return err
		}
	}
	for i, q := range queries {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		result, err := compareQuery(context.Background(), *pythonRepo, q, events, *caseSensitive, *allowSample, *allowNegation, *allowRuns, *elasticsearchSyntax, *elasticEndpointSyntax, defs)
		if err != nil {
			return err
		}
		printResult(stdout, result)
	}
	return nil
}

func compareQuery(ctx context.Context, pythonRepo string, query string, events []map[string]any, caseSensitive bool, allowSample bool, allowNegation bool, allowRuns bool, elasticsearchSyntax bool, elasticEndpointSyntax bool, definitions string) (conformance.Result, error) {
	return conformance.CompareWithOptions(ctx, pythonRepo, query, events, conformance.CompareOptions{
		CaseSensitive:         caseSensitive,
		AllowSample:           allowSample,
		AllowNegation:         allowNegation,
		AllowRuns:             allowRuns,
		ElasticsearchSyntax:   elasticsearchSyntax,
		ElasticEndpointSyntax: elasticEndpointSyntax,
		Definitions:           definitions,
	})
}

func printResult(w io.Writer, result conformance.Result) {
	fmt.Fprintf(w, "QUERY %s\n", result.Query)
	fmt.Fprintln(w, "PYTHON")
	printRows(w, result.PythonRows)
	fmt.Fprintln(w, "GO")
	printRows(w, result.GoRows)
	fmt.Fprintf(w, "EQUAL %v\n", result.Equal())
}

func printRows(w io.Writer, rows []string) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "<empty>")
		return
	}
	for _, row := range rows {
		fmt.Fprintln(w, row)
	}
}
