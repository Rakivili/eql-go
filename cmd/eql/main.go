package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	eql "github.com/Rakivili/eql-go"
)

const cliVersion = "eql 1.0.0"

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-V") {
		fmt.Fprintln(stdout, cliVersion)
		return 0
	}
	if len(args) < 1 || args[0] != "query" {
		fmt.Fprintln(stderr, "usage: eql query [-f file] [--format json|jsonl] QUERY")
		return 2
	}
	if err := runQuery(args[1:], stdin, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runQuery(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	file := fs.String("f", "", "input file (.jsonl or .json)")
	fs.StringVar(file, "file", "", "input file (.jsonl or .json)")
	format := fs.String("format", "", "input format: json or jsonl (default: auto-detect from file extension, jsonl for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("query text required")
	}
	rule, err := eql.Compile(fs.Arg(0), eql.ImpliedAny(), eql.ImpliedBase())
	if err != nil {
		return err
	}

	// Determine format.
	useJSON := false
	if *format == "json" {
		useJSON = true
	} else if *format == "jsonl" {
		useJSON = false
	} else if *file != "" {
		ext := strings.ToLower(filepath.Ext(*file))
		useJSON = ext == ".json"
	}

	var r io.Reader = stdin
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	if useJSON {
		return streamJSON(r, stdout, rule)
	}
	return streamJSONL(r, stdout, rule)
}

// streamJSON reads a JSON array of event objects from r and processes each.
func streamJSON(r io.Reader, w io.Writer, rule *eql.Rule) error {
	eng := eql.NewEngine(rule)
	enc := json.NewEncoder(w)

	dec := json.NewDecoder(r)
	dec.UseNumber()

	// Expect opening '['.
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("expected JSON array")
	}

	for dec.More() {
		var data map[string]any
		if err := dec.Decode(&data); err != nil {
			return err
		}
		ev := eql.EventFromData(data)
		matches, err := eng.Feed(ev)
		if err != nil {
			return err
		}
		if err := encodeMatches(enc, matches); err != nil {
			return err
		}
	}

	// Consume closing ']'.
	if _, err := dec.Token(); err != nil {
		return err
	}

	matches, err := eng.Finalize()
	if err != nil {
		return err
	}
	return encodeMatches(enc, matches)
}

func streamJSONL(r io.Reader, w io.Writer, rule *eql.Rule) error {
	eng := eql.NewEngine(rule)
	scanner := bufio.NewScanner(r)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var data map[string]any
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return err
		}
		ev := eql.EventFromData(data)
		matches, err := eng.Feed(ev)
		if err != nil {
			return err
		}
		if err := encodeMatches(enc, matches); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	matches, err := eng.Finalize()
	if err != nil {
		return err
	}
	return encodeMatches(enc, matches)
}

func encodeMatches(enc *json.Encoder, matches []eql.Match) error {
	for _, match := range matches {
		for _, event := range match.Events {
			if err := enc.Encode(event.Data); err != nil {
				return err
			}
		}
	}
	return nil
}
