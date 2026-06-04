package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// TOMLCases contains conformance cases extracted from one Python EQL TOML file.
type TOMLCases struct {
	Fold       []TOMLFoldCase       `json:"fold"`
	Optimizer  []TOMLOptimizerCase  `json:"optimizer"`
	Equivalent []TOMLEquivalentCase `json:"equivalent"`
	Verifier   []TOMLVerifierCase   `json:"verifier"`
}

// TOMLFoldCase contains one expanded folding test case.
type TOMLFoldCase struct {
	File          string `json:"file"`
	Group         string `json:"group"`
	Expression    string `json:"expression"`
	Expected      string `json:"expected"`
	CaseSensitive bool   `json:"case_sensitive"`
}

// TOMLOptimizerCase contains one expanded optimizer test case.
type TOMLOptimizerCase struct {
	File       string `json:"file"`
	Group      string `json:"group"`
	Expression string `json:"expression"`
	Optimized  string `json:"optimized"`
}

// TOMLEquivalentCase contains one expanded optimizer-equivalence test case.
type TOMLEquivalentCase struct {
	File       string `json:"file"`
	Group      string `json:"group"`
	Expression string `json:"expression"`
	Alternate  string `json:"alternate"`
}

// TOMLVerifierCase contains one expected semantic failure case.
type TOMLVerifierCase struct {
	File       string `json:"file"`
	Group      string `json:"group"`
	Expression string `json:"expression"`
}

// TOMLQueryCase contains one expanded event-stream query conformance case.
type TOMLQueryCase struct {
	File             string   `json:"file"`
	Index            int      `json:"index"`
	Query            string   `json:"query"`
	ExpectedEventIDs []int64  `json:"expected_event_ids"`
	CaseSensitive    bool     `json:"case_sensitive"`
	Tags             []string `json:"tags"`
	Note             string   `json:"note"`
}

// LoadTOMLCases loads and expands Python EQL TOML conformance cases.
func LoadTOMLCases(ctx context.Context, pythonRepo string, fileName string) (TOMLCases, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]string{"file_name": fileName}
	body, err := json.Marshal(payload)
	if err != nil {
		return TOMLCases{}, err
	}
	script := `
import json, os, string, sys
import eql
import eql.etc
try:
    import tomllib as toml_reader
except ImportError:
    import tomli as toml_reader

payload = json.load(sys.stdin)
file_name = payload["file_name"]
with open(eql.etc.get_etc_path(file_name), "rb") as f:
    data = toml_reader.load(f)

type_values = {
    "null": None,
    "bool": True,
    "int": 1,
    "string": "string",
    "float": 1.5,
}

result = {"fold": [], "optimizer": [], "equivalent": [], "verifier": []}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def literal_for(type_name):
    return str(eql.ast.Literal.from_python(type_values[type_name]))

def case_settings(contents):
    if "case_sensitive" not in contents and "case_insensitive" not in contents:
        return [True, False]
    settings = []
    if contents.get("case_sensitive") is True:
        settings.append(True)
    if contents.get("case_insensitive") is True:
        settings.append(False)
    if not settings:
        raise AssertionError("%s is missing case_sensitive/case_insensitive" % file_name)
    return settings

def extract(group, contents, settings, params=None):
    params = dict(params or {})
    for param in contents.get("params", []):
        params[param["name"]] = literal_for(param["type"])

    def parametrize(expr):
        if params:
            return string.Template(expr).substitute(params)
        return expr

    for fold_test in contents.get("fold", {}).get("tests", []):
        expected = fold_test.get("expected", None)
        for case_sensitive in settings:
            result["fold"].append({
                "file": file_name,
                "group": group,
                "expression": parametrize(fold_test["expression"]),
                "expected": canonical(expected),
                "case_sensitive": case_sensitive,
            })

    for optimizer_test in contents.get("optimizer", {}).get("tests", []):
        result["optimizer"].append({
            "file": file_name,
            "group": group,
            "expression": parametrize(optimizer_test["expression"]),
            "optimized": parametrize(optimizer_test["optimized"]),
        })

    for equivalent_test in contents.get("equivalent", {}).get("tests", []):
        result["equivalent"].append({
            "file": file_name,
            "group": group,
            "expression": parametrize(equivalent_test["expression"]),
            "alternate": parametrize(equivalent_test["alternate"]),
        })

    for verifier_failure in contents.get("verifier", {}).get("failures", []):
        result["verifier"].append({
            "file": file_name,
            "group": group,
            "expression": parametrize(verifier_failure["expression"]),
        })

    for loop in contents.get("loop", []):
        for param_type in loop["param"]["type"]:
            nested = dict(loop)
            nested["params"] = [{
                "type": param_type,
                "name": loop["param"]["name"],
            }]
            extract(group, nested, settings, params)

for group, contents in sorted(data.items()):
    extract(group, contents, case_settings(contents))

print(json.dumps(result, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return TOMLCases{}, fmt.Errorf("python TOML loader: %w: %s", err, bytes.TrimSpace(out))
	}
	var cases TOMLCases
	if err := json.Unmarshal(bytes.TrimSpace(out), &cases); err != nil {
		return TOMLCases{}, err
	}
	return cases, nil
}

// LoadTOMLQueries loads and expands Python EQL query TOML conformance cases.
func LoadTOMLQueries(ctx context.Context, pythonRepo string, fileName string) ([]TOMLQueryCase, error) {
	if pythonRepo == "" {
		pythonRepo = DefaultPythonRepo()
	}
	payload := map[string]string{"file_name": fileName}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	script := `
import json, sys
import eql.etc
try:
    import tomllib as toml_reader
except ImportError:
    import tomli as toml_reader

payload = json.load(sys.stdin)
file_name = payload["file_name"]
with open(eql.etc.get_etc_path(file_name), "rb") as f:
    data = toml_reader.load(f)

result = []

def case_settings(contents):
    if "case_sensitive" not in contents and "case_insensitive" not in contents:
        return [True, False]
    settings = []
    if contents.get("case_sensitive") is True:
        settings.append(True)
    if contents.get("case_insensitive") is True:
        settings.append(False)
    if not settings:
        raise AssertionError("%s query has no enabled case setting" % file_name)
    return settings

for index, query_case in enumerate(data.get("queries", [])):
    for case_sensitive in case_settings(query_case):
        result.append({
            "file": file_name,
            "index": index,
            "query": query_case["query"],
            "expected_event_ids": query_case.get("expected_event_ids", []),
            "case_sensitive": case_sensitive,
            "tags": query_case.get("tags", []),
            "note": query_case.get("note", query_case.get("notes", "")),
        })

print(json.dumps(result, sort_keys=True, separators=(",", ":")))
`
	cmd := exec.CommandContext(ctx, "python3", "-c", script)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonRepo)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python query TOML loader: %w: %s", err, bytes.TrimSpace(out))
	}
	var cases []TOMLQueryCase
	if err := json.Unmarshal(bytes.TrimSpace(out), &cases); err != nil {
		return nil, err
	}
	return cases, nil
}
