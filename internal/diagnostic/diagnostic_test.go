package diagnostic

import (
	"strings"
	"testing"
)

func TestErrorWithoutSource(t *testing.T) {
	err := Semantic("unknown function wildcrad")
	if err.Error() != "unknown function wildcrad" {
		t.Fatalf("Error()=%q", err.Error())
	}
	if err.Width != 0 || err.Line != 0 || err.Column != 0 || err.Source != "" || err.Caret != "" {
		t.Fatalf("unexpected source fields: %#v", err)
	}
}

func TestErrorWithSource(t *testing.T) {
	err := New(ClassSemantic, "unknown function wildcrad", 14, 8, nil).WithSource(`process where wildcrad(pid)`)
	if err.Line != 1 || err.Column != 15 {
		t.Fatalf("line/column=%d/%d, want 1/15", err.Line, err.Column)
	}
	if err.Source != `process where wildcrad(pid)` {
		t.Fatalf("Source=%q", err.Source)
	}
	if !strings.Contains(err.Caret, "^^^^^^^^") {
		t.Fatalf("Caret=%q", err.Caret)
	}
	for _, want := range []string{
		"Error at line:1,column:15",
		"unknown function wildcrad",
		"process where wildcrad(pid)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Error()=%q, want %q", err.Error(), want)
		}
	}
}
