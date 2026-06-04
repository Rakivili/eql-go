package eql

import (
	"errors"
	"fmt"
	"testing"

	internaldiag "github.com/Rakivili/eql-go/internal/diagnostic"
)

func TestAppErrorDiagnosticBridgesInternalDiagnostic(t *testing.T) {
	base := &internaldiag.Error{
		Class:   internaldiag.ClassSemantic,
		Message: "unknown function wildcrad",
		Pos:     14,
		Line:    1,
		Column:  15,
		Source:  `process where wildcrad(pid)`,
		Caret:   `              ^^^^^^^^`,
		Width:   8,
	}
	err := WrapError(CodeParse, "validate query", fmt.Errorf("outer: %w", base))
	var appErr *AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got %T", err)
	}
	diagnostic, ok := appErr.Diagnostic()
	if !ok {
		t.Fatal("expected internal diagnostic")
	}
	if diagnostic.Class != DiagnosticClassSemantic {
		t.Fatalf("Class=%q, want %q", diagnostic.Class, DiagnosticClassSemantic)
	}
	if diagnostic.Message != base.Message {
		t.Fatalf("Message=%q, want %q", diagnostic.Message, base.Message)
	}
	if diagnostic.Pos != base.Pos || diagnostic.Line != base.Line || diagnostic.Column != base.Column {
		t.Fatalf("position=%d/%d/%d, want %d/%d/%d", diagnostic.Pos, diagnostic.Line, diagnostic.Column, base.Pos, base.Line, base.Column)
	}
	if diagnostic.Source != base.Source || diagnostic.Caret != base.Caret || diagnostic.Width != base.Width {
		t.Fatalf("source diagnostic=%#v, want source=%q caret=%q width=%d", diagnostic, base.Source, base.Caret, base.Width)
	}
}

func TestPublicDiagnosticClassConstants(t *testing.T) {
	cases := map[DiagnosticClass]string{
		DiagnosticClassSyntax:       "syntax",
		DiagnosticClassSemantic:     "semantic",
		DiagnosticClassSchema:       "schema",
		DiagnosticClassTypeMismatch: "type_mismatch",
	}
	for class, want := range cases {
		if string(class) != want {
			t.Fatalf("class %q string=%q, want %q", class, string(class), want)
		}
	}
}
