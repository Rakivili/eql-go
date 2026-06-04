package eql

import (
	"errors"

	internaldiag "github.com/Rakivili/eql-go/internal/diagnostic"
	"github.com/Rakivili/eql-go/internal/parser"
)

// DiagnosticClass identifies the compiler phase that produced a diagnostic.
type DiagnosticClass string

const (
	// DiagnosticClassSyntax reports syntax diagnostics produced by the parser.
	DiagnosticClassSyntax DiagnosticClass = "syntax"
	// DiagnosticClassSemantic reports semantic validation diagnostics.
	DiagnosticClassSemantic DiagnosticClass = "semantic"
	// DiagnosticClassSchema reports schema validation diagnostics.
	DiagnosticClassSchema DiagnosticClass = "schema"
	// DiagnosticClassTypeMismatch reports type mismatch diagnostics.
	DiagnosticClassTypeMismatch DiagnosticClass = "type_mismatch"
)

// ErrorDiagnostic contains source-position details for an AppError.
type ErrorDiagnostic struct {
	// Class is the category of diagnostic.
	Class DiagnosticClass

	// Message is the diagnostic message without source/caret rendering.
	Message string

	// Pos is the zero-based byte offset in the original query.
	Pos int

	// Line is the one-based source line number.
	Line int

	// Column is the one-based byte column within Source.
	Column int

	// Source is the single source line containing the diagnostic.
	Source string

	// Caret is the pre-rendered caret marker line for Source.
	Caret string

	// Width is the diagnostic width in bytes.
	Width int
}

// Diagnostic returns compile-time diagnostic details when they are available.
func (e *AppError) Diagnostic() (ErrorDiagnostic, bool) {
	if e == nil || e.Code != CodeParse || e.Err == nil {
		return ErrorDiagnostic{}, false
	}
	var diagErr *internaldiag.Error
	if errors.As(e.Err, &diagErr) {
		return ErrorDiagnostic{
			Class:   publicDiagnosticClass(diagErr.Class),
			Message: diagErr.Message,
			Pos:     diagErr.Pos,
			Line:    diagErr.Line,
			Column:  diagErr.Column,
			Source:  diagErr.Source,
			Caret:   diagErr.Caret,
			Width:   diagErr.Width,
		}, true
	}
	var parseErr *parser.ParseError
	if !errors.As(e.Err, &parseErr) {
		return ErrorDiagnostic{}, false
	}
	return ErrorDiagnostic{
		Class:   DiagnosticClassSyntax,
		Message: parseErr.Message,
		Pos:     parseErr.Pos,
		Line:    parseErr.Line,
		Column:  parseErr.Column,
		Source:  parseErr.Source,
		Caret:   parseErr.Caret,
		Width:   parseErr.Width,
	}, true
}

func publicDiagnosticClass(class internaldiag.Class) DiagnosticClass {
	switch class {
	case internaldiag.ClassSemantic:
		return DiagnosticClassSemantic
	case internaldiag.ClassSchema:
		return DiagnosticClassSchema
	case internaldiag.ClassTypeMismatch:
		return DiagnosticClassTypeMismatch
	default:
		return DiagnosticClassSyntax
	}
}
