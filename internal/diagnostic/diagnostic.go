package diagnostic

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Class identifies the compiler phase that produced a diagnostic.
type Class string

const (
	// ClassSyntax identifies parser syntax diagnostics.
	ClassSyntax Class = "syntax"

	// ClassSemantic identifies parser or validator semantic diagnostics.
	ClassSemantic Class = "semantic"

	// ClassSchema identifies schema lookup diagnostics.
	ClassSchema Class = "schema"

	// ClassTypeMismatch identifies type mismatch diagnostics.
	ClassTypeMismatch Class = "type_mismatch"
)

// Error carries a classified diagnostic and optional source-position details.
type Error struct {
	Class   Class
	Message string
	Pos     int
	Line    int
	Column  int
	Source  string
	Caret   string
	Width   int
	Node    any
	Err     error
}

// Span identifies a byte range in the original source.
type Span struct {
	Pos   int
	Width int
}

// New creates a diagnostic error for a source byte range.
func New(class Class, message string, pos int, width int, err error) *Error {
	return &Error{
		Class:   class,
		Message: message,
		Pos:     pos,
		Width:   width,
		Err:     err,
	}
}

// AttachNode attaches a source node to err if err is a *Error.
func AttachNode(err error, node any) error {
	if err == nil || node == nil {
		return err
	}
	var de *Error
	if !errors.As(err, &de) {
		return err
	}
	return de.WithNode(node)
}

// WithNode returns a copy associated with an internal source node.
func (e *Error) WithNode(node any) *Error {
	if e == nil {
		return nil
	}
	out := *e
	out.Node = node
	return &out
}

// Semantic reports semantic validation diagnostics.
func Semantic(message string) *Error {
	return New(ClassSemantic, message, 0, 0, nil)
}

// Semanticf formats a semantic validation diagnostic.
func Semanticf(format string, args ...any) *Error {
	return Semantic(fmt.Sprintf(format, args...))
}

// Schema reports schema lookup diagnostics.
func Schema(message string) *Error {
	return New(ClassSchema, message, 0, 0, nil)
}

// Schemaf formats a schema lookup diagnostic.
func Schemaf(format string, args ...any) *Error {
	return Schema(fmt.Sprintf(format, args...))
}

// TypeMismatch reports type mismatch diagnostics.
func TypeMismatch(message string) *Error {
	return New(ClassTypeMismatch, message, 0, 0, nil)
}

// TypeMismatchf formats a type mismatch diagnostic.
func TypeMismatchf(format string, args ...any) *Error {
	return TypeMismatch(fmt.Sprintf(format, args...))
}

// Error returns a human-readable diagnostic message.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Line > 0 && e.Column > 0 {
		return fmt.Sprintf("Error at line:%d,column:%d\n%s\n%s\n%s", e.Line, e.Column, e.Message, e.Source, e.Caret)
	}
	return e.Message
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// WithSource returns a copy enriched with source line, column, and caret data.
func (e *Error) WithSource(input string) *Error {
	return e.WithSourceSpan(input, Span{Pos: e.Pos, Width: e.Width})
}

// WithSourceSpan returns a copy enriched with source data for span.
func (e *Error) WithSourceSpan(input string, span Span) *Error {
	if e == nil {
		return nil
	}
	out := *e
	line, column, source, caret, width := sourceDetails(input, span.Pos, span.Width)
	out.Pos = span.Pos
	out.Line = line
	out.Column = column
	out.Source = source
	out.Caret = caret
	out.Width = width
	return &out
}

func sourceDetails(input string, pos int, width int) (line int, column int, source string, caret string, actualWidth int) {
	if pos < 0 {
		pos = 0
	}
	if pos > len(input) {
		pos = len(input)
	}
	lineStarts := []int{0}
	for i, r := range input {
		if r == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	lineIdx := sort.Search(len(lineStarts), func(i int) bool {
		return lineStarts[i] > pos
	}) - 1
	if lineIdx < 0 {
		lineIdx = 0
	}
	lineStart := lineStarts[lineIdx]
	lineEnd := len(input)
	if lineIdx+1 < len(lineStarts) {
		lineEnd = lineStarts[lineIdx+1] - 1
	}
	if lineEnd > lineStart && input[lineEnd-1] == '\r' {
		lineEnd--
	}
	if lineEnd < lineStart {
		lineEnd = lineStart
	}
	source = input[lineStart:lineEnd]
	column0 := pos - lineStart
	if column0 < 0 {
		column0 = 0
	}
	if column0 > len(source) {
		column0 = len(source)
	}
	if width < 1 {
		width = 1
	}
	if remaining := len(source) - column0; remaining > 0 && width > remaining {
		width = remaining
	}
	if width < 1 {
		width = 1
	}
	return lineIdx + 1, column0 + 1, source, caretLine(source, column0, width), width
}

func caretLine(source string, column0 int, width int) string {
	var b strings.Builder
	for i := 0; i < column0 && i < len(source); i++ {
		if source[i] == '\t' {
			b.WriteByte('\t')
		} else {
			b.WriteByte(' ')
		}
	}
	for i := 0; i < width; i++ {
		b.WriteByte('^')
	}
	return b.String()
}
