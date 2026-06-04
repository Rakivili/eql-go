package eql

import "fmt"

// ErrorCode identifies a stable category of application error.
type ErrorCode int

const (
	// CodeParse reports invalid or unsupported EQL source text.
	CodeParse ErrorCode = 1001

	// CodeRuntime reports a failure while evaluating compiled rules.
	CodeRuntime ErrorCode = 2001
)

// AppError is the public error type returned for EQL application failures.
type AppError struct {
	Code ErrorCode
	Msg  string
	Err  error
}

// Error returns a human-readable error message.
func (e *AppError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("eql error %d: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("eql error %d: %s: %v", e.Code, e.Msg, e.Err)
}

// Unwrap returns the underlying cause.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// WrapError converts an error into an AppError with the supplied code.
func WrapError(code ErrorCode, msg string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*AppError); ok {
		return err
	}
	return &AppError{Code: code, Msg: msg, Err: err}
}
