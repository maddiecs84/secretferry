// Package ferry holds what every other package shares: the error type whose
// message is safe to print.
package ferry

import "fmt"

// Error is a failure whose message is written for the person at the terminal.
// Nothing that builds one may put a secret value in it: that is the rule the
// whole tool is shaped around, so messages are fixed text plus names.
type Error struct{ msg string }

// Errorf makes an Error. Never pass a secret value as an argument.
func Errorf(format string, args ...any) *Error {
	return &Error{msg: fmt.Sprintf(format, args...)}
}

func (e *Error) Error() string { return e.msg }
