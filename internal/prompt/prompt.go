// Package prompt reads a secret's value so that it is never echoed, kept in
// history or put in an argument.
package prompt

import (
	"io"
	"os"
	"os/signal"

	"golang.org/x/term"

	"github.com/maddiecs84/secretferry/internal/ferry"
)

// ErrNoValue is what giving up (Ctrl-C, Ctrl-D, an empty pipe) ends in.
var ErrNoValue = ferry.Errorf("No value was given.")

// Terminal is a standard input that can be a terminal.
type Terminal interface {
	io.Reader
	Fd() uintptr
}

// ReadValue returns the value. From a terminal it is one line, typed or pasted
// at a prompt that shows nothing of it: the prompt, and a line break when Enter
// is pressed. From anything else it is standard input to the end, after a line
// on out saying so, because a run with nothing piped would otherwise wait with
// nothing on the screen. A multi-line value goes in through a file on standard
// input. The answer is never written to out.
func ReadValue(promptText string, in io.Reader, out io.Writer) (string, error) {
	file, isFile := in.(Terminal)
	if !isFile || !term.IsTerminal(int(file.Fd())) {
		_, _ = io.WriteString(out, "Reading the value from standard input until it ends.\n")
		raw, err := io.ReadAll(in)
		if err != nil {
			return "", ErrNoValue
		}
		return string(raw), nil
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	return readHidden(int(file.Fd()), promptText, out, realTerminal, interrupts)
}

// terminal is the part of golang.org/x/term the prompt uses, so a test can stand in for a tty.
type terminal struct {
	getState func(fd int) (*term.State, error)
	restore  func(fd int, state *term.State) error
	read     func(fd int) ([]byte, error)
}

var realTerminal = terminal{getState: term.GetState, restore: term.Restore, read: term.ReadPassword}

// readHidden reads a line with echo off. Ctrl-C would otherwise leave the
// terminal with echo off, so the state is restored when it arrives.
func readHidden(fd int, promptText string, out io.Writer, tty terminal, interrupts <-chan os.Signal) (string, error) {
	state, err := tty.getState(fd)
	if err != nil {
		return "", ferry.Errorf("could not read from the terminal")
	}
	_, _ = io.WriteString(out, promptText)
	type answer struct {
		line []byte
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		line, err := tty.read(fd)
		done <- answer{line, err}
	}()

	select {
	case <-interrupts:
		_ = tty.restore(fd, state)
		_, _ = io.WriteString(out, "\n")
		return "", ErrNoValue
	case a := <-done:
		_, _ = io.WriteString(out, "\n")
		if a.err != nil {
			return "", ErrNoValue
		}
		return string(a.line), nil
	}
}
