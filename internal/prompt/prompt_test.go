package prompt

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestFromAPipeItReadsToTheEndAfterSayingSo(t *testing.T) {
	var out bytes.Buffer
	got, err := ReadValue("Value: ", strings.NewReader("line one\nline two\n"), &out)
	if err != nil || got != "line one\nline two\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !strings.Contains(out.String(), "standard input until it ends") {
		t.Errorf("a run with nothing piped would wait in silence; output = %q", out.String())
	}
	if strings.Contains(out.String(), "line") {
		t.Errorf("the value was echoed: %q", out.String())
	}
}

func TestFromAnEmptyPipeItReturnsNothingForTheCallerToRefuse(t *testing.T) {
	got, err := ReadValue("Value: ", strings.NewReader(""), io.Discard)
	if err != nil || got != "" {
		t.Errorf("got %q, %v", got, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestAReadErrorIsNoValue(t *testing.T) {
	if _, err := ReadValue("Value: ", failingReader{}, io.Discard); !errors.Is(err, ErrNoValue) {
		t.Errorf("error = %v", err)
	}
}

// fakeTTY stands in for a terminal.
func fakeTTY(line string, readErr error, restored *bool) terminal {
	return terminal{
		getState: func(int) (*term.State, error) { return &term.State{}, nil },
		restore:  func(int, *term.State) error { *restored = true; return nil },
		read:     func(int) ([]byte, error) { return []byte(line), readErr },
	}
}

func TestFromATerminalItShowsThePromptAndABreakButNeverTheValue(t *testing.T) {
	var out bytes.Buffer
	var restored bool
	got, err := readHidden(0, "Value for x: ", &out, fakeTTY("hunter2", nil, &restored), make(chan os.Signal))
	if err != nil || got != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	if out.String() != "Value for x: \n" {
		t.Errorf("output = %q, want only the prompt and a line break", out.String())
	}
}

func TestCtrlDGivesUp(t *testing.T) {
	var restored bool
	_, err := readHidden(0, "p", io.Discard, fakeTTY("", io.EOF, &restored), make(chan os.Signal))
	if !errors.Is(err, ErrNoValue) {
		t.Errorf("error = %v", err)
	}
}

func TestCtrlCRestoresTheTerminalAndGivesUp(t *testing.T) {
	var out bytes.Buffer
	var restored bool
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	tty := terminal{
		getState: func(int) (*term.State, error) { return &term.State{}, nil },
		restore:  func(int, *term.State) error { restored = true; return nil },
		read:     func(int) ([]byte, error) { <-block; return nil, io.EOF },
	}
	interrupts := make(chan os.Signal, 1)
	interrupts <- os.Interrupt

	_, err := readHidden(0, "p", &out, tty, interrupts)
	if !errors.Is(err, ErrNoValue) {
		t.Errorf("error = %v", err)
	}
	if !restored {
		t.Error("echo was left off")
	}
}

func TestATerminalThatCannotBeReadIsRefused(t *testing.T) {
	tty := terminal{getState: func(int) (*term.State, error) { return nil, errors.New("not a tty") }}
	if _, err := readHidden(0, "p", io.Discard, tty, make(chan os.Signal)); err == nil {
		t.Error("expected an error")
	}
}
