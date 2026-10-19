package onepassword

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

type call struct {
	args  []string
	stdin string
}

func recorder(out string, err error) (Runner, *[]call) {
	var calls []call
	return func(args []string, stdin string) (string, error) {
		calls = append(calls, call{args, stdin})
		return out, err
	}, &calls
}

func TestGetAsksForThePasswordFieldRevealedAndTrimsOneLineBreak(t *testing.T) {
	for out, want := range map[string]string{"v\n": "v", "v\r\n": "v", "v": "v", "v\n\n": "v\n"} {
		run, calls := recorder(out, nil)
		got, ok, err := (&Client{Vault: "Acme", Run: run}).Get("secretferry - acme-a")
		if err != nil || !ok || got != want {
			t.Errorf("Get(%q) = %q, %v, %v; want %q", out, got, ok, err, want)
		}
		args := strings.Join((*calls)[0].args, " ")
		if args != "item get secretferry - acme-a --vault Acme --fields label=password --reveal" {
			t.Errorf("args = %s", args)
		}
	}
}

func TestGetTreatsAFailedOpAsNoItem(t *testing.T) {
	run, _ := recorder("", errors.New("exit status 1"))
	got, ok, err := (&Client{Vault: "V", Run: run}).Get("t")
	if got != "" || ok || err != nil {
		t.Errorf("Get = %q, %v, %v", got, ok, err)
	}
}

func TestGetReportsAMissingCLI(t *testing.T) {
	run, _ := recorder("", ErrNotInstalled)
	if _, _, err := (&Client{Vault: "V", Run: run}).Get("t"); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("error = %v", err)
	}
}

func TestCreatePutsTheValueOnStandardInputAndNeverInAnArgument(t *testing.T) {
	run, calls := recorder("", nil)
	if err := (&Client{Vault: "Acme", Run: run}).Create("secretferry - acme-a", "THE-VALUE", "a note"); err != nil {
		t.Fatal(err)
	}
	c := (*calls)[0]
	if strings.Join(c.args, " ") != "item create --vault Acme -" {
		t.Errorf("args = %v", c.args)
	}
	for _, a := range c.args {
		if strings.Contains(a, "THE-VALUE") {
			t.Errorf("the value is in an argument: %v", c.args)
		}
	}
	var item struct {
		Title    string `json:"title"`
		Category string `json:"category"`
		Fields   []struct {
			Label, Value string
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(c.stdin), &item); err != nil {
		t.Fatalf("stdin is not JSON: %v", err)
	}
	if item.Title != "secretferry - acme-a" || item.Category != "PASSWORD" {
		t.Errorf("item = %+v", item)
	}
	got := map[string]string{}
	for _, f := range item.Fields {
		got[f.Label] = f.Value
	}
	if got["password"] != "THE-VALUE" || got["notesPlain"] != "a note" {
		t.Errorf("fields = %v", got)
	}
}

func TestCreateFailureSaysNothingOfTheValue(t *testing.T) {
	run, _ := recorder("", errors.New("op: THE-VALUE rejected"))
	err := (&Client{Vault: "V", Run: run}).Create("t", "THE-VALUE", "n")
	if err == nil || strings.Contains(err.Error(), "THE-VALUE") || !strings.Contains(err.Error(), "signed in") {
		t.Errorf("error = %v", err)
	}
	notInstalled, _ := recorder("", ErrNotInstalled)
	if err := (&Client{Vault: "V", Run: notInstalled}).Create("t", "v", "n"); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("error = %v", err)
	}
}

func TestRunnerFallsBackOnlyWhenAProgramCannotBeRun(t *testing.T) {
	missing := &exec.Error{Name: "op", Err: exec.ErrNotFound}
	cases := map[string]struct {
		results   map[string]error
		wantBins  []string
		wantError error
		wantOut   string
	}{
		"op works": {
			results: map[string]error{"op": nil}, wantBins: []string{"op"}, wantOut: "ok",
		},
		"op missing, op.exe works": {
			results: map[string]error{"op": missing, "op.exe": nil}, wantBins: []string{"op", "op.exe"}, wantOut: "ok",
		},
		"op cannot execute (ENOEXEC)": {
			results: map[string]error{"op": syscall.ENOEXEC, "op.exe": nil}, wantBins: []string{"op", "op.exe"}, wantOut: "ok",
		},
		"op not permitted (EACCES)": {
			results: map[string]error{"op": syscall.EACCES, "op.exe": nil}, wantBins: []string{"op", "op.exe"}, wantOut: "ok",
		},
		"an op that ran and failed is not run again as op.exe": {
			results: map[string]error{"op": errors.New("exit status 1")}, wantBins: []string{"op"}, wantError: errors.New("exit status 1"),
		},
		"neither can be run": {
			results: map[string]error{"op": missing, "op.exe": missing}, wantBins: []string{"op", "op.exe"}, wantError: ErrNotInstalled,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var tried []string
			run := newRunner(func(bin string, _ []string, _ string) (string, error) {
				tried = append(tried, bin)
				if err := c.results[bin]; err != nil {
					return "", err
				}
				return "ok", nil
			})
			out, err := run([]string{"x"}, "")
			if strings.Join(tried, ",") != strings.Join(c.wantBins, ",") {
				t.Errorf("tried %v, want %v", tried, c.wantBins)
			}
			if out != c.wantOut {
				t.Errorf("out = %q", out)
			}
			switch {
			case c.wantError == nil && err != nil:
				t.Errorf("error = %v", err)
			case c.wantError != nil && (err == nil || err.Error() != c.wantError.Error()):
				t.Errorf("error = %v, want %v", err, c.wantError)
			}
		})
	}
}
