package app

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/config"
	"github.com/maddiecs84/secretferry/internal/testfake"
)

// forbiddenReader fails the test if anything reads from it.
type forbiddenReader struct{ t *testing.T }

func (f forbiddenReader) Read([]byte) (int, error) {
	f.t.Helper()
	f.t.Error("standard input was read")
	return 0, io.EOF
}

// answers is what a person types: each answer ends with Enter.
func answers(lines ...string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// guided is a harness whose standard input is a terminal that types input, in a project directory
// whose name needs tidying, with a configuration made by init.
func guided(t *testing.T, input string) (*harness, string) {
	t.Helper()
	h, root := configHarness(t)
	dir := filepath.Join(root, "My Project_X")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	h.env.Getwd = func() (string, error) { return dir, nil }
	if code := h.runPlain("config", "init", "--account", testfake.Account, "--vault", "Acme"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, h.stderr.String())
	}
	h.env.Stdin = strings.NewReader(input)
	h.env.StdinIsTerminal = func() bool { return true }
	return h, filepath.Join(dir, "secretferry.json")
}

func loadKind(t *testing.T, path, kind string) *config.Kind {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("does not load: %v\n%s", err, read(t, path))
	}
	k, ok := cfg.Kind(kind)
	if !ok {
		t.Fatalf("no kind %q in:\n%s", kind, read(t, path))
	}
	return k
}

func TestGuidedWithEveryDefault(t *testing.T) {
	// Only the kind is typed; everything else is Enter. Over Windows line endings too.
	for name, input := range map[string]string{
		"unix":    answers("signing-key", "", "", "", "", "", "", ""),
		"windows": strings.ReplaceAll(answers("signing-key", "", "", "", "", "", "", ""), "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			h, path := guided(t, input)
			if code := h.runPlain("config", "add-secret"); code != 0 {
				t.Fatalf("exit %d: %s", code, h.stderr.String())
			}
			k := loadKind(t, path, "signing-key")
			want := config.Secret{
				Kind:     "signing-key",
				Name:     "my-project-x-{env}-signing-key", // the directory's name, tidied
				Params:   map[string]string{"env": "(sandbox|staging|production)-[0-9]{2}"},
				Value:    config.ValueRule{Rule: "base64-32"},
				Generate: "base64-32",
				Defaults: map[string][]string{"env": {"sandbox-01", "staging-01", "production-01"}},
			}
			if !reflect.DeepEqual(k.Secret, want) {
				t.Errorf("got  %+v\nwant %+v", k.Secret, want)
			}
		})
	}
}

func TestGuidedShowsItsDefaultsAndTheCommandThatDoesTheSame(t *testing.T) {
	h, path := guided(t, answers("signing-key", "", "", "", "", "", "", ""))
	h.runPlain("config", "add-secret")
	out := h.stdout.String()
	for _, want := range []string{
		"Adding a secret to " + path,
		"Kind: a short name for this secret, such as signing-key [api-key]: ",
		"Name template [my-project-x-{env}-signing-key]: ",
		"Pattern for {env} [(sandbox|staging|production)-[0-9]{2}]: ",
		"1. secretferry makes it: 32 random bytes as padded base64",
		"3. someone else issues it",
		"Choice [1]: ",
		"Values for {env} [sandbox-01,staging-01,production-01]: ",
		"This will add to " + path,
		"provision makes by default: my-project-x-production-01-signing-key, my-project-x-sandbox-01-signing-key, my-project-x-staging-01-signing-key",
		"secretferry config add-secret --kind signing-key --template 'my-project-x-{env}-signing-key' --pattern 'env=(sandbox|staging|production)-[0-9]{2}' --rule base64-32 --generate base64-32 --default env=sandbox-01 --default env=staging-01 --default env=production-01",
		"Add it? [Y]: ",
		"Added signing-key to " + path,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	h.assertNothingLeftTheMachine()
}

func TestGuidedWithAnswersOfItsOwn(t *testing.T) {
	h, path := guided(t, answers(
		"vendor-key",
		"acme-{env}-{region}-vendor",
		"", "(eu|us)", // patterns: env takes the default
		"3",                                      // someone else issues it
		"regex:sk-[a-z]+", "Use the vendor key.", // its rule, and what to say when it fails
		"sandbox-01,staging-01", "eu", // values for env, region
		"the vendor must reissue it.",
		"y",
	))
	if code := h.runPlain("config", "add-secret"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	k := loadKind(t, path, "vendor-key")
	want := config.Secret{
		Kind: "vendor-key",
		Name: "acme-{env}-{region}-vendor",
		Params: map[string]string{
			"env":    "(sandbox|staging|production)-[0-9]{2}",
			"region": "(eu|us)",
		},
		Value:         config.ValueRule{Rule: "regex:sk-[a-z]+", Message: "Use the vendor key."},
		Defaults:      map[string][]string{"env": {"sandbox-01", "staging-01"}, "region": {"eu"}},
		RotateWarning: "the vendor must reissue it.",
	}
	if !reflect.DeepEqual(k.Secret, want) {
		t.Errorf("got  %+v\nwant %+v", k.Secret, want)
	}
	if !strings.Contains(h.stdout.String(), "supplied with set") {
		t.Errorf("the summary does not say who makes the value:\n%s", h.stdout.String())
	}
}

func TestGuidedIssuedElsewhereOffersNoDefaultValuesAndTheStandardRule(t *testing.T) {
	// Enter all the way: a key someone else issues is "printable", and no environments are assumed.
	h, path := guided(t, answers("vendor-key", "", "", "3", "", "", "", ""))
	if code := h.runPlain("config", "add-secret"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	k := loadKind(t, path, "vendor-key")
	if k.Generate != "" || k.Value.Rule != "printable" || len(k.Defaults) != 0 {
		t.Errorf("got %+v", k.Secret)
	}
	if strings.Contains(h.stdout.String(), "Values for {env} [") {
		t.Errorf("default environments were offered for a key someone else issues:\n%s", h.stdout.String())
	}
}

func TestGuidedAsksAgainOnABadAnswerAndSaysWhy(t *testing.T) {
	h, path := guided(t, "")
	if code := h.runPlain("config", "add-secret", "--kind", "taken", "--template", "acme-taken"); code != 0 {
		t.Fatalf("setup: exit %d: %s", code, h.stderr.String())
	}
	h.env.Stdin = strings.NewReader(answers(
		"Bad Kind", "taken", "fresh", // kind
		"{broken", "acme-{env}-fresh", // template
		"(", "[a-z]+-[0-9]+", // the pattern for env
		"9", "abc", "", // who makes it
		"UPPER-01", "", // values for env
		"",           // warning
		"maybe", "y", // confirm
	))
	if code := h.runPlain("config", "add-secret"); code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, h.stderr.String(), h.stdout.String())
	}
	out := h.stdout.String()
	// Each bad answer gets its message once: two bad choices ("9", "abc") give it twice.
	for want, times := range map[string]int{
		"A kind is lower-case letters, digits and hyphens.": 1,
		"There is already a secret of that kind.":           1,
		"stray brace": 1,
		"That is not a valid regular expression.":          1,
		"Choose a number from 1 to 3.":                     2,
		`"UPPER-01" does not match the pattern for {env}.`: 1,
		"Answer y or n.":                                   1,
	} {
		if got := strings.Count(out, want); got != times {
			t.Errorf("%q appears %d times, want %d:\n%s", want, got, times, out)
		}
	}
	k := loadKind(t, path, "fresh")
	if k.Name != "acme-{env}-fresh" || k.Params["env"] != "[a-z]+-[0-9]+" || strings.Join(k.Defaults["env"], ",") != defaultsEnv {
		t.Errorf("got %+v", k.Secret)
	}
}

func TestGuidedOffersNoKindWhenTheSuggestionIsTaken(t *testing.T) {
	h, path := guided(t, "")
	if code := h.runPlain("config", "add-secret", "--kind", "api-key", "--template", "acme-api"); code != 0 {
		t.Fatalf("setup: exit %d: %s", code, h.stderr.String())
	}
	h.env.Stdin = strings.NewReader(answers("", "second", "", "", "", "", "", ""))
	if code := h.runPlain("config", "add-secret"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	out := h.stdout.String()
	if strings.Contains(out, "such as signing-key [api-key]") || strings.Count(out, "A kind is needed.") != 1 {
		t.Errorf("output:\n%s", out)
	}
	loadKind(t, path, "second")
}

func TestGuidedWithATemplateThatHasNoPlaceholders(t *testing.T) {
	h, path := guided(t, answers("fixed", "acme-fixed", "", "", ""))
	if code := h.runPlain("config", "add-secret"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	k := loadKind(t, path, "fixed")
	if len(k.Params) != 0 || len(k.Defaults) != 0 || k.Generate != "base64-32" {
		t.Errorf("got %+v", k.Secret)
	}
	if strings.Contains(h.stdout.String(), "Pattern for") || strings.Contains(h.stdout.String(), "Values for") {
		t.Errorf("it asked about placeholders there are none of:\n%s", h.stdout.String())
	}
	if !strings.Contains(h.stdout.String(), "provision makes by default: acme-fixed") {
		t.Errorf("output:\n%s", h.stdout.String())
	}
	if text := read(t, path); strings.Contains(text, `"params"`) || strings.Contains(text, `"defaults"`) {
		t.Errorf("empty fields were written:\n%s", text)
	}
}

func TestGuidedDeclineAndCancelWriteNothing(t *testing.T) {
	for name, c := range map[string]struct {
		input    string
		wantExit int
		want     string
	}{
		"declined at the end":      {answers("signing-key", "", "", "", "", "", "n"), 0, "Nothing was written."},
		"input ends at a question": {answers("signing-key"), 1, "Cancelled; nothing was written."},
		"input ends straight away": {"", 1, "Cancelled; nothing was written."},
	} {
		t.Run(name, func(t *testing.T) {
			h, path := guided(t, c.input)
			before := read(t, path)
			code := h.runPlain("config", "add-secret")
			got := h.stdout.String() + h.stderr.String()
			if code != c.wantExit || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output:\n%s", code, got)
			}
			if read(t, path) != before {
				t.Error("the file changed")
			}
		})
	}
}

func TestGuidedLastCheckRefusesAndSaysNothingWasWritten(t *testing.T) {
	h, path := guided(t, "")
	if code := h.runPlain("config", "add-secret", "--kind", "signing-key", "--template", "acme-{env}-signing-key",
		"--pattern", "env=[a-z]+-[0-9]{2}", "--default", "env=sandbox-01"); code != 0 {
		t.Fatalf("setup: exit %d: %s", code, h.stderr.String())
	}
	before := read(t, path)
	// A different kind whose template and default produce the same name as the first.
	h.env.Stdin = strings.NewReader(answers("other", "acme-{env}-signing-key", "[a-z]+-[0-9]{2}", "", "", "", ""))
	if code := h.runPlain("config", "add-secret"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "both produce") || !strings.Contains(h.stderr.String(), "Nothing was written.") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if read(t, path) != before {
		t.Error("the file changed")
	}
}

func TestAddSecretOnlyAsksQuestionsAtATerminalWithNoFlags(t *testing.T) {
	t.Run("not a terminal: it says what to do and reads nothing", func(t *testing.T) {
		h, path := guided(t, "")
		h.env.StdinIsTerminal = func() bool { return false }
		h.env.Stdin = forbiddenReader{t}
		before := read(t, path)
		if code := h.runPlain("config", "add-secret"); code != 1 || !strings.Contains(h.stderr.String(), "needs --kind and --template") || !strings.Contains(h.stderr.String(), "guided setup") {
			t.Errorf("exit %d, stderr %q", code, h.stderr.String())
		}
		if read(t, path) != before {
			t.Error("the file changed")
		}
	})
	t.Run("no terminal known at all", func(t *testing.T) {
		h, _ := guided(t, "")
		h.env.StdinIsTerminal = nil
		h.env.Stdin = forbiddenReader{t}
		if code := h.runPlain("config", "add-secret"); code != 1 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("flags given: nothing is asked, even at a terminal", func(t *testing.T) {
		h, path := guided(t, "")
		h.env.Stdin = forbiddenReader{t}
		if code := h.runPlain("config", "add-secret", "--kind", "k", "--template", "acme-k"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		loadKind(t, path, "k")
		if strings.Contains(h.stdout.String(), "Press Enter") {
			t.Errorf("the guide started:\n%s", h.stdout.String())
		}
	})
	t.Run("some flags but not the required ones: refused, not guessed at", func(t *testing.T) {
		h, _ := guided(t, "")
		h.env.Stdin = forbiddenReader{t}
		for _, args := range [][]string{
			{"--kind", "k"},
			{"--template", "acme-k"},
			{"--rule", "any"},
			{"--rotate-warning", "x"},
		} {
			if code := h.runPlain(append([]string{"config", "add-secret"}, args...)...); code != 1 || !strings.Contains(h.stderr.String(), "needs --kind and --template") {
				t.Errorf("%v: exit %d, stderr %q", args, code, h.stderr.String())
			}
		}
	})
	t.Run("--config alone does not count as a flag", func(t *testing.T) {
		h, path := guided(t, answers("k", "", "", "", "", "", "", ""))
		if code := h.runPlain("config", "add-secret", "--config", path); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		loadKind(t, path, "k")
	})
}

func TestGuidedNeedsAFileLikeEveryOtherWayOfAdding(t *testing.T) {
	h, _ := configHarness(t)
	h.env.StdinIsTerminal = func() bool { return true }
	h.env.Stdin = forbiddenReader{t}
	if code := h.runPlain("config", "add-secret"); code != 1 || !strings.Contains(h.stderr.String(), "secretferry config init") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
}

// ---- the command it prints ----

func TestThePrintedCommandDescribesTheSameSecret(t *testing.T) {
	secrets := []config.Secret{
		{Kind: "k", Name: "acme-k"},
		{
			Kind: "signing-key", Name: "acme-{env}-{region}-key",
			Params:        map[string]string{"env": "(a|b)", "region": "[a-z]+"},
			Value:         config.ValueRule{Rule: "regex:x+", Message: `say "this" & that's it`},
			Generate:      "",
			Defaults:      map[string][]string{"env": {"a", "b"}, "region": {"eu"}},
			RotateWarning: "has a space, a 'quote' and a $dollar `tick`",
		},
		{
			Kind: "gen", Name: "acme-{env}-gen",
			Params:   map[string]string{"env": "(sandbox|staging)-[0-9]{2}"},
			Value:    config.ValueRule{Rule: "base64url-32"},
			Generate: "base64url-32",
			Defaults: map[string][]string{"env": {"sandbox-01"}},
		},
	}
	for _, want := range secrets {
		opts, err := parseOptions("config add-secret", secretArgs(want), commandFlags["config add-secret"])
		if err != nil {
			t.Fatalf("%s: the arguments do not parse: %v", want.Kind, err)
		}
		got, err := secretFromOptions(opts)
		if err != nil {
			t.Fatalf("%s: %v", want.Kind, err)
		}
		if want.Params == nil {
			want.Params = map[string]string{}
		}
		if want.Defaults == nil {
			want.Defaults = map[string][]string{}
		}
		if got.Defaults == nil {
			got.Defaults = map[string][]string{}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s\ngot  %+v\nwant %+v", want.Kind, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":         "plain",
		"a-b_c.d/e:f=g": "a-b_c.d/e:f=g",
		"a b":           "'a b'",
		"it's":          `'it'\''s'`,
		"{env}":         "'{env}'",
		"(a|b)":         "'(a|b)'",
		"$HOME":         "'$HOME'",
		"":              "''",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestProjectNameForTheDefaultTemplate(t *testing.T) {
	for path, want := range map[string]string{
		"/work/My Project_X/secretferry.json": "my-project-x",
		"/work/acme/secretferry.json":         "acme",
		"/work/--weird--/secretferry.json":    "weird",
		"/work/___/secretferry.json":          "myapp",
		"/secretferry.json":                   "myapp",
	} {
		if got := project(path); got != want {
			t.Errorf("project(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestGuidedOffersAPatternForEachPlaceholderByItsName(t *testing.T) {
	// env, version and any other placeholder each get their own default, and only env gets default values.
	h, path := guided(t, answers("wrap", "acme-{env}-{zone}-wrap-{version}", "", "", "", "", "", "", "", "", ""))
	if code := h.runPlain("config", "add-secret"); code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, h.stderr.String(), h.stdout.String())
	}
	k := loadKind(t, path, "wrap")
	wantParams := map[string]string{"env": patternEnv, "zone": patternWord, "version": patternVersion}
	if !reflect.DeepEqual(k.Params, wantParams) {
		t.Errorf("params = %v, want %v", k.Params, wantParams)
	}
	if !reflect.DeepEqual(k.Defaults, map[string][]string{"env": {"sandbox-01", "staging-01", "production-01"}}) {
		t.Errorf("defaults = %v: only env has values worth offering", k.Defaults)
	}
}
