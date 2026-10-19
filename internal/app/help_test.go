package app

import (
	"sort"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/config"
)

// helpHarness has nothing a command could use: no token, no configuration file, no terminal, no input.
func helpHarness(t *testing.T) *harness {
	t.Helper()
	h, _ := configHarness(t)
	h.env.Stdin = forbiddenReader{t}
	return h
}

func (h *harness) helpOf(args ...string) (stdout string, code int) {
	h.t.Helper()
	code = h.runPlain(args...)
	return h.stdout.String(), code
}

// shellSplit splits a documented example the way a POSIX shell would: single quotes, and a
// backslash at the end of a line continuing it.
func shellSplit(t *testing.T, line string) []string {
	t.Helper()
	line = strings.ReplaceAll(line, "\\\n", " ")
	var words []string
	var cur strings.Builder
	inWord, quoted := false, false
	for _, r := range line {
		switch {
		case quoted:
			if r == '\'' {
				quoted = false
			} else {
				cur.WriteRune(r)
			}
		case r == '\'':
			quoted, inWord = true, true
		case r == ' ' || r == '\n' || r == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quoted {
		t.Fatalf("unterminated quote in %q", line)
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

func TestOverviewListsEveryCommandAndWhatTheyNeed(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		h := helpHarness(t)
		out, code := h.helpOf(args...)
		if code != 0 || h.stderr.Len() != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, h.stderr.String())
		}
		for _, want := range []string{
			"Usage:", "secretferry <command> [options]",
			"  set ", "  rotate ", "  list ", "  check ", "  provision ", "  config ", "  version ", "  help ",
			"secretferry <command> --help",
			"Configuration:", "secretferry config init", "secretferry config add-secret",
			"Environment:", "CLOUDFLARE_API_TOKEN", "Secrets Store: Edit", "wrangler auth token", "CLOUDFLARE_ACCOUNT_ID",
			"Exit status: 0 on success, 1 on an error, 2 when run with no arguments.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%v: the overview lacks %q:\n%s", args, want, out)
			}
		}
		h.assertNothingLeftTheMachine()
	}

	// Run with nothing, it shows the same overview but exits 2, as for a mistake.
	h := helpHarness(t)
	out, code := h.helpOf()
	if code != 2 || !strings.HasPrefix(out, "secretferry moves a secret") || !strings.Contains(out, "Usage:") {
		t.Errorf("no arguments: exit %d, stdout %q", code, out)
	}
}

func TestEveryCommandHasHelpAtEveryRouteAndItIsTheSameText(t *testing.T) {
	for name := range commandFlags {
		words := strings.Fields(name)
		var texts []string
		for _, route := range [][]string{
			append(append([]string{}, words...), "--help"),
			append(append([]string{}, words...), "-h"),
			append([]string{"help"}, words...),
		} {
			h := helpHarness(t)
			out, code := h.helpOf(route...)
			if code != 0 || h.stderr.Len() != 0 {
				t.Errorf("%v: exit %d, stderr %q", route, code, h.stderr.String())
			}
			if !strings.Contains(out, "Usage:") || !strings.Contains(out, "secretferry "+name) || !strings.Contains(out, "Examples:") {
				t.Errorf("%v: not a command's help:\n%s", route, out)
			}
			h.assertNothingLeftTheMachine()
			texts = append(texts, out)
		}
		if texts[0] != texts[1] || texts[0] != texts[2] {
			t.Errorf("%s: its help differs by route", name)
		}
	}
}

func TestConfigHelpListsItsSubcommands(t *testing.T) {
	var first string
	for i, route := range [][]string{{"config", "--help"}, {"config", "-h"}, {"config", "help"}, {"help", "config"}} {
		h := helpHarness(t)
		out, code := h.helpOf(route...)
		if code != 0 {
			t.Fatalf("%v: exit %d", route, code)
		}
		for _, want := range []string{"init ", "add-secret ", "validate ", "secretferry config <command> --help", "None of them needs a token"} {
			if !strings.Contains(out, want) {
				t.Errorf("%v lacks %q:\n%s", route, want, out)
			}
		}
		if i == 0 {
			first = out
		} else if out != first {
			t.Errorf("%v: differs from config --help", route)
		}
	}
	// With nothing after config it is a mistake, and says where to look.
	h := helpHarness(t)
	if code := h.runPlain("config"); code != 1 || !strings.Contains(h.stderr.String(), "secretferry config --help") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
}

func TestWhatTheHelpDocumentsIsWhatTheCommandAccepts(t *testing.T) {
	for name, allowed := range commandFlags {
		d, ok := docFor(name)
		if !ok {
			t.Errorf("%s has no help", name)
			continue
		}
		var documented []string
		for _, f := range d.flags {
			documented = append(documented, f.name)
		}
		got, want := append([]string(nil), documented...), append([]string(nil), allowed...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s documents %v but accepts %v", name, got, want)
		}
		for _, f := range d.flags {
			if strings.TrimSpace(f.desc) == "" {
				t.Errorf("%s: --%s has no description", name, f.name)
			}
		}
	}
	for _, d := range commandDocs {
		if _, isCommand := commandFlags[d.name]; !isCommand && d.name != "version" {
			t.Errorf("help for %q, which is not a command", d.name)
		}
		if d.summary == "" || len(d.usage) == 0 || len(d.examples) == 0 {
			t.Errorf("%s is missing its summary, usage or examples", d.name)
		}
	}
}

func TestEveryDocumentedExampleParsesAndFitsTheExampleConfiguration(t *testing.T) {
	cfg, err := config.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range commandDocs {
		for _, ex := range d.examples {
			words := shellSplit(t, ex)
			if len(words) == 0 || words[0] != "secretferry" {
				t.Errorf("%s: example %q does not start with secretferry", d.name, ex)
				continue
			}
			words = words[1:]
			// A redirect is the shell's, not ours.
			for i, w := range words {
				if w == "<" {
					words = words[:i]
					break
				}
			}
			if d.name == "version" {
				if strings.Join(words, " ") != "version" {
					t.Errorf("version example %q", ex)
				}
				continue
			}
			nameWords := strings.Fields(d.name)
			if len(words) < len(nameWords) || strings.Join(words[:len(nameWords)], " ") != d.name {
				t.Errorf("%s: example %q is for another command", d.name, ex)
				continue
			}
			opts, err := parseOptions(d.name, words[len(nameWords):], commandFlags[d.name])
			if err != nil {
				t.Errorf("%s: example %q does not parse: %v", d.name, ex, err)
				continue
			}
			// The names and kinds it uses are ones the example configuration produces.
			for _, n := range opts.names {
				if _, _, ok := cfg.Match(n); !ok {
					t.Errorf("%s: example %q names %s, which the example configuration does not produce", d.name, ex, n)
				}
			}
			if opts.secret != "" {
				kind, ok := cfg.Kind(opts.secret)
				if !ok {
					t.Errorf("%s: example %q names a kind the example configuration lacks", d.name, ex)
				} else if _, err := kind.Names(opts.params); err != nil {
					t.Errorf("%s: example %q: %v", d.name, ex, err)
				}
			}
			if d.name == "config add-secret" && opts.kind != "" {
				secret, err := secretFromOptions(opts)
				if err == nil {
					_, err = config.Parse([]byte(config.Render(config.File{Secrets: []config.Secret{secret}})), "example.json")
				}
				if err != nil {
					t.Errorf("example %q describes a secret that is refused: %v", ex, err)
				}
			}
		}
	}
}

func TestHelpIsNotMistakenForAValue(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	h := helpHarness(t)
	// --help as the value of an option is that option's value, not a request for help.
	out, code := h.helpOf("set", "--name", "--help")
	if code != 1 || strings.Contains(out, "Usage:") {
		t.Errorf("--name --help: exit %d, stdout %q", code, out)
	}
	// A word before it stops the options, as always, and is never printed.
	out, code = h.helpOf("set", word, "--help")
	if code != 1 || strings.Contains(h.stderr.String(), word) || strings.Contains(out, word) || !strings.Contains(h.stderr.String(), "Unexpected word") {
		t.Errorf("a stray word: exit %d, stderr %q", code, h.stderr.String())
	}
	h.assertNothingLeftTheMachine()
}

func TestHelpForSomethingThatIsNotACommandIsAnErrorThatQuotesNothing(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	for _, args := range [][]string{{"help", word}, {"help", "set", word}, {"help", "config", word}} {
		h := helpHarness(t)
		if code := h.runPlain(args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
		if strings.Contains(h.stderr.String(), word) || !strings.Contains(h.stderr.String(), "secretferry --help") {
			t.Errorf("%v: stderr %q", args, h.stderr.String())
		}
	}
	// And an unknown command or subcommand points at help without repeating the word.
	h := helpHarness(t)
	for _, args := range [][]string{{word}, {"config", word}} {
		if code := h.runPlain(args...); code != 1 || strings.Contains(h.stderr.String(), word) || !strings.Contains(h.stderr.String(), "--help") {
			t.Errorf("%v: exit %d, stderr %q", args, code, h.stderr.String())
		}
	}
}

func TestVersionAndItsHelp(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		h := helpHarness(t)
		if out, code := h.helpOf(args...); code != 0 || out != "secretferry test\n" {
			t.Errorf("%v: exit %d, stdout %q", args, code, out)
		}
	}
	h := helpHarness(t)
	if out, code := h.helpOf("version", "--help"); code != 0 || !strings.Contains(out, "Print the version.") {
		t.Errorf("exit %d, stdout %q", code, out)
	}
}

// The exact text of a small command's help pins the layout: the heading, the columns, the wrapping.
func TestTheLayoutOfACommandsHelp(t *testing.T) {
	h := helpHarness(t)
	out, _ := h.helpOf("list", "--help")
	const want = `List the secrets in the store: names only, sorted.

Usage:
  secretferry list

Options:
  --config <file>  Use this configuration file instead of the nearest
                   secretferry.json (looked for in the working directory, then
                   each parent).
  --help           Show this help.

Cloudflare never returns a value, so there is none to show. It lists every
secret in the account's store, whether or not the configuration names it: use
check for that.

Examples:
  secretferry list
`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestWrap(t *testing.T) {
	for _, c := range []struct {
		text  string
		width int
		want  []string
	}{
		{"", 10, nil},
		{"one", 10, []string{"one"}},
		{"one two three", 7, []string{"one two", "three"}},
		{"one two", 7, []string{"one two"}},
		{"one two", 6, []string{"one", "two"}},
		{"a  lot   of space", 20, []string{"a lot of space"}},
		{"unbreakable-long-word and more", 5, []string{"unbreakable-long-word", "and", "more"}},
	} {
		got := wrap(c.text, c.width)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("wrap(%q, %d) = %q, want %q", c.text, c.width, got, c.want)
		}
	}
}

func TestNoOptionLineRunsPastTheWidthExceptAWordThatCannotBreak(t *testing.T) {
	for name := range commandFlags {
		d, _ := docFor(name)
		h := helpHarness(t)
		out, _ := h.helpOf(append(strings.Fields(name), "--help")...)
		inExamples, inUsage := false, false
		for _, line := range strings.Split(out, "\n") {
			switch line {
			case "Usage:":
				inUsage = true
				continue
			case "Options:", "":
				inUsage = false
			case "Examples:":
				inExamples = true
				continue
			}
			if inExamples || inUsage {
				continue // commands to copy are not wrapped
			}
			if len(line) > helpWidth+2 {
				t.Errorf("%s: a line of %d characters:\n%s", d.name, len(line), line)
			}
		}
	}
}

func TestAWrappedUsageLineLinesUpUnderWhatItContinues(t *testing.T) {
	h := helpHarness(t)
	out, _ := h.helpOf("provision", "--help")
	const want = `Usage:
  secretferry provision (--name <name> ... |
                         --secret <kind> [--param <placeholder>=<value> ...])
`
	if !strings.Contains(out, want) {
		t.Errorf("the usage block is not laid out as expected:\n%s", out)
	}
	out, _ = h.helpOf("config", "add-secret", "--help")
	const wantAdd = `  secretferry config add-secret --kind <kind> --template <name-template>
                                --pattern <placeholder>=<regex> ... [options]
`
	if !strings.Contains(out, wantAdd) {
		t.Errorf("add-secret usage:\n%s", out)
	}
}
