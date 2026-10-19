package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/config"
	"github.com/maddiecs84/secretferry/internal/testfake"
)

// addArgs is a valid add-secret command line for a signing key.
func addArgs(extra ...string) []string {
	args := []string{
		"config", "add-secret",
		"--kind", "signing-key",
		"--template", "acme-{env}-signing-key",
		"--pattern", "env=(sandbox|staging|production)-[0-9]{2}",
		"--rule", "base64-32",
		"--generate", "base64-32",
		"--default", "env=sandbox-01",
		"--default", "env=staging-01",
		"--rotate-warning", "anything signed with it stops verifying.",
	}
	return append(args, extra...)
}

// initialised is a configHarness with a secretferry.json made by `config init`.
func initialised(t *testing.T) (*harness, string) {
	t.Helper()
	h, dir := configHarness(t)
	if code := h.runPlain("config", "init", "--account", testfake.Account, "--vault", "Acme"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, h.stderr.String())
	}
	return h, filepath.Join(dir, "secretferry.json")
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAddSecretFromInitToAProvisionedSecret(t *testing.T) {
	h, path := initialised(t)
	if code := h.runPlain(addArgs()...); code != 0 {
		t.Fatalf("add-secret: exit %d: %s", code, h.stderr.String())
	}
	for _, want := range []string{"Added signing-key to " + path, "name: acme-<env>-signing-key", "secretferry config validate"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, h.stdout.String())
		}
	}

	// validate shows it.
	if code := h.runPlain("config", "validate"); code != 0 {
		t.Fatalf("validate: exit %d: %s", code, h.stderr.String())
	}
	for _, want := range []string{"  signing-key", "acme-<env>-signing-key", "base64-32", "acme-sandbox-01-signing-key, acme-staging-01-signing-key"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("validate lacks %q:\n%s", want, h.stdout.String())
		}
	}
	if strings.Contains(h.stdout.String(), "Note:") {
		t.Errorf("init was given an account and a vault, so there is nothing to note:\n%s", h.stdout.String())
	}

	// And the other commands now use it, against the fake: the file made by two commands drives a real provision.
	h.envVars = map[string]string{"CLOUDFLARE_API_TOKEN": "tok"}
	if code := h.runPlain("provision", "--secret", "signing-key", "--config", path); code != 0 {
		t.Fatalf("provision: exit %d: %s", code, h.stderr.String())
	}
	for _, name := range []string{"acme-sandbox-01-signing-key", "acme-staging-01-signing-key"} {
		if _, ok := h.api.Inspect(name); !ok {
			t.Errorf("%s was not provisioned", name)
		}
	}
	if _, ok := h.api.Inspect("acme-production-01-signing-key"); ok {
		t.Error("a name outside the defaults was provisioned")
	}
}

func TestAddSecretKeepsEverythingElseTheFileSaid(t *testing.T) {
	h, dir := configHarness(t)
	path := filepath.Join(dir, "secretferry.json")
	const before = `{
  "source": "stdin",
  "cloudflare": { "accountId": "0123456789abcdef0123456789abcdef", "scopes": ["workers", "secrets"] },
  "onePassword": { "vault": "Acme", "itemTitle": "mine - {name}" },
  "secrets": [
    { "kind": "first", "name": "acme-first", "value": { "rule": "printable" } }
  ]
}
`
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.runPlain("config", "add-secret", "--kind", "second", "--template", "acme-second"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the edited file does not load: %v", err)
	}
	if cfg.Raw.Source != "stdin" || strings.Join(cfg.Raw.Cloudflare.Scopes, ",") != "workers,secrets" || cfg.Raw.OnePassword.ItemTitle != "mine - {name}" {
		t.Errorf("settings changed: %+v", cfg.Raw)
	}
	if got := strings.Join(cfg.KindNames(), ","); got != "first,second" {
		t.Errorf("kinds = %s", got)
	}
	first, _ := cfg.Kind("first")
	if first.Rule.Spec() != "printable" {
		t.Errorf("the first secret changed: %+v", first.Secret)
	}
	// Nothing was written that the file did not say before: no defaults filled in.
	after := read(t, path)
	for _, invented := range []string{`"generate"`, `"defaults"`, `"rotateWarning"`, `"params"`} {
		if strings.Contains(after, invented) {
			t.Errorf("the edit invented %s:\n%s", invented, after)
		}
	}
}

func TestAddSecretWritesTheOrderOfSecretsAsAdded(t *testing.T) {
	h, path := initialised(t)
	for _, kind := range []string{"zeta", "alpha", "mid"} {
		if code := h.runPlain("config", "add-secret", "--kind", kind, "--template", "acme-"+kind); code != 0 {
			t.Fatalf("%s: exit %d: %s", kind, code, h.stderr.String())
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, k := range cfg.Kinds {
		order = append(order, k.Kind)
	}
	if strings.Join(order, ",") != "zeta,alpha,mid" {
		t.Errorf("order = %v", order)
	}
}

func TestAddSecretCarriesCharactersThatNeedEscaping(t *testing.T) {
	h, path := initialised(t)
	const warning = `quote " backslash \ <tag> & more`
	if code := h.runPlain("config", "add-secret", "--kind", "k", "--template", "acme-k", "--rotate-warning", warning, "--message", warning, "--rule", "regex:[a-z]+"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("does not load: %v\n%s", err, read(t, path))
	}
	k, _ := cfg.Kind("k")
	if k.RotateWarning != warning || k.Value.Message != warning {
		t.Errorf("did not round-trip: %+v", k.Secret)
	}
}

func TestARefusedAddLeavesTheFileExactlyAsItWas(t *testing.T) {
	h, path := initialised(t)
	if code := h.runPlain(addArgs()...); code != 0 {
		t.Fatalf("setup: exit %d: %s", code, h.stderr.String())
	}
	before := read(t, path)
	dir := filepath.Dir(path)

	cases := map[string]struct {
		args []string
		want string
	}{
		"the kind is taken": {
			[]string{"config", "add-secret", "--kind", "signing-key", "--template", "acme-other"},
			"declared twice",
		},
		"a placeholder with no pattern": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-{env}-k"},
			"no pattern",
		},
		"a pattern for no placeholder": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-k", "--pattern", "env=[a-z]+"},
			"does not use",
		},
		"a pattern that is not a regular expression": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-{env}", "--pattern", "env=("},
			"regular expression",
		},
		"an unknown rule": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-k", "--rule", "hex"},
			"unknown value rule",
		},
		"a generator its own rule refuses": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-k", "--rule", "base64-32", "--generate", "base64url-32"},
			"does not pass its own value rule",
		},
		"an unknown generator": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-k", "--generate", "hex"},
			"cannot generate",
		},
		"a name another secret already produces": {
			[]string{"config", "add-secret", "--kind", "clash", "--template", "acme-{env}-signing-key",
				"--pattern", "env=[a-z]+-[0-9]+", "--default", "env=sandbox-01"},
			"both produce",
		},
		"a default the pattern refuses": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-{env}", "--pattern", "env=[a-z]+", "--default", "env=UPPER"},
			"not a valid",
		},
		"a default for a placeholder that is not there": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-k", "--default", "env=x"},
			"does not use",
		},
		"a kind that is not a word": {
			[]string{"config", "add-secret", "--kind", "Not A Kind", "--template", "acme-k"},
			"kind",
		},
		"no kind":                  {[]string{"config", "add-secret", "--template", "acme-k"}, "needs --kind and --template"},
		"no template":              {[]string{"config", "add-secret", "--kind", "k"}, "needs --kind and --template"},
		"a pattern with no equals": {[]string{"config", "add-secret", "--kind", "k", "--template", "acme-{env}", "--pattern", "env"}, "--pattern takes name=value"},
		"a pattern given twice": {
			[]string{"config", "add-secret", "--kind", "k", "--template", "acme-{env}", "--pattern", "env=a", "--pattern", "env=b"},
			"--pattern was given twice",
		},
		"a default with an empty value": {[]string{"config", "add-secret", "--kind", "k", "--template", "acme-{env}", "--pattern", "env=[a-z]*", "--default", "env="}, "--default takes name=value"},
		"a default with no equals":      {[]string{"config", "add-secret", "--kind", "k", "--template", "acme-k", "--default", "x"}, "--default takes name=value"},
		"--kind twice":                  {[]string{"config", "add-secret", "--kind", "a", "--kind", "b", "--template", "acme-k"}, "more than once"},
	}
	for label, c := range cases {
		if code := h.runPlain(c.args...); code != 1 {
			t.Errorf("%s: exit %d", label, code)
			continue
		}
		if !strings.Contains(h.stderr.String(), c.want) {
			t.Errorf("%s: stderr %q lacks %q", label, h.stderr.String(), c.want)
		}
		if got := read(t, path); got != before {
			t.Errorf("%s: the file changed:\n%s", label, got)
		}
	}
	// A failed write leaves no temporary file behind either.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory holds %d files, want only the configuration", len(entries))
	}
	h.assertNothingLeftTheMachine()
}

func TestAddSecretLeavesNoTemporaryFileAndKeepsThePermissions(t *testing.T) {
	h, path := initialised(t)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // the test needs a mode other than init's default to see it kept
			t.Fatal(err)
		}
	}
	if code := h.runPlain(addArgs()...); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("the directory holds %d files, want only the configuration", len(entries))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o640 {
			t.Errorf("permissions = %v, %v; want 0640", info.Mode().Perm(), err)
		}
	}
}

func TestAddSecretNeedsAFileToAddTo(t *testing.T) {
	h, dir := configHarness(t)
	if code := h.runPlain(addArgs()...); code != 1 || !strings.Contains(h.stderr.String(), "secretferry config init") {
		t.Errorf("no file: exit %d, stderr %q", code, h.stderr.String())
	}
	if code := h.runPlain(addArgs("--config", filepath.Join(dir, "absent.json"))...); code != 1 || !strings.Contains(h.stderr.String(), "does not exist") {
		t.Errorf("named file missing: exit %d, stderr %q", code, h.stderr.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("add-secret created %d files; only init creates the configuration", len(entries))
	}
}

func TestAddSecretIsRefusedAgainstABrokenFileWithoutChangingIt(t *testing.T) {
	h, dir := configHarness(t)
	path := filepath.Join(dir, "secretferry.json")
	const broken = `{"secrets": [{"kind": "k", "name": "n", "surprise": 1}]}`
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.runPlain(addArgs()...); code != 1 || !strings.Contains(h.stderr.String(), "surprise") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	if read(t, path) != broken {
		t.Error("a broken file was rewritten")
	}
}

func TestAddSecretFlagsBelongToAddSecretAndAreNeverQuoted(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	h, path := initialised(t)
	before := read(t, path)
	for label, args := range map[string][]string{
		"a value flag":        {"config", "add-secret", "--kind", "k", "--template", "acme-k", "--value", word},
		"a stray word":        {"config", "add-secret", "--kind", "k", "--template", "acme-k", word},
		"--kind on init":      {"config", "init", "--kind", "k"},
		"--kind on set":       {"set", "--name", "acme-k", "--kind", "k"},
		"--template on set":   {"set", "--name", "acme-k", "--template", "t"},
		"--rule on provision": {"provision", "--name", "acme-k", "--rule", "any"},
		"--generate on list":  {"list", "--generate", "base64-32"},
	} {
		if code := h.runPlain(args...); code != 1 {
			t.Errorf("%s: exit %d", label, code)
		}
		if !strings.Contains(h.stderr.String(), "Only --") && !strings.Contains(h.stderr.String(), "Unexpected word") {
			t.Errorf("%s: stderr %q", label, h.stderr.String())
		}
		if strings.Contains(h.stderr.String(), word) {
			t.Errorf("%s: a word that might be the value was printed", label)
		}
	}
	if read(t, path) != before {
		t.Error("a refused command changed the file")
	}
}

func TestCommandsThatNeedASecretSayHowToAddOne(t *testing.T) {
	h, path := initialised(t)
	h.envVars = map[string]string{"CLOUDFLARE_API_TOKEN": "tok"}
	h.api.Seed("something", "v")
	for _, args := range [][]string{
		{"set", "--name", "acme-x"},
		{"rotate", "--name", "acme-x", "--confirm", "acme-x"},
		{"provision", "--name", "acme-x"},
		{"check"},
	} {
		h.stdout.Reset()
		h.stderr.Reset()
		if code := Run(append(args, "--config", path), h.env); code != 1 || !strings.Contains(h.stderr.String(), "declares no secrets yet") || !strings.Contains(h.stderr.String(), "config add-secret") {
			t.Errorf("%v: exit %d, stderr %q", args, code, h.stderr.String())
		}
	}
	if len(h.api.Requests()) != 0 || len(h.opCalls) != 0 || h.asked != 0 {
		t.Error("a command with nothing to act on went further")
	}

	// list needs no declared secret: it shows the store.
	h.stdout.Reset()
	if code := Run([]string{"list", "--config", path}, h.env); code != 0 || !strings.Contains(h.stdout.String(), "something") {
		t.Errorf("list: exit %d, stdout %q, stderr %q", code, h.stdout.String(), h.stderr.String())
	}
}

func TestAddSecretDoesNotWriteDefaultsTheFileNeverSaid(t *testing.T) {
	// init writes no source, no scopes and no itemTitle; they must stay out of the file the
	// commands fill in on load, or every add would pin today's defaults into it.
	h, path := initialised(t)
	if code := h.runPlain(addArgs()...); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	text := read(t, path)
	for _, invented := range []string{`"source"`, `"scopes"`, `"itemTitle"`} {
		if strings.Contains(text, invented) {
			t.Errorf("the edit wrote %s, which the file never said:\n%s", invented, text)
		}
	}
	if !strings.Contains(text, testfake.Account) || !strings.Contains(text, `"vault": "Acme"`) {
		t.Errorf("what init was given was lost:\n%s", text)
	}
}

func TestAFailedReplaceLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	// The target is a directory, so the rename over it fails after the temporary file is written.
	target := filepath.Join(dir, "secretferry.json")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(target, []byte("{}")); err == nil {
		t.Fatal("replacing a directory with a file succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "secretferry.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v, want only the original", names)
	}
}

// writeFile replaces a file's contents in a test.
func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
