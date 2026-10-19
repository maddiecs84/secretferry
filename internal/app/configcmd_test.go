package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/testfake"
)

// configHarness has no token, no 1Password and a working directory of its own: the config
// commands need none of them, and the tests check they touch none of them.
func configHarness(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t, testfake.Options{})
	h.envVars = map[string]string{}
	dir := t.TempDir()
	h.env.Getwd = func() (string, error) { return dir, nil }
	return h, dir
}

func (h *harness) runPlain(args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	return Run(args, h.env)
}

func (h *harness) assertNothingLeftTheMachine() {
	h.t.Helper()
	if len(h.api.Requests()) != 0 || len(h.opCalls) != 0 || h.asked != 0 {
		h.t.Errorf("requests=%d op calls=%d asked=%d: the config commands need none of them", len(h.api.Requests()), len(h.opCalls), h.asked)
	}
}

// ---- validate ----

func TestValidateDescribesTheConfigurationWithoutATokenOrTheNetwork(t *testing.T) {
	h, _ := configHarness(t)
	if code := h.runPlain("config", "validate", "--config", example); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	out := h.stdout.String()
	for _, want := range []string{
		example + " is valid.",
		"Default source: prompt",
		"  signing-key",
		"name:      acme-<env>-signing-key",
		"value:     base64-32",
		"generates: base64-32",
		"provisions by default: acme-production-01-signing-key, acme-sandbox-01-signing-key, acme-staging-01-signing-key",
		"  wrapping-key",
		"provision needs: --param version=<value>",
		"  vendor-api-key",
		"generates: no (a value is supplied with set)",
		"provision needs: --param env=<value>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Note:") {
		t.Errorf("the example has an account and a vault, so there is nothing to note:\n%s", out)
	}
	h.assertNothingLeftTheMachine()
}

func TestValidateRefusesABadFileAndSaysWhy(t *testing.T) {
	h, dir := configHarness(t)
	path := filepath.Join(dir, "bad.json")
	for name, c := range map[string]struct{ json, want string }{
		"unknown field":      {`{"secrets":[{"kind":"k","name":"n"}],"surprise":1}`, "surprise"},
		"generate vs rule":   {`{"secrets":[{"kind":"k","name":"n","value":{"rule":"base64-32"},"generate":"base64url-32"}]}`, "does not pass its own value rule"},
		"no secrets":         {`{"secrets":[]}`, "no secrets"},
		"1password no vault": {`{"source":"1password","secrets":[{"kind":"k","name":"n"}]}`, "onePassword.vault"},
	} {
		if err := os.WriteFile(path, []byte(c.json), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := h.runPlain("config", "validate", "--config", path); code != 1 {
			t.Errorf("%s: exit %d", name, code)
		}
		if !strings.Contains(h.stderr.String(), c.want) || strings.Contains(h.stdout.String(), "is valid") {
			t.Errorf("%s: stderr %q, stdout %q", name, h.stderr.String(), h.stdout.String())
		}
	}
	h.assertNothingLeftTheMachine()
}

func TestValidateNotesWhatWillStopACommandLater(t *testing.T) {
	h, dir := configHarness(t)
	path := filepath.Join(dir, "secretferry.json")
	if err := os.WriteFile(path, []byte(`{"secrets":[{"kind":"k","name":"acme-k"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := h.runPlain("config", "validate", "--config", path); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, want := range []string{"Note: no Cloudflare account", "Note: no 1Password vault"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("no %q in:\n%s", want, h.stdout.String())
		}
	}

	// The environment can supply the account, so that note goes.
	h.envVars["CLOUDFLARE_ACCOUNT_ID"] = testfake.Account
	h.runPlain("config", "validate", "--config", path)
	if strings.Contains(h.stdout.String(), "no Cloudflare account") || !strings.Contains(h.stdout.String(), "no 1Password vault") {
		t.Errorf("output:\n%s", h.stdout.String())
	}
}

func TestValidateFindsTheFileFromTheWorkingDirectory(t *testing.T) {
	h, dir := configHarness(t)
	raw, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secretferry.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.runPlain("config", "validate"); code != 0 || !strings.Contains(h.stdout.String(), "secretferry.json is valid") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, h.stdout.String(), h.stderr.String())
	}

	h.env.Getwd = func() (string, error) { return t.TempDir(), nil }
	if code := h.runPlain("config", "validate"); code != 1 || !strings.Contains(h.stderr.String(), "no secretferry.json found") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
}

// ---- init ----

func TestInitWritesAStarterThatValidates(t *testing.T) {
	h, dir := configHarness(t)
	if code := h.runPlain("config", "init"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	path := filepath.Join(dir, "secretferry.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no file written: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the starter is not JSON: %v", err)
	}
	if _, ok := parsed["cloudflare"]; ok {
		t.Error("an account block was written without an account")
	}
	for _, want := range []string{"Wrote " + path, "Add cloudflare.accountId", "Add onePassword.vault", "secretferry config validate"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, h.stdout.String())
		}
	}

	// What init wrote is accepted by the commands that read it.
	if code := h.runPlain("config", "validate"); code != 0 || !strings.Contains(h.stdout.String(), "myapp-<env>-example-key") {
		t.Errorf("validate: exit %d, stdout %q, stderr %q", code, h.stdout.String(), h.stderr.String())
	}
	h.assertNothingLeftTheMachine()
}

func TestInitFillsInTheAccountAndVaultItIsGiven(t *testing.T) {
	h, dir := configHarness(t)
	if code := h.runPlain("config", "init", "--account", testfake.Account, "--vault", `My "Vault"`); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "secretferry.json"))
	var parsed struct {
		Cloudflare  struct{ AccountID string }
		OnePassword struct{ Vault string }
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("not valid JSON (a quote in the vault name must be escaped): %v\n%s", err, raw)
	}
	if parsed.Cloudflare.AccountID != testfake.Account || parsed.OnePassword.Vault != `My "Vault"` {
		t.Errorf("parsed %+v", parsed)
	}
	if strings.Contains(h.stdout.String(), "Add cloudflare.accountId") || strings.Contains(h.stdout.String(), "Add onePassword.vault") {
		t.Errorf("it asked for what it was given:\n%s", h.stdout.String())
	}
	if code := h.runPlain("config", "validate"); code != 0 || strings.Contains(h.stdout.String(), "Note:") {
		t.Errorf("validate: exit %d, stdout %q", code, h.stdout.String())
	}
}

func TestInitNeverOverwrites(t *testing.T) {
	h, dir := configHarness(t)
	path := filepath.Join(dir, "secretferry.json")
	const mine = `{"secrets":[{"kind":"mine","name":"mine"}]}`
	if err := os.WriteFile(path, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.runPlain("config", "init"); code != 1 || !strings.Contains(h.stderr.String(), "already exists") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != mine {
		t.Errorf("the existing file was changed: %s", got)
	}
}

func TestInitWritesToTheFileItIsToldAndNeedsItsDirectory(t *testing.T) {
	h, dir := configHarness(t)
	path := filepath.Join(dir, "custom.json")
	if code := h.runPlain("config", "init", "--config", path); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secretferry.json")); err == nil {
		t.Error("the default file was written as well")
	}
	if code := h.runPlain("config", "init", "--config", filepath.Join(dir, "no", "such", "dir.json")); code != 1 || !strings.Contains(h.stderr.String(), "directory") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
}

func TestInitRefusesABadAccountWithoutQuotingItAndWritesNothing(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	h, dir := configHarness(t)
	for _, args := range [][]string{
		{"config", "init", "--account", word},
		{"config", "init", "--account", testfake.Account, "--account", testfake.Account},
		{"config", "init", "--vault", "a", "--vault", "b"},
	} {
		if code := h.runPlain(args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
		if strings.Contains(h.stderr.String(), word) {
			t.Errorf("%v: a word that might be the value was printed: %q", args, h.stderr.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "secretferry.json")); err == nil {
		t.Error("a file was written for a refused command")
	}
}

// ---- the subcommands themselves ----

func TestConfigSubcommandsAndTheirFlags(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	h, dir := configHarness(t)
	// Each case is refused for the reason named, not merely refused: validate is given a
	// configuration that exists, so a missing file cannot be what stops it.
	cases := map[string]struct {
		args []string
		want string
	}{
		"no subcommand":             {[]string{"config"}, "needs a subcommand"},
		"unknown subcommand":        {[]string{"config", word}, "Unknown config subcommand"},
		"a stray word":              {[]string{"config", "validate", "--config", example, word}, "Unexpected word"},
		"validate takes no account": {[]string{"config", "validate", "--config", example, "--account", testfake.Account}, "Only --config"},
		"validate takes no vault":   {[]string{"config", "validate", "--config", example, "--vault", "V"}, "Only --config"},
		"validate takes no source":  {[]string{"config", "validate", "--config", example, "--source", "prompt"}, "Only --config"},
		"init takes no name":        {[]string{"config", "init", "--name", word}, "Only --config, --account, --vault"},
		"init takes no value":       {[]string{"config", "init", "--value", word}, "Only --config, --account, --vault"},
		"init takes no source":      {[]string{"config", "init", "--source", "prompt"}, "Only --config, --account, --vault"},
		"a bad account":             {[]string{"config", "init", "--account", word}, "--account must be a 32-character"},
	}
	for label, c := range cases {
		if code := h.runPlain(c.args...); code != 1 {
			t.Errorf("%s: exit %d", label, code)
		}
		if !strings.Contains(h.stderr.String(), c.want) {
			t.Errorf("%s: stderr %q lacks %q", label, h.stderr.String(), c.want)
		}
		if strings.Contains(h.stderr.String(), word) || strings.Contains(h.stdout.String(), word) {
			t.Errorf("%s: a word that might be the value was printed: %q", label, h.stderr.String())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused command wrote %d files", len(entries))
	}
	h.assertNothingLeftTheMachine()
}
