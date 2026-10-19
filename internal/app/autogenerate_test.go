package app

import (
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/testfake"
)

const (
	signingItem = "secretferry - " + signingA
	vendorItem  = "secretferry - " + vendorKey
)

// firstCreate is the index of the first op call that saves an item, or -1.
func (h *harness) firstCreate() int {
	for i, args := range h.opCalls {
		if len(args) > 1 && args[1] == "create" {
			return i
		}
	}
	return -1
}

func TestAutoGenerateMakesTheValueWhenTheAnswerIsBlankAndBacksItUpFirst(t *testing.T) {
	for label, answer := range map[string]string{"empty": "", "only whitespace": "  \t "} {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t, testfake.Options{})
			h.answer = answer
			if code := h.run("set", "--name", signingA, "--auto-generate"); code != 0 {
				t.Fatalf("exit %d: %s", code, h.stderr.String())
			}
			stored, ok := h.api.Inspect(signingA)
			if !ok || len(stored.Value) != 44 || !strings.HasSuffix(stored.Value, "=") {
				t.Fatalf("stored %+v, %v: want 32 bytes as padded base64", stored, ok)
			}
			// The copy that outlives the store is the one in 1Password, and it is the same value.
			if h.items[signingItem] != stored.Value {
				t.Errorf("1Password holds %q, Cloudflare %q", h.items[signingItem], stored.Value)
			}
			for _, want := range []string{
				"Made the value (base64-32) and saved it as '" + signingItem + "' in the Acme vault, then read it back.",
				"Set " + signingA + ".",
				"that 1Password item is the copy",
			} {
				if !strings.Contains(h.stdout.String(), want) {
					t.Errorf("stdout lacks %q:\n%s", want, h.stdout.String())
				}
			}
			h.assertNeverShown(stored.Value)
		})
	}
}

func TestAutoGenerateSavesTheBackupBeforeCloudflareIsWrittenTo(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.run("set", "--name", signingA, "--auto-generate")
	if h.firstCreate() == -1 || h.posts() != 1 {
		t.Fatalf("item created at %d, posts %d", h.firstCreate(), h.posts())
	}
	// And if the copy does not read back, Cloudflare is never written to at all.
	h2 := newHarness(t, testfake.Options{})
	h2.breakReadback = true
	if code := h2.run("set", "--name", signingA, "--auto-generate"); code != 1 || !strings.Contains(h2.stderr.String(), "does not match") {
		t.Errorf("a copy that does not read back: exit %d, stderr %q", code, h2.stderr.String())
	}
	if h2.posts() != 0 {
		t.Error("Cloudflare was written to although the backup did not read back")
	}
	if _, ok := h2.api.Inspect(signingA); ok {
		t.Error("a value with no proven copy was set")
	}
}

func TestAutoGenerateNeverReplacesAValueThatWasGiven(t *testing.T) {
	// Typed and fine: used as it is, nothing made, 1Password not touched.
	h := newHarness(t, testfake.Options{})
	h.answer = signingValue
	if code := h.run("set", "--name", signingA, "--auto-generate"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(signingA); got.Value != signingValue || len(h.opCalls) != 0 {
		t.Errorf("stored %q with %d op calls", got.Value, len(h.opCalls))
	}

	// Typed and wrong: refused, not quietly swapped for a made one.
	bad := newHarness(t, testfake.Options{})
	bad.answer = "NOT-A-KEY-SECRET"
	if code := bad.run("set", "--name", signingA, "--auto-generate"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if bad.posts() != 0 || len(bad.opCalls) != 0 || len(bad.items) != 0 {
		t.Errorf("posts %d, op calls %d, items %d: a wrong value was replaced by a made one", bad.posts(), len(bad.opCalls), len(bad.items))
	}
	bad.assertNeverShown("NOT-A-KEY-SECRET")
}

func TestAutoGenerateFromStandardInputAndFromOnePassword(t *testing.T) {
	t.Run("blank standard input", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.env.Stdin = strings.NewReader("")
		if code := h.run("set", "--name", signingA, "--source", "stdin", "--auto-generate"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if _, ok := h.api.Inspect(signingA); !ok || h.items[signingItem] == "" || h.asked != 0 {
			t.Errorf("stored %v, item %q, asked %d", ok, h.items[signingItem], h.asked)
		}
	})
	t.Run("standard input with a value", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.env.Stdin = strings.NewReader(signingValue + "\n")
		if code := h.run("set", "--name", signingA, "--source", "stdin", "--auto-generate"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if got, _ := h.api.Inspect(signingA); got.Value != signingValue || len(h.items) != 0 {
			t.Errorf("stored %q, %d items", got.Value, len(h.items))
		}
	})
	t.Run("no 1Password item yet", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		if code := h.run("set", "--name", signingA, "--source", "1password", "--auto-generate"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		got, ok := h.api.Inspect(signingA)
		if !ok || h.items[signingItem] != got.Value {
			t.Errorf("stored %+v, item %q", got, h.items[signingItem])
		}
	})
	t.Run("a 1Password item that is there is used, not remade", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.items[signingItem] = signingValue
		if code := h.run("set", "--name", signingA, "--source", "1password", "--auto-generate"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if got, _ := h.api.Inspect(signingA); got.Value != signingValue || h.firstCreate() != -1 {
			t.Errorf("stored %q; an item was created: %v", got.Value, h.firstCreate() != -1)
		}
		if strings.Contains(h.stdout.String(), "Made the value") {
			t.Errorf("it says it made a value:\n%s", h.stdout.String())
		}
	})
}

func TestAutoGenerateReusesTheItemAnEarlierRunLeft(t *testing.T) {
	// A blank answer, and an earlier provision (or set) already saved the item: that value is the one.
	h := newHarness(t, testfake.Options{})
	h.items[signingItem] = signingValue
	h.answer = ""
	if code := h.run("set", "--name", signingA, "--auto-generate"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(signingA); got.Value != signingValue {
		t.Errorf("stored %q, not the value already backed up", got.Value)
	}
	if h.firstCreate() != -1 || !strings.Contains(h.stdout.String(), "used the one already saved as '"+signingItem+"'") {
		t.Errorf("created an item: %v\n%s", h.firstCreate() != -1, h.stdout.String())
	}
}

func TestWithoutAutoGenerateABlankValueIsStillRefused(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = ""
	if code := h.run("set", "--name", signingA); code != 1 || !strings.Contains(h.stderr.String(), "The value is empty.") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	if h.posts() != 0 || len(h.opCalls) != 0 {
		t.Errorf("posts %d, op calls %d", h.posts(), len(h.opCalls))
	}
	// And a missing 1Password item still says so, rather than making one.
	h2 := newHarness(t, testfake.Options{})
	if code := h2.run("set", "--name", signingA, "--source", "1password"); code != 1 || !strings.Contains(h2.stderr.String(), "has no item") || len(h2.items) != 0 {
		t.Errorf("exit %d, stderr %q, items %d", code, h2.stderr.String(), len(h2.items))
	}
}

func TestAutoGenerateNeedsAFormToMakeAndAVaultToKeepItIn(t *testing.T) {
	t.Run("the kind has no generate", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.answer = ""
		if code := h.run("set", "--name", vendorKey, "--auto-generate"); code != 1 || !strings.Contains(h.stderr.String(), "nothing to make") {
			t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
		}
		if h.posts() != 0 || len(h.items) != 0 {
			t.Errorf("posts %d, items %d", h.posts(), len(h.items))
		}
	})
	t.Run("the kind has no generate but the item is there", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.items[vendorItem] = vendorValue
		h.answer = ""
		if code := h.run("set", "--name", vendorKey, "--auto-generate"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if got, _ := h.api.Inspect(vendorKey); got.Value != vendorValue {
			t.Errorf("stored %q", got.Value)
		}
	})
	t.Run("no vault is configured", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.answer = ""
		path := writeConfig(t, "")
		raw := read(t, path)
		noVault := strings.Replace(raw, `"onePassword":{"vault":"Acme"},`, "", 1)
		if noVault == raw {
			t.Fatalf("could not remove the vault from %s", raw)
		}
		writeFile(t, path, noVault)
		if code := Run([]string{"set", "--name", "acme-api-key", "--auto-generate", "--config", path}, h.env); code != 1 || !strings.Contains(h.stderr.String(), "onePassword.vault must be set") {
			t.Errorf("exit %d, stderr %q", code, h.stderr.String())
		}
		if h.posts() != 0 {
			t.Error("something was set with no copy anywhere")
		}
		// A value that is given needs no vault.
		h.answer = "given-value"
		if code := Run([]string{"set", "--name", "acme-api-key", "--auto-generate", "--config", path}, h.env); code != 0 {
			t.Errorf("a given value: exit %d, stderr %q", code, h.stderr.String())
		}
	})
	t.Run("the item holds a value the rule rejects", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.items[signingItem] = "NOT-A-KEY-SECRET"
		h.answer = ""
		if code := h.run("set", "--name", signingA, "--auto-generate"); code != 1 || !strings.Contains(h.stderr.String(), "not acceptable") {
			t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
		}
		if h.posts() != 0 {
			t.Error("a value its rule rejects was set")
		}
		h.assertNeverShown("NOT-A-KEY-SECRET")
	})
}

func TestAutoGenerateChangesNothingWhenTheSecretIsAlreadySet(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingA, "old")
	h.answer = ""
	if code := h.run("set", "--name", signingA, "--auto-generate"); code != 1 || !strings.Contains(h.stderr.String(), "already set") {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if len(h.opCalls) != 0 || h.asked != 0 {
		t.Errorf("op calls %d, asked %d: it made a value for a secret that is already set", len(h.opCalls), h.asked)
	}
}

func TestThePromptSaysEnterMakesOneOnlyWhenItCan(t *testing.T) {
	cases := map[string]struct {
		args []string
		hint bool
	}{
		"auto-generate, and the kind can generate":    {[]string{"set", "--name", signingA, "--auto-generate"}, true},
		"auto-generate, but the kind cannot generate": {[]string{"set", "--name", vendorKey, "--auto-generate"}, false},
		"no auto-generate":                            {[]string{"set", "--name", signingA}, false},
	}
	for label, c := range cases {
		h := newHarness(t, testfake.Options{})
		h.answer = signingValue
		h.run(c.args...)
		if got := strings.Contains(h.lastPrompt, "Enter to have secretferry make one"); got != c.hint {
			t.Errorf("%s: prompt %q", label, h.lastPrompt)
		}
	}
}

func TestAutoGenerateBelongsToSetAlone(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	for label, args := range map[string][]string{
		"the earlier name": {"set", "--name", signingA, "--auto-create"},
		"rotate":           {"rotate", "--name", signingA, "--confirm", signingA, "--auto-generate"},
		"provision":        {"provision", "--name", signingA, "--auto-generate"},
		"list":             {"list", "--auto-generate"},
		"check":            {"check", "--auto-generate"},
	} {
		if code := h.run(args...); code != 1 || !strings.Contains(h.stderr.String(), "Only --") {
			t.Errorf("%s: exit %d, stderr %q", label, code, h.stderr.String())
		}
	}
	if h.posts() != 0 || len(h.opCalls) != 0 {
		t.Error("a refused command did work")
	}
}

func TestProvisionStillSaysWhatItDidAfterTheSharedStep(t *testing.T) {
	// provision and set --auto-generate share backedUpValue; provision's own lines are unchanged.
	h := newHarness(t, testfake.Options{})
	if code := h.run("provision", "--name", signingA); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, want := range []string{"saved '" + signingItem + "' in the Acme vault", "set in Secrets Store", "Now check: secretferry list"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, h.stdout.String())
		}
	}
	if code := h.run("provision", "--name", signingA); code != 0 || !strings.Contains(h.stdout.String(), "already has '"+signingItem+"'") {
		t.Errorf("second run: exit %d\n%s", code, h.stdout.String())
	}
}
