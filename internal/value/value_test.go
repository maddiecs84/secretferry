package value

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const key32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // 0x00..0x1f, padded base64

func TestRules(t *testing.T) {
	urlKey := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(key32), "=")
	cases := []struct {
		spec  string
		value string
		ok    bool
	}{
		{"any", "anything at all", true},
		{"", "empty spec means any", true},

		{"base64-32", key32, true},
		{"base64-32", strings.TrimRight(key32, "="), false}, // unpadded
		{"base64-32", base64.StdEncoding.EncodeToString(make([]byte, 31)), false},
		{"base64-32", base64.StdEncoding.EncodeToString(make([]byte, 33)), false},
		{"base64-32", "not base64!", false},
		{"base64-32", key32 + "\n", false},

		{"base64url-32", urlKey, true},
		{"base64url-32", key32, false}, // padded
		{"base64url-32", urlKey[:42], false},
		{"base64url-32", urlKey + "A", false},
		{"base64url-32", strings.Repeat("!", 43), false},

		{"printable", "vendor_live_AbC_dEf-123", true},
		{"printable", "has a space", false},
		{"printable", "has\nline", false},
		{"printable", "naïve", false},
		{"printable", "", false},

		{"regex:sk-[a-z]+", "sk-abc", true},
		{"regex:sk-[a-z]+", "xsk-abc", false}, // matched in full, not a prefix
		{"regex:sk-[a-z]+", "sk-abcX", false},
	}
	for _, c := range cases {
		rule, err := ParseRule(c.spec, "")
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", c.spec, err)
		}
		if got := rule.Check(c.value) == nil; got != c.ok {
			t.Errorf("%q accepts %q = %v, want %v", c.spec, c.value, got, c.ok)
		}
	}
}

func TestAFailureSaysNothingOfTheValue(t *testing.T) {
	const secret = "SUPERSECRETVALUE"
	for _, spec := range []string{"base64-32", "base64url-32", "printable", "regex:x+"} {
		rule, _ := ParseRule(spec, "")
		err := rule.Check(secret + " ")
		if err == nil {
			t.Fatalf("%s accepted the bad value", spec)
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: the message quotes the value: %v", spec, err)
		}
	}
}

func TestACustomMessageReplacesTheDefault(t *testing.T) {
	rule, err := ParseRule("regex:x+", "Use the key from the dashboard.")
	if err != nil {
		t.Fatal(err)
	}
	if got := rule.Check("y"); got == nil || got.Error() != "Use the key from the dashboard." {
		t.Errorf("Check = %v", got)
	}
}

func TestParseRuleRefusals(t *testing.T) {
	for _, spec := range []string{"base64", "regex:(", "REGEX:a", "printable "} {
		if _, err := ParseRule(spec, ""); err == nil {
			t.Errorf("ParseRule(%q) accepted a bad spec", spec)
		}
	}
}

func TestGenerateMakesAValueItsOwnRuleAccepts(t *testing.T) {
	for _, spec := range Generators {
		v, err := Generate(spec, nil)
		if err != nil {
			t.Fatalf("Generate(%q): %v", spec, err)
		}
		rule, _ := ParseRule(spec, "")
		if err := rule.Check(v); err != nil {
			t.Errorf("a %s value fails its own rule: %v", spec, err)
		}
		other, _ := Generate(spec, nil)
		if v == other {
			t.Errorf("two %s values are equal", spec)
		}
	}
}

func TestGenerateReadsExactly32BytesFromTheSource(t *testing.T) {
	src := bytes.NewReader(make([]byte, 31))
	if _, err := Generate("base64-32", src); err == nil {
		t.Error("a short source was accepted")
	}
	if _, err := Generate("hex", nil); err == nil {
		t.Error("an unknown generator was accepted")
	}
	want := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if got, _ := Generate("base64-32", bytes.NewReader(bytes.Repeat([]byte{7}, 64))); got != want {
		t.Errorf("Generate = %q, want %q", got, want)
	}
}

func TestNormalise(t *testing.T) {
	ok := map[string]string{
		"abc":        "abc",
		"abc\n":      "abc",
		"abc\r\n":    "abc",
		"abc\n\n":    "abc\n", // one trailing line break only
		" abc ":      " abc ", // nothing else changed
		"abc\r":      "abc\r", // a lone carriage return is part of the value
		"two\nlines": "two\nlines",
	}
	for in, want := range ok {
		got, err := Normalise(in, 100)
		if err != nil || got != want {
			t.Errorf("Normalise(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "\n", "   ", "  \r\n"} {
		if _, err := Normalise(in, 100); err == nil {
			t.Errorf("Normalise(%q) accepted a blank value", in)
		}
	}
}

func TestNormaliseCountsBytesNotCharacters(t *testing.T) {
	if _, err := Normalise(strings.Repeat("a", 10), 10); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
	if _, err := Normalise(strings.Repeat("a", 11), 10); err == nil {
		t.Error("one byte over was accepted")
	}
	// Three characters, six bytes.
	if _, err := Normalise("éèà", 5); err == nil {
		t.Error("multi-byte characters were counted as one byte each")
	}
	if _, err := Normalise(strings.Repeat("a", 1_000_000), 0); err != nil {
		t.Errorf("no limit: %v", err)
	}
}
