// Package value holds the rules a secret's value is checked against before
// anything is sent, and the generators for values the tool makes itself. No
// message here quotes a value.
package value

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"regexp"
	"strings"

	"github.com/maddiecs84/secretferry/internal/ferry"
)

// Rule is a named check on a value.
type Rule struct {
	spec    string
	check   func(string) bool
	message string
}

var (
	printable   = regexp.MustCompile(`^[\x21-\x7e]+$`)
	base64urlRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// 32 bytes as padded base64 is 43 characters and one "=". The shape is checked first
	// because Go's decoder silently skips line breaks, which a pasted key can carry.
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

// Specs lists the built-in rules, for messages and the README.
var Specs = []string{"any", "base64-32", "base64url-32", "printable", "regex:<pattern>"}

// ParseRule reads a rule spec: any, base64-32 (padded base64 of exactly 32
// bytes), base64url-32 (the unpadded form, 43 characters), printable (ASCII
// with no spaces or line breaks, as a request header carries) or
// regex:<pattern> (a pattern the whole value must match). message replaces the
// default failure text when it is not empty.
func ParseRule(spec, message string) (Rule, error) {
	if spec == "" {
		spec = "any"
	}
	r := Rule{spec: spec, message: message}
	switch {
	case spec == "any":
		r.check = func(string) bool { return true }
	case spec == "base64-32":
		r.check = func(v string) bool {
			if !base64Re.MatchString(v) {
				return false
			}
			b, err := base64.StdEncoding.Strict().DecodeString(v)
			return err == nil && len(b) == 32
		}
		r.defaultMessage("The value must be 32 bytes as padded base64, such as `openssl rand -base64 32` makes.")
	case spec == "base64url-32":
		r.check = func(v string) bool {
			if !base64urlRe.MatchString(v) {
				return false
			}
			b, err := base64.RawURLEncoding.Strict().DecodeString(v)
			return err == nil && len(b) == 32
		}
		r.defaultMessage("The value must be 32 random bytes as 43 base64url characters, such as `head -c 32 /dev/urandom | basenc --base64url | tr -d =` makes.")
	case spec == "printable":
		r.check = printable.MatchString
		r.defaultMessage("The value must be printable characters with no spaces or line breaks.")
	case strings.HasPrefix(spec, "regex:"):
		re, err := regexp.Compile("^(?:" + strings.TrimPrefix(spec, "regex:") + ")$")
		if err != nil {
			return Rule{}, ferry.Errorf("the value rule %q is not a valid regular expression: %v", spec, err)
		}
		r.check = re.MatchString
		r.defaultMessage("The value is not in the form this secret requires.")
	default:
		return Rule{}, ferry.Errorf("unknown value rule %q; the rules are %s", spec, strings.Join(Specs, ", "))
	}
	return r, nil
}

func (r *Rule) defaultMessage(text string) {
	if r.message == "" {
		r.message = text
	}
}

// Spec is the rule as written.
func (r Rule) Spec() string { return r.spec }

// Check refuses a value the rule does not accept. The error says nothing of it.
func (r Rule) Check(v string) error {
	if r.check == nil || r.check(v) {
		return nil
	}
	return ferry.Errorf("%s", r.message)
}

// Generators lists what Generate can make.
var Generators = []string{"base64-32", "base64url-32"}

// Generate makes 32 random bytes in the named form, reading from r (crypto/rand
// when r is nil).
func Generate(spec string, r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var encode func([]byte) string
	switch spec {
	case "base64-32":
		encode = base64.StdEncoding.EncodeToString
	case "base64url-32":
		encode = base64.RawURLEncoding.EncodeToString
	default:
		return "", ferry.Errorf("cannot generate %q; the generators are %s", spec, strings.Join(Generators, ", "))
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", ferry.Errorf("could not read random bytes")
	}
	return encode(b), nil
}

// Normalise is what was typed or piped, as the value: one trailing line break
// dropped (an echo, openssl or a typed Enter leaves one), nothing else
// changed. A blank value and one over maxBytes are refused.
func Normalise(raw string, maxBytes int) (string, error) {
	v := raw
	if strings.HasSuffix(v, "\n") {
		v = strings.TrimSuffix(strings.TrimSuffix(v, "\n"), "\r")
	}
	if strings.TrimSpace(v) == "" {
		return "", ferry.Errorf("The value is empty.")
	}
	if maxBytes > 0 && len(v) > maxBytes {
		return "", ferry.Errorf("The value is over %d bytes, the most the store accepts.", maxBytes)
	}
	return v, nil
}
