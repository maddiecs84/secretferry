// Package naming turns a name template such as "acme-{env}-api-key" into a
// builder and a parser, so the name a secret is written under and the name a
// project's configuration binds are one rule, not two that can drift apart.
package naming

import (
	"regexp"
	"strings"

	"github.com/maddiecs84/secretferry/internal/ferry"
)

var placeholder = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)

// Template is a compiled name template.
type Template struct {
	source   string
	parts    []string // literal text between placeholders; len(parts) == len(params)+1
	params   []string // placeholder names in order of appearance
	patterns map[string]*regexp.Regexp
	whole    *regexp.Regexp
}

// Compile reads a template whose placeholders are written {name}. Every
// placeholder needs a pattern in params (a regular expression the value must
// match in full), and every pattern must be used.
func Compile(source string, params map[string]string) (*Template, error) {
	t := &Template{source: source, patterns: map[string]*regexp.Regexp{}}

	matches := placeholder.FindAllStringSubmatchIndex(source, -1)
	last := 0
	var expr strings.Builder
	expr.WriteString("^")
	seen := map[string]bool{}
	for _, m := range matches {
		literal := source[last:m[0]]
		if strings.ContainsAny(literal, "{}") {
			return nil, ferry.Errorf("name template %q has a stray brace; a placeholder is {name} in lower case", source)
		}
		name := source[m[2]:m[3]]
		if seen[name] {
			return nil, ferry.Errorf("name template %q uses {%s} more than once", source, name)
		}
		seen[name] = true
		pattern, ok := params[name]
		if !ok {
			return nil, ferry.Errorf("name template %q uses {%s}, which has no pattern in params", source, name)
		}
		anchored, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return nil, ferry.Errorf("the pattern for {%s} is not a valid regular expression: %v", name, err)
		}
		t.parts = append(t.parts, literal)
		t.params = append(t.params, name)
		t.patterns[name] = anchored
		expr.WriteString(regexp.QuoteMeta(literal))
		expr.WriteString("(?P<" + name + ">" + pattern + ")")
		last = m[1]
	}
	tail := source[last:]
	if strings.ContainsAny(tail, "{}") {
		return nil, ferry.Errorf("name template %q has a stray brace; a placeholder is {name} in lower case", source)
	}
	t.parts = append(t.parts, tail)
	expr.WriteString(regexp.QuoteMeta(tail))
	expr.WriteString("$")

	for name := range params {
		if !seen[name] {
			return nil, ferry.Errorf("params has a pattern for {%s}, which name template %q does not use", name, source)
		}
	}
	if len(t.params) == 0 && source == "" {
		return nil, ferry.Errorf("a name template cannot be empty")
	}
	whole, err := regexp.Compile(expr.String())
	if err != nil {
		return nil, ferry.Errorf("name template %q is not usable: %v", source, err)
	}
	t.whole = whole
	return t, nil
}

// Placeholders lists the placeholder names a template source uses, in order of
// appearance, without compiling it.
func Placeholders(source string) []string {
	var names []string
	for _, m := range placeholder.FindAllStringSubmatch(source, -1) {
		names = append(names, m[1])
	}
	return names
}

// Source is the template as written.
func (t *Template) Source() string { return t.source }

// Params lists the placeholder names in order of appearance.
func (t *Template) Params() []string { return append([]string(nil), t.params...) }

// Check reports whether value is acceptable for the placeholder.
func (t *Template) Check(param, value string) bool {
	pattern, ok := t.patterns[param]
	return ok && pattern.MatchString(value)
}

// Build makes the name from a value for every placeholder, refusing a missing
// or unknown placeholder and any value its pattern does not accept.
func (t *Template) Build(values map[string]string) (string, error) {
	for name := range values {
		if _, ok := t.patterns[name]; !ok {
			return "", ferry.Errorf("%q has no such placeholder", t.source)
		}
	}
	var out strings.Builder
	for i, name := range t.params {
		out.WriteString(t.parts[i])
		value, ok := values[name]
		if !ok {
			return "", ferry.Errorf("%q needs a value for {%s}", t.source, name)
		}
		if !t.patterns[name].MatchString(value) {
			// The value is not quoted: it came from the command line.
			return "", ferry.Errorf("the value for {%s} does not match its pattern in %q", name, t.source)
		}
		out.WriteString(value)
	}
	out.WriteString(t.parts[len(t.parts)-1])
	return out.String(), nil
}

// Parse reads a name back into its placeholder values. ok is false for any
// name Build would not produce.
func (t *Template) Parse(name string) (values map[string]string, ok bool) {
	m := t.whole.FindStringSubmatch(name)
	if m == nil {
		return nil, false
	}
	values = map[string]string{}
	for i, group := range t.whole.SubexpNames() {
		if group != "" {
			values[group] = m[i]
		}
	}
	return values, true
}

// Form describes the template for a message: the source with each placeholder
// shown as <name>.
func (t *Template) Form() string {
	return placeholder.ReplaceAllString(t.source, "<$1>")
}
