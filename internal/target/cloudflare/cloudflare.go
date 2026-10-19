// Package cloudflare writes secrets to Cloudflare Secrets Store through its
// REST API. Cloudflare never returns a stored value, to anyone, and neither
// does this package: it takes a value in, sends it in a request body, and
// answers with names. No error it returns holds the value, even one the API
// echoes back.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/maddiecs84/secretferry/internal/ferry"
)

// MaxSecretBytes is Secrets Store's limit on a value.
const MaxSecretBytes = 65_536

const (
	defaultBase = "https://api.cloudflare.com/client/v4"
	pageSize    = 100
)

var (
	accountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// What an Authorization header can carry: printable ASCII, no spaces.
	tokenRe = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Credentials are the account and token the tool acts with.
type Credentials struct {
	Account string
	Token   string
	// TokenFrom names where the token came from, for a message.
	TokenFrom string
}

// ResolveCredentials finds the account (CLOUDFLARE_ACCOUNT_ID, else the
// configuration's) and the token (CLOUDFLARE_API_TOKEN, else the last line of
// what `wrangler auth token` prints, when wrangler is installed). Either
// needs permission to edit Secrets Store: a `wrangler login` may not have it,
// and then the API says so. A token a header cannot carry is refused by where
// it came from, never echoed.
func ResolveCredentials(configured string, getenv func(string) string, wranglerToken func() (string, error)) (Credentials, error) {
	account := strings.TrimSpace(getenv("CLOUDFLARE_ACCOUNT_ID"))
	if account == "" {
		account = configured
	}
	if account == "" {
		return Credentials{}, ferry.Errorf("No account: set cloudflare.accountId in the configuration, or CLOUDFLARE_ACCOUNT_ID.")
	}
	if !accountRe.MatchString(account) {
		return Credentials{}, ferry.Errorf("The Cloudflare account must be a 32-character account id.")
	}

	token := strings.TrimSpace(getenv("CLOUDFLARE_API_TOKEN"))
	from := "CLOUDFLARE_API_TOKEN"
	if token == "" {
		from = "wrangler auth token"
		if printed, err := wranglerToken(); err == nil {
			lines := strings.Split(printed, "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				if line := strings.TrimSpace(lines[i]); line != "" {
					token = line
					break
				}
			}
		}
		if token == "" {
			return Credentials{}, ferry.Errorf("No token: set CLOUDFLARE_API_TOKEN (Account Secrets Store: Edit), or run `wrangler login` with wrangler on your PATH.")
		}
	}
	if !tokenRe.MatchString(token) {
		return Credentials{}, ferry.Errorf("The token from %s has characters a token cannot contain, such as spaces or symbols outside ASCII.", from)
	}
	return Credentials{Account: account, Token: token, TokenFrom: from}, nil
}

// WranglerAuthToken runs `wrangler auth token` if wrangler is on the PATH.
// It is a convenience, never a requirement.
func WranglerAuthToken() (string, error) {
	path, err := exec.LookPath("wrangler")
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, "auth", "token") //nolint:gosec // the wrangler the user has on their PATH, run with fixed arguments
	cmd.Env = append(os.Environ(), "WRANGLER_HIDE_BANNER=true")
	out, err := cmd.Output()
	return string(out), err
}

// Client talks to the API as one account.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	Creds   Credentials
	Scopes  []string
}

// New makes a Client for the real API.
func New(creds Credentials, scopes []string) *Client {
	return &Client{HTTP: http.DefaultClient, BaseURL: defaultBase, Creds: creds, Scopes: scopes}
}

type envelope struct {
	Success *bool `json:"success"`
	Errors  []struct {
		Message any `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalCount *int `json:"total_count"`
	} `json:"result_info"`
}

func redact(text, value string) string {
	if value == "" {
		return text
	}
	text = strings.ReplaceAll(text, value, "[redacted]")
	if quoted, err := json.Marshal(value); err == nil && len(quoted) > 2 {
		text = strings.ReplaceAll(text, string(quoted[1:len(quoted)-1]), "[redacted]")
	}
	return text
}

func apiError(status int, env *envelope, value string) error {
	var messages []string
	if env != nil {
		for _, e := range env.Errors {
			if s, ok := e.Message.(string); ok && s != "" {
				messages = append(messages, s)
			}
		}
	}
	text := "The Secrets Store API answered " + strconv.Itoa(status)
	if len(messages) > 0 {
		text += ": " + strings.Join(messages, "; ")
	}
	text += "."
	if status == 401 || status == 403 {
		text += " The token needs the account permission Secrets Store: Edit (Read is enough for list)."
	}
	return ferry.Errorf("%s", redact(text, value))
}

func (c *Client) call(ctx context.Context, method, path string, body any, value string) (*envelope, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, ferry.Errorf("could not encode the request")
		}
		reader = bytes.NewReader(encoded)
	}
	endpoint := c.BaseURL + "/accounts/" + c.Creds.Account + "/secrets_store" + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, ferry.Errorf("could not build the request")
	}
	req.Header.Set("Authorization", "Bearer "+c.Creds.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// The error is not quoted: all it could add is the address.
		return nil, ferry.Errorf("The Cloudflare API could not be reached.")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ferry.Errorf("The Cloudflare API could not be reached.")
	}

	var env envelope
	parsed := json.Unmarshal(raw, &env) == nil
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok || !parsed || env.Success == nil || !*env.Success {
		if !parsed && ok {
			return nil, ferry.Errorf("The Secrets Store API answered %d with something that is not JSON.", resp.StatusCode)
		}
		if parsed {
			return nil, apiError(resp.StatusCode, &env, value)
		}
		return nil, apiError(resp.StatusCode, nil, value)
	}
	return &env, nil
}

type metadata struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func asSecrets(raw json.RawMessage) ([]metadata, error) {
	var items []metadata
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, ferry.Errorf("The Secrets Store API answered with an unexpected shape.")
	}
	for _, item := range items {
		if item.ID == "" || item.Name == "" {
			return nil, ferry.Errorf("The Secrets Store API answered with an unexpected shape.")
		}
	}
	return items, nil
}

// Store is the account's one Secrets Store.
type Store struct {
	client *Client
	id     string
}

// Store finds the account's store (Secrets Store allows one per account), or
// refuses and says why not.
func (c *Client) Store(ctx context.Context) (*Store, error) {
	env, err := c.call(ctx, http.MethodGet, "/stores", nil, "")
	if err != nil {
		return nil, err
	}
	stores, err := asSecrets(env.Result)
	if err != nil {
		return nil, err
	}
	switch len(stores) {
	case 0:
		return nil, ferry.Errorf("The account has no Secrets Store yet: create one in the Cloudflare dashboard (Secrets Store) first.")
	case 1:
		return &Store{client: c, id: stores[0].ID}, nil
	default:
		return nil, ferry.Errorf("The account has more than one Secrets Store, which secretferry does not choose between.")
	}
}

func (s *Store) secrets(ctx context.Context, search string) ([]metadata, error) {
	var found []metadata
	for page := 1; ; page++ {
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(pageSize)}}
		if search != "" {
			query.Set("search", search)
		}
		env, err := s.client.call(ctx, http.MethodGet, "/stores/"+s.id+"/secrets?"+query.Encode(), nil, "")
		if err != nil {
			return nil, err
		}
		batch, err := asSecrets(env.Result)
		if err != nil {
			return nil, err
		}
		found = append(found, batch...)
		total := env.ResultInfo.TotalCount
		if len(batch) == 0 || (total != nil && len(found) >= *total) {
			return found, nil
		}
	}
}

// Names lists every secret's name, sorted. Never a value: there is none to show.
func (s *Store) Names(ctx context.Context) ([]string, error) {
	all, err := s.secrets(ctx, "")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(all))
	for _, secret := range all {
		names = append(names, secret.Name)
	}
	sort.Strings(names)
	return names, nil
}

// Lookup finds a secret by its exact name. The API's search matches any name
// that contains this one, so the result is filtered.
func (s *Store) Lookup(ctx context.Context, name string) (id string, found bool, err error) {
	matches, err := s.secrets(ctx, name)
	if err != nil {
		return "", false, err
	}
	for _, m := range matches {
		if m.Name == name {
			return m.ID, true, nil
		}
	}
	return "", false, nil
}

// Create writes a new secret.
func (s *Store) Create(ctx context.Context, name, value string) error {
	body := []map[string]any{{"name": name, "value": value, "scopes": s.client.Scopes}}
	_, err := s.client.call(ctx, http.MethodPost, "/stores/"+s.id+"/secrets", body, value)
	return err
}

// Replace overwrites an existing secret's value in place.
func (s *Store) Replace(ctx context.Context, id, value string) error {
	_, err := s.client.call(ctx, http.MethodPatch, "/stores/"+s.id+"/secrets/"+id, map[string]string{"value": value}, value)
	return err
}
