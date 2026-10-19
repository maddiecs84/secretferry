package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/testfake"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func noWrangler() (string, error) { return "", errors.New("not installed") }

func TestResolveCredentials(t *testing.T) {
	const acct = "0123456789abcdef0123456789abcdef"
	other := strings.Repeat("a", 32)

	t.Run("token and account from the environment", func(t *testing.T) {
		c, err := ResolveCredentials("", env(map[string]string{"CLOUDFLARE_API_TOKEN": " tok ", "CLOUDFLARE_ACCOUNT_ID": acct}), noWrangler)
		if err != nil || c != (Credentials{Account: acct, Token: "tok", TokenFrom: "CLOUDFLARE_API_TOKEN"}) {
			t.Fatalf("%+v, %v", c, err)
		}
	})
	t.Run("the environment's account beats the configured one", func(t *testing.T) {
		c, _ := ResolveCredentials(acct, env(map[string]string{"CLOUDFLARE_API_TOKEN": "t", "CLOUDFLARE_ACCOUNT_ID": other}), noWrangler)
		if c.Account != other {
			t.Errorf("account = %q", c.Account)
		}
	})
	t.Run("the configured account is used otherwise", func(t *testing.T) {
		c, _ := ResolveCredentials(acct, env(map[string]string{"CLOUDFLARE_API_TOKEN": "t"}), noWrangler)
		if c.Account != acct {
			t.Errorf("account = %q", c.Account)
		}
	})
	t.Run("no account", func(t *testing.T) {
		if _, err := ResolveCredentials("", env(map[string]string{"CLOUDFLARE_API_TOKEN": "t"}), noWrangler); err == nil || !strings.Contains(err.Error(), "No account") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("a malformed account", func(t *testing.T) {
		if _, err := ResolveCredentials("nope", env(map[string]string{"CLOUDFLARE_API_TOKEN": "t"}), noWrangler); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("wrangler is the fallback, and its last line is the token", func(t *testing.T) {
		wrangler := func() (string, error) { return "  ⛅ banner\n\nthe-token\n", nil }
		c, err := ResolveCredentials(acct, env(nil), wrangler)
		if err != nil || c.Token != "the-token" || c.TokenFrom != "wrangler auth token" {
			t.Fatalf("%+v, %v", c, err)
		}
	})
	t.Run("the environment's token is preferred and wrangler is not run", func(t *testing.T) {
		wrangler := func() (string, error) { t.Error("wrangler was run"); return "x", nil }
		if _, err := ResolveCredentials(acct, env(map[string]string{"CLOUDFLARE_API_TOKEN": "t"}), wrangler); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no token anywhere", func(t *testing.T) {
		for name, wrangler := range map[string]func() (string, error){
			"not installed":  noWrangler,
			"prints nothing": func() (string, error) { return "\n \n", nil },
		} {
			if _, err := ResolveCredentials(acct, env(nil), wrangler); err == nil || !strings.Contains(err.Error(), "No token") {
				t.Errorf("%s: error = %v", name, err)
			}
		}
	})
	t.Run("a token a header cannot carry is refused by where it came from, never echoed", func(t *testing.T) {
		for _, bad := range []string{"to ken", "tokené"} {
			_, err := ResolveCredentials(acct, env(map[string]string{"CLOUDFLARE_API_TOKEN": bad}), noWrangler)
			if err == nil || strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN") {
				t.Errorf("%q: error = %v", bad, err)
			}
		}
	})
}

func newClient(api *testfake.API) *Client {
	c := New(Credentials{Account: testfake.Account, Token: "token-abc"}, []string{"workers"})
	c.BaseURL = api.URL()
	return c
}

func store(t *testing.T, api *testfake.API) *Store {
	t.Helper()
	s, err := newClient(api).Store(context.Background())
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	return s
}

func fake(t *testing.T, opts testfake.Options) *testfake.API {
	t.Helper()
	api := testfake.New(opts)
	t.Cleanup(api.Server.Close)
	return api
}

func TestStoreNeedsExactlyOne(t *testing.T) {
	ctx := context.Background()
	if _, err := newClient(fake(t, testfake.Options{NoStores: true})).Store(ctx); err == nil || !strings.Contains(err.Error(), "no Secrets Store") {
		t.Errorf("none: %v", err)
	}
	two := fake(t, testfake.Options{Stores: []string{testfake.StoreID, strings.Repeat("b", 32)}})
	if _, err := newClient(two).Store(ctx); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("two: %v", err)
	}
}

func TestCreateSendsTheValueInTheBodyWithScopesAndTheBearerToken(t *testing.T) {
	api := fake(t, testfake.Options{})
	s := store(t, api)
	if err := s.Create(context.Background(), "acme-a", "the-value"); err != nil {
		t.Fatal(err)
	}
	got, ok := api.Inspect("acme-a")
	if !ok || got.Value != "the-value" || strings.Join(got.Scopes, ",") != "workers" {
		t.Fatalf("stored %+v, %v", got, ok)
	}
	for _, r := range api.Requests() {
		if r.Authorization != "Bearer token-abc" {
			t.Errorf("%s %s sent %q", r.Method, r.URL, r.Authorization)
		}
		// The value goes in a request body and nowhere else.
		if strings.Contains(r.URL, "the-value") {
			t.Errorf("the value is in a URL: %s", r.URL)
		}
	}
	last := api.Requests()[len(api.Requests())-1]
	if last.Method != "POST" || !strings.Contains(last.Body, "the-value") {
		t.Errorf("last request = %+v", last)
	}
}

func TestReplaceOverwritesInPlace(t *testing.T) {
	api := fake(t, testfake.Options{})
	api.Seed("acme-a", "old")
	s := store(t, api)
	id, ok, err := s.Lookup(context.Background(), "acme-a")
	if err != nil || !ok {
		t.Fatalf("Lookup: %v, %v", ok, err)
	}
	if err := s.Replace(context.Background(), id, "new"); err != nil {
		t.Fatal(err)
	}
	if got, _ := api.Inspect("acme-a"); got.Value != "new" {
		t.Errorf("value = %q", got.Value)
	}
}

func TestLookupMatchesTheNameExactly(t *testing.T) {
	api := fake(t, testfake.Options{})
	api.Seed("acme-a-extra", "x") // the API's search finds this for "acme-a"
	s := store(t, api)
	if _, ok, err := s.Lookup(context.Background(), "acme-a"); err != nil || ok {
		t.Errorf("a longer name was taken for a match: %v, %v", ok, err)
	}
	api.Seed("acme-a", "y")
	if _, ok, _ := s.Lookup(context.Background(), "acme-a"); !ok {
		t.Error("the exact name was not found")
	}
}

func TestNamesPagesThroughEverythingAndSorts(t *testing.T) {
	api := fake(t, testfake.Options{})
	for i := 250; i > 0; i-- {
		api.Seed(fmt.Sprintf("acme-%03d", i), "v")
	}
	names, err := store(t, api).Names(context.Background())
	if err != nil || len(names) != 250 {
		t.Fatalf("got %d names, %v", len(names), err)
	}
	if names[0] != "acme-001" || names[249] != "acme-250" {
		t.Errorf("not sorted: %s ... %s", names[0], names[249])
	}
}

func TestCreateOfAnExistingNameIsRefusedByTheAPI(t *testing.T) {
	api := fake(t, testfake.Options{})
	api.Seed("acme-a", "x")
	err := store(t, api).Create(context.Background(), "acme-a", "y")
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Errorf("error = %v", err)
	}
}

func TestPermissionErrorsSayWhichPermission(t *testing.T) {
	for _, status := range []int{401, 403} {
		_, err := newClient(fake(t, testfake.Options{FailWith: status})).Store(context.Background())
		if err == nil || !strings.Contains(err.Error(), "Secrets Store: Edit") || !strings.Contains(err.Error(), fmt.Sprint(status)) {
			t.Errorf("%d: %v", status, err)
		}
	}
	_, err := newClient(fake(t, testfake.Options{FailWith: 500})).Store(context.Background())
	if err == nil || strings.Contains(err.Error(), "Secrets Store: Edit") {
		t.Errorf("500 should not blame the token: %v", err)
	}
}

func TestAnErrorThatEchoesTheRequestNeverHoldsTheValue(t *testing.T) {
	const secret = "s3cr3t/with+\"odd\"\\chars"
	api := fake(t, testfake.Options{FailWith: 400, EchoBodyInErrors: true})
	// Build the store by hand: the failing fake refuses to list stores.
	s := &Store{client: newClient(api), id: testfake.StoreID}

	for name, call := range map[string]func() error{
		"create":  func() error { return s.Create(context.Background(), "acme-a", secret) },
		"replace": func() error { return s.Replace(context.Background(), strings.Repeat("a", 32), secret) },
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), `odd\"`) {
			t.Errorf("%s: the error holds the value: %v", name, err)
		}
		if !strings.Contains(err.Error(), "[redacted]") {
			t.Errorf("%s: the value was not replaced by a marker: %v", name, err)
		}
	}
}

func TestAnErrorThatQuotesTheValueItselfNeverHoldsIt(t *testing.T) {
	const secret = `plain-SECRET"with\quote`
	api := fake(t, testfake.Options{FailWith: 422, EchoValueInErrors: true})
	s := &Store{client: newClient(api), id: testfake.StoreID}

	err := s.Create(context.Background(), "acme-a", secret)
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "invalid value [redacted]") {
		t.Errorf("error = %v", err)
	}
}

func TestUnreachableAndNotJSON(t *testing.T) {
	api := fake(t, testfake.Options{})
	c := newClient(api)
	api.Server.Close()
	if _, err := c.Store(context.Background()); err == nil || !strings.Contains(err.Error(), "could not be reached") {
		t.Errorf("unreachable: %v", err)
	}
	if _, err := newClient(fake(t, testfake.Options{NotJSON: true})).Store(context.Background()); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("not json: %v", err)
	}
}

func TestAnUnexpectedShapeIsRefused(t *testing.T) {
	odd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":1,"name":"x"}]}`)
	}))
	defer odd.Close()
	c := New(Credentials{Account: testfake.Account, Token: "t"}, nil)
	c.BaseURL = odd.URL
	if _, err := c.Store(context.Background()); err == nil || !strings.Contains(err.Error(), "unexpected shape") {
		t.Errorf("error = %v", err)
	}
}
