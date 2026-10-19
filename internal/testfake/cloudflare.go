// Package testfake is Cloudflare's Secrets Store API as far as secretferry uses
// it, kept in memory. Like the real one it takes a value in and never gives one
// out: nothing here returns a value over HTTP, so a test can only look at what
// the tool sent. Inspect is the test's own view of what a Worker would read.
package testfake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// StoreID is the id of the default fake store.
const StoreID = "0123456789abcdef0123456789abcdef"

// Account is an account id the fake accepts.
const Account = "0123456789abcdef0123456789abcdef"

// Seen is one request, as the fake saw it.
type Seen struct {
	Method        string
	URL           string
	Authorization string
	Body          string
}

// Secret is a stored secret.
type Secret struct {
	ID     string
	Name   string
	Value  string
	Scopes []string
}

// Options shape the fake.
type Options struct {
	// Stores replaces the default single store; set NoStores for none.
	Stores   []string
	NoStores bool
	// FailWith answers every request with this status.
	FailWith int
	// EchoBodyInErrors quotes the request body in the error, as a careless API might.
	EchoBodyInErrors bool
	// EchoValueInErrors quotes the value itself, as the API's error text would decode it,
	// rather than the request body around it.
	EchoValueInErrors bool
	// NotJSON answers 200 with text that is not JSON.
	NotJSON bool
}

// API is a running fake.
type API struct {
	Server *httptest.Server

	mu       sync.Mutex
	opts     Options
	stores   []string
	secrets  []*Secret
	requests []Seen
	next     int
}

// New starts a fake. Close it with t.Cleanup(api.Server.Close).
func New(opts Options) *API {
	a := &API{opts: opts, next: 1}
	switch {
	case opts.NoStores:
	case len(opts.Stores) > 0:
		a.stores = opts.Stores
	default:
		a.stores = []string{StoreID}
	}
	a.Server = httptest.NewServer(http.HandlerFunc(a.handle))
	return a
}

// URL is the base URL to give the client; it ends where the real one's /client/v4 does.
func (a *API) URL() string { return a.Server.URL + "/client/v4" }

// Requests returns every request seen so far.
func (a *API) Requests() []Seen {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Seen(nil), a.requests...)
}

// Inspect returns what a bound Worker would read.
func (a *API) Inspect(name string) (Secret, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.secrets {
		if s.Name == name {
			return *s, true
		}
	}
	return Secret{}, false
}

// Seed adds a secret, as an earlier set would have.
func (a *API) Seed(name, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secrets = append(a.secrets, &Secret{ID: a.newID(), Name: name, Value: value, Scopes: []string{"workers"}})
}

func (a *API) newID() string {
	id := fmt.Sprintf("%032x", a.next)
	a.next++
	return id
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func failure(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": 10000, "message": message}},
		"result":  nil,
	})
}

var (
	storesPath  = regexp.MustCompile(`^/client/v4/accounts/[0-9a-f]{32}/secrets_store/stores`)
	secretsPath = regexp.MustCompile(`^/([0-9a-f]{32})/secrets(?:/([0-9a-f]+))?$`)
)

func (a *API) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	raw, _ := io.ReadAll(r.Body)
	body := string(raw)
	a.requests = append(a.requests, Seen{
		Method: r.Method, URL: r.URL.String(), Authorization: r.Header.Get("Authorization"), Body: body,
	})

	if a.opts.FailWith != 0 {
		message := "Forbidden"
		if a.opts.EchoBodyInErrors && body != "" {
			message = "bad request: " + body
		}
		if a.opts.EchoValueInErrors {
			message = "invalid value " + sentValue(raw)
		}
		failure(w, a.opts.FailWith, message)
		return
	}
	if a.opts.NotJSON {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "<html>not json</html>")
		return
	}

	base := storesPath.FindString(r.URL.Path)
	if base == "" {
		failure(w, 404, "no such route")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, base)

	if rest == "" && r.Method == http.MethodGet {
		stores := make([]map[string]string, 0, len(a.stores))
		for _, id := range a.stores {
			stores = append(stores, map[string]string{"id": id, "name": "store"})
		}
		reply(w, 200, map[string]any{"success": true, "result": stores})
		return
	}

	m := secretsPath.FindStringSubmatch(rest)
	known := false
	if m != nil {
		for _, id := range a.stores {
			known = known || id == m[1]
		}
	}
	if !known {
		failure(w, 404, "no such store")
		return
	}
	meta := func(s *Secret) map[string]any {
		return map[string]any{"id": s.ID, "name": s.Name, "store_id": m[1], "scopes": s.Scopes, "status": "active"}
	}

	switch {
	case m[2] == "" && r.Method == http.MethodGet:
		search := r.URL.Query().Get("search")
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if perPage == 0 {
			perPage = 20
		}
		if page == 0 {
			page = 1
		}
		var matching []*Secret
		for _, s := range a.secrets {
			if search == "" || strings.Contains(s.Name, search) {
				matching = append(matching, s)
			}
		}
		from, to := min((page-1)*perPage, len(matching)), min(page*perPage, len(matching))
		result := []map[string]any{}
		for _, s := range matching[from:to] {
			result = append(result, meta(s))
		}
		reply(w, 200, map[string]any{
			"success": true, "result": result,
			"result_info": map[string]any{"page": page, "per_page": perPage, "total_count": len(matching)},
		})
	case m[2] == "" && r.Method == http.MethodPost:
		var items []struct {
			Name   string   `json:"name"`
			Value  string   `json:"value"`
			Scopes []string `json:"scopes"`
		}
		if json.Unmarshal(raw, &items) != nil {
			failure(w, 400, "bad body")
			return
		}
		var created []map[string]any
		for _, item := range items {
			for _, s := range a.secrets {
				if s.Name == item.Name {
					failure(w, 409, "secret_name_already_exists")
					return
				}
			}
			s := &Secret{ID: a.newID(), Name: item.Name, Value: item.Value, Scopes: item.Scopes}
			a.secrets = append(a.secrets, s)
			created = append(created, meta(s))
		}
		reply(w, 200, map[string]any{"success": true, "result": created})
	case m[2] != "" && r.Method == http.MethodPatch:
		for _, s := range a.secrets {
			if s.ID != m[2] {
				continue
			}
			var patch struct {
				Value  *string  `json:"value"`
				Scopes []string `json:"scopes"`
			}
			_ = json.Unmarshal(raw, &patch)
			if patch.Value != nil {
				s.Value = *patch.Value
			}
			if patch.Scopes != nil {
				s.Scopes = patch.Scopes
			}
			reply(w, 200, map[string]any{"success": true, "result": meta(s)})
			return
		}
		failure(w, 404, "no such secret")
	default:
		failure(w, 405, "no such method")
	}
}

// sentValue is the "value" a create (a list of items) or a replace (one object) carried.
func sentValue(raw []byte) string {
	var items []struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &items) == nil && len(items) > 0 {
		return items[0].Value
	}
	var one struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(raw, &one)
	return one.Value
}
