package actions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-cli-golang/pkg/cli"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb/models"
)

// This file holds the shared harness for the exec success-output tests. It
// builds the real cobra tree (IdsecBaseExecAction.DefineAction) and runs it
// with root.Execute(), so a test goes through PersistentPreRun,
// IdsecBaseExecAction.runExecAction, common.RetryCall and
// IdsecServiceExecAction.RunExecAction. The SDK services it reaches are the
// real ones; only the network is replaced: an ISP-authenticated API is built
// from a fake JWT, and every HTTPS request is sent through a CONNECT proxy to a
// local TLS test server.
//
// It deliberately references no symbol added by OLY-21332 so the human-mode
// golden tests that use it can be run unchanged against the baseline commit.

// f64p returns a pointer to f.
func f64p(f float64) *float64 { return &f }

// fakeJWT returns an unsigned-looking JWT with the claims the SDK needs to
// resolve a tenant URL. Only its structure matters: nothing verifies it.
func fakeJWT() string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"subdomain":"t","platform_domain":"cyberark.cloud","iss":"https://t.id.cyberark.cloud"}`)) + "." +
		enc([]byte("sig"))
}

// connectProxy returns an HTTP proxy that tunnels every CONNECT request to
// backendAddr, whatever host the client asked for.
func connectProxy(t *testing.T, backendAddr string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", backendAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// execFake is a ready-to-run `idsec exec ...` command tree with a fake backend.
type execFake struct {
	t    *testing.T
	root *cobra.Command
	mu   sync.Mutex
	hits map[string]int
}

// hitCount returns how many requests "METHOD /path" the backend served.
func (h *execFake) hitCount(key string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[key]
}

// newExecFake builds the command tree. agent selects agent mode (through
// IDSEC_AGENT_MODE, as setExecAgentMode does). The profile has an "isp" auth
// profile plus one per extra name; extra authenticators have no usable token,
// which makes the run a partial-auth run. handler serves the backend; a nil
// handler uses defaultExecBackend.
//
// It must not be called from a t.Parallel() test.
func newExecFake(t *testing.T, agent bool, handler http.HandlerFunc, extraAuthenticators ...string) *execFake {
	t.Helper()
	setExecAgentMode(t, agent)
	// CommonActionsExecution reserves stdout in agent mode; do not leak it.
	t.Cleanup(config.ReleaseStdoutForData)

	t.Setenv(suppressUpgradeCheckEnvVar, "1")
	t.Setenv(config.IdsecDisableTelemetryCollectionEnvVar, "1")
	t.Setenv(config.IdsecDisableCertificateVerificationEnvVar, "1")
	t.Setenv("IDSEC_IDENTITY_FORCE_PLATFORM_URL", "true")

	prevNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prevNoColor })

	if handler == nil {
		handler = defaultExecBackend
	}
	h := &execFake{t: t, hits: map[string]int{}}
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hits[r.Method+" "+r.URL.Path]++
		h.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(backend.Close)
	proxy := connectProxy(t, backend.Listener.Addr().String())
	t.Setenv(config.IdsecProxyAddressEnvVar, proxy.URL)

	stubLoadAuthentication(t, func(name string) (*authmodels.IdsecToken, error) {
		if name == "isp" {
			return tokenExpiringIn(time.Hour), nil
		}
		return nil, nil
	})
	prevAPI := newCLIAPI
	t.Cleanup(func() { newCLIAPI = prevAPI })
	newCLIAPI = func(_ []auth.IdsecAuth, profile *models.IdsecProfile) (*cli.IdsecCLIAPI, error) {
		isp, _ := auth.NewIdsecISPAuth(false).(*auth.IdsecISPAuth)
		token := tokenExpiringIn(time.Hour)
		token.Token = fakeJWT()
		token.TokenType = authmodels.JWT
		isp.Token = token
		return cli.NewIdsecCLIAPI([]auth.IdsecAuth{isp}, profile)
	}

	loader := testutils.NewMockProfileLoader()
	loader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
		return profileWithAuthenticators(name, append([]string{"isp"}, extraAuthenticators...)...), nil
	}
	h.root = &cobra.Command{Use: "idsec", SilenceErrors: true, SilenceUsage: true}
	NewIdsecServiceExecAction(loader.AsProfileLoader()).DefineAction(h.root)
	return h
}

// run executes `idsec exec <path...> --profile-name dev <flags...>` and returns
// what the command wrote to stdout and stderr.
func (h *execFake) run(path []string, flags ...string) (stdout, stderr string, err error) {
	h.t.Helper()
	argv := append([]string{"exec"}, path...)
	argv = append(argv, "--profile-name", "dev")
	argv = append(argv, flags...)
	h.root.SetArgs(argv)
	stdout = withCapturedOutput(func() {
		stderr = withCapturedStderr(func() { err = h.root.Execute() })
	})
	return stdout, stderr, err
}

// Backend routes of defaultExecBackend, as "METHOD /path".
const (
	routePoolsList     = "GET /api/pool-service/pools"
	routeSessionsList  = "GET /api/sessions"
	routePublicKey     = "GET /api/public-keys"
	routeGenerateCA    = "POST /api/public-keys/rotation/generate-new"
	routeAuthProfiles  = "POST /api/idadmin/AuthProfile/GetDecoratedProfileList"
	publicKeyText      = "ssh-ed25519 AAAA test"
	noOutputMessage    = "Generate New Ca finished successfully"
	defaultPoolsReply  = `{"resources":[{"id":"p1","name":"alpha","assigned_network_ids":["n1"]}]}`
	defaultSessionsRep = `{"sessions":[],"filtered_count":5,"returned_count":3}`
)

// defaultExecBackend serves the handful of SDK endpoints the success-output
// tests use.
func defaultExecBackend(w http.ResponseWriter, r *http.Request) {
	switch r.Method + " " + r.URL.Path {
	case routePoolsList:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, defaultPoolsReply)
	case routeSessionsList:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, defaultSessionsRep)
	case routePublicKey:
		_, _ = io.WriteString(w, publicKeyText)
	case routeGenerateCA:
		w.WriteHeader(http.StatusCreated)
	case routeAuthProfiles:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"Result":{"Results":[]}}`)
	default:
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

// indentedJSON returns v as json.MarshalIndent(v, "", "  ") plus the newline
// the human path's PrintSuccess adds.
func indentedJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// execKindCase is one result kind reachable through the real exec path.
type execKindCase struct {
	name  string
	path  []string
	flags []string
	// agentData and agentCount are what the agent envelope holds after
	// decoding; a nil agentCount means the count member must be absent.
	agentData  any
	agentCount *float64
	agentMsg   string
	// human is the exact stdout in human mode.
	human string
}

// execKindCases lists the result kinds a real SDK service can produce without
// network access beyond the fake backend. Maps, bools and channels of non-paged
// values have no real producer; seamKindCases covers them.
func execKindCases(t *testing.T) []execKindCase {
	t.Helper()
	engines := make([]any, 0, len(workspacesdbmodels.DatabaseEngineTypes))
	for _, e := range workspacesdbmodels.DatabaseEngineTypes {
		engines = append(engines, e)
	}
	const poolHuman = "{\n" +
		"  \"pool_id\": \"p1\",\n" +
		"  \"name\": \"alpha\",\n" +
		"  \"assigned_network_ids\": [\n" +
		"    \"n1\"\n" +
		"  ],\n" +
		"  \"created_at\": \"\",\n" +
		"  \"updated_at\": \"\"\n" +
		"}"
	return []execKindCase{
		{
			name:       "slice",
			path:       []string{"sia", "workspaces-db", "list-engine-types"},
			agentData:  engines,
			agentCount: f64p(float64(len(engines))),
			human:      indentedJSON(t, workspacesdbmodels.DatabaseEngineTypes),
		},
		{
			// The SDK returns a nil slice here; human mode prints "null".
			name:       "empty_slice",
			path:       []string{"identity", "auth-profiles", "list"},
			agentData:  []any{},
			agentCount: f64p(0),
			human:      "null\n",
		},
		{
			name: "channel_of_items_pages",
			path: []string{"cmgr", "pools", "list"},
			agentData: []any{map[string]any{
				"pool_id": "p1", "name": "alpha", "assigned_network_ids": []any{"n1"},
				"created_at": "", "updated_at": "",
			}},
			agentCount: f64p(1),
			human:      "[\n  " + indentTail(poolHuman) + "\n]\n",
		},
		{
			name: "struct",
			path: []string{"cmgr", "pools", "stats"},
			agentData: map[string]any{
				"pools_count":                1.0,
				"networks_count_per_pool":    map[string]any{"alpha": 1.0},
				"identifiers_count_per_pool": map[string]any{"alpha": 0.0},
				"components_count_per_pool":  map[string]any{"alpha": nil},
			},
			human: "{\n" +
				"  \"pools_count\": 1,\n" +
				"  \"networks_count_per_pool\": {\n    \"alpha\": 1\n  },\n" +
				"  \"identifiers_count_per_pool\": {\n    \"alpha\": 0\n  },\n" +
				"  \"components_count_per_pool\": {\n    \"alpha\": null\n  }\n" +
				"}\n",
		},
		{
			name:      "int",
			path:      []string{"sm", "sessions", "count"},
			agentData: 3.0,
			human:     "3\n",
		},
		{
			name:      "string",
			path:      []string{"sia", "ssh-ca", "public-key"},
			agentData: publicKeyText,
			human:     publicKeyText + "\n",
		},
		{
			name:      "no_output",
			path:      []string{"sia", "ssh-ca", "generate-new-ca"},
			agentData: nil,
			agentMsg:  noOutputMessage,
			human:     noOutputMessage + "\n",
		},
	}
}

// indentTail indents every line of s after the first by two spaces, so a
// MarshalIndent object can be embedded as an array element.
func indentTail(s string) string {
	out := make([]byte, 0, len(s)+16)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i])
		if s[i] == '\n' {
			out = append(out, ' ', ' ')
		}
	}
	return string(out)
}

// matrixPage is a paged SDK result: pages carry their elements in Items.
type matrixPage struct {
	Items []any
}

// matrixValue is a channel element that is not a page (it has no Items field).
type matrixValue struct {
	ID int
}

// seamKindCase is one result kind fed directly to the output seam, for kinds
// no real SDK service returns without a network.
type seamKindCase struct {
	name       string
	mk         func() []reflect.Value
	agentData  any
	agentCount *float64
	agentMsg   string
	human      string
}

// seamKindCases covers every result kind of the output seam. mk builds fresh
// values because channel results are consumed.
func seamKindCases() []seamKindCase {
	pages := func() []reflect.Value {
		ch := make(chan matrixPage, 2)
		ch <- matrixPage{Items: []any{"a", "b"}}
		ch <- matrixPage{Items: []any{"c"}}
		close(ch)
		return []reflect.Value{reflect.ValueOf(ch)}
	}
	values := func() []reflect.Value {
		ch := make(chan matrixValue, 2)
		ch <- matrixValue{ID: 1}
		ch <- matrixValue{ID: 2}
		close(ch)
		return []reflect.Value{reflect.ValueOf(ch)}
	}
	var nilPtr *string
	return []seamKindCase{
		{
			name:      "struct",
			mk:        func() []reflect.Value { return []reflect.Value{reflect.ValueOf(struct{ A int }{1})} },
			agentData: map[string]any{"A": 1.0},
			human:     "{\n  \"A\": 1\n}\n",
		},
		{
			name:      "map",
			mk:        func() []reflect.Value { return []reflect.Value{reflect.ValueOf(map[string]any{"k": "v"})} },
			agentData: map[string]any{"k": "v"},
			human:     "{\n  \"k\": \"v\"\n}\n",
		},
		{
			name:       "slice",
			mk:         func() []reflect.Value { return []reflect.Value{reflect.ValueOf([]any{"x", "y"})} },
			agentData:  []any{"x", "y"},
			agentCount: f64p(2),
			human:      "[\n  \"x\",\n  \"y\"\n]\n",
		},
		{
			name:       "empty_slice",
			mk:         func() []reflect.Value { return []reflect.Value{reflect.ValueOf([]any{})} },
			agentData:  []any{},
			agentCount: f64p(0),
			human:      "[]\n",
		},
		{
			name:       "channel_of_items_pages",
			mk:         pages,
			agentData:  []any{"a", "b", "c"},
			agentCount: f64p(3),
			human:      "[\n  \"a\",\n  \"b\",\n  \"c\"\n]\n",
		},
		{
			name:       "channel_of_non_paged_values",
			mk:         values,
			agentData:  []any{map[string]any{"ID": 1.0}, map[string]any{"ID": 2.0}},
			agentCount: f64p(2),
			human:      "[\n  {\n    \"ID\": 1\n  },\n  {\n    \"ID\": 2\n  }\n]\n",
		},
		{
			name:      "int",
			mk:        func() []reflect.Value { return []reflect.Value{reflect.ValueOf(42)} },
			agentData: 42.0,
			human:     "42\n",
		},
		{
			name:      "bool",
			mk:        func() []reflect.Value { return []reflect.Value{reflect.ValueOf(true)} },
			agentData: true,
			human:     "true\n",
		},
		{
			name:      "string",
			mk:        func() []reflect.Value { return []reflect.Value{reflect.ValueOf("hi")} },
			agentData: "hi",
			human:     "hi\n",
		},
		{
			name:      "nil_pointer",
			mk:        func() []reflect.Value { return []reflect.Value{reflect.ValueOf(nilPtr)} },
			agentData: nil,
			agentMsg:  "List Things finished successfully",
			human:     "List Things finished successfully\n",
		},
		{
			name:      "no_output",
			mk:        func() []reflect.Value { return nil },
			agentData: nil,
			agentMsg:  "List Things finished successfully",
			human:     "List Things finished successfully\n",
		},
	}
}

// failBackend answers every request with a 500 and records nothing else.
func failBackend(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, fmt.Sprintf("backend failure at %s", time.Now().Format(time.RFC3339)), http.StatusInternalServerError)
}
