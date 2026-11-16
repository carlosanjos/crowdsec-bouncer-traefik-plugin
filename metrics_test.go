package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_decisionOrigin(t *testing.T) {
	tests := []struct {
		decision Decision
		want     string
	}{
		{Decision{Origin: "CAPI", Scenario: "crowdsecurity/http-probing"}, "CAPI"},
		{Decision{Origin: "crowdsec", Scenario: "crowdsecurity/http-probing"}, "crowdsec"},
		{Decision{Origin: "lists", Scenario: "firehol_greensnow"}, "lists:firehol_greensnow"},
		{Decision{Origin: "lists"}, "lists"},
		{Decision{}, ""},
	}
	for _, tt := range tests {
		if got := decisionOrigin(tt.decision); got != tt.want {
			t.Errorf("decisionOrigin(%+v) = %q, want %q", tt.decision, got, tt.want)
		}
	}
}

func Test_handleStreamCache_keepsOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"deleted": [], "new": [
			{"type": "ban", "scope": "Ip", "value": "192.0.2.21", "duration": "1h", "origin": "CAPI", "scenario": "crowdsecurity/http-probing"},
			{"type": "ban", "scope": "Ip", "value": "192.0.2.22", "duration": "1h", "origin": "lists", "scenario": "firehol_greensnow"}
		]}`))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "")
	bouncer := &Bouncer{
		crowdsecScheme:      serverURL.Scheme,
		crowdsecHost:        serverURL.Host,
		crowdsecHeader:      "X-Api-Key",
		crowdsecStreamRoute: "/v1/decisions/stream",
		updateInterval:      60,
		httpClient:          server.Client(),
		cacheClient:         cacheClient,
		log:                 log,
	}
	cacheClient.Delete(cacheTimeoutKey)
	if err := handleStreamCache(bouncer); err != nil {
		t.Fatalf("handleStreamCache() error = %v", err)
	}
	for ipAddr, want := range map[string]string{"192.0.2.21": "CAPI", "192.0.2.22": "lists:firehol_greensnow"} {
		raw, err := cacheClient.Get(ipAddr)
		if err != nil {
			t.Fatalf("Get(%s) error = %v", ipAddr, err)
		}
		value, origin := cache.DecodeDecision(raw)
		if value != cache.BannedValue || origin != want {
			t.Errorf("cached %s = %q/%q, want %q/%q", ipAddr, value, origin, cache.BannedValue, want)
		}
	}
}

type usageMetricsPayload struct {
	RemediationComponents []struct {
		Metrics []struct {
			Items []struct {
				Name   string            `json:"name"`
				Value  int64             `json:"value"`
				Unit   string            `json:"unit"`
				Labels map[string]string `json:"labels"`
			} `json:"items"`
		} `json:"metrics"`
	} `json:"remediation_components"` //nolint:tagliatelle // LAPI wire format

}

func Test_reportMetrics_labelsByOriginAndRemediation(t *testing.T) {
	takeDropped()
	atomic.StoreInt64(&blockedRequests, 0)

	var payload usageMetricsPayload
	fail := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("invalid payload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	bouncer := &Bouncer{
		crowdsecScheme: serverURL.Scheme,
		crowdsecHost:   serverURL.Host,
		crowdsecHeader: "X-Api-Key",
		httpClient:     server.Client(),
		captchaClient:  &captcha.Client{},
		log:            logger.New("ERROR", ""),
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	bouncer.remediationStatusCode = http.StatusForbidden
	bouncer.handleRemediationServeHTTP(rw, req, "192.0.2.1", cache.EncodeDecision(cache.BannedValue, "CAPI"))
	bouncer.handleRemediationServeHTTP(rw, req, "192.0.2.1", cache.EncodeDecision(cache.BannedValue, "CAPI"))
	bouncer.handleRemediationServeHTTP(rw, req, "192.0.2.2", cache.EncodeDecision(cache.BannedValue, "lists:firehol_greensnow"))
	bouncer.handleBanServeHTTP(rw, req, "192.0.2.3", configuration.ReasonAPPSEC)
	bouncer.handleBanServeHTTP(rw, req, "192.0.2.4", configuration.ReasonTECH)

	// A failed push keeps the counts for the next window.
	if err := reportMetrics(bouncer); err == nil {
		t.Fatal("expected reportMetrics to fail against a 500")
	}
	fail = false
	if err := reportMetrics(bouncer); err != nil {
		t.Fatalf("reportMetrics() error = %v", err)
	}

	type item struct {
		origin, remediation string
		value               int64
	}
	items := payload.RemediationComponents[0].Metrics[0].Items
	got := make([]item, 0, len(items))
	for _, it := range items {
		if it.Name != "dropped" || it.Unit != "request" {
			t.Errorf("unexpected item %+v", it)
		}
		got = append(got, item{it.Labels["origin"], it.Labels["remediation"], it.Value})
	}
	want := []item{
		{"", "ban", 1},
		{"CAPI", "ban", 2},
		{"appsec", "ban", 1},
		{"lists:firehol_greensnow", "ban", 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("items = %+v, want %+v", got, want)
	}
	if n := atomic.LoadInt64(&blockedRequests); n != 0 {
		t.Errorf("blockedRequests = %d after push, want 0", n)
	}
	if left := takeDropped(); len(left) != 0 {
		t.Errorf("counts left after push: %v", left)
	}
}
