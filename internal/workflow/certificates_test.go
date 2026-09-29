package workflow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/bevicted/ict/internal/config"
)

func testSecretsManagerPolicy() AuthPolicy {
	return AuthPolicy{SecretsManagerID: "sm-1", SecretsManagerRegion: "eu-gb"}
}

func testIAMAuthenticator(t *testing.T, client *http.Client, endpoint string) *core.IamAuthenticator {
	t.Helper()
	authenticator, err := core.NewIamAuthenticatorBuilder().SetApiKey("test-api-key").SetURL(endpoint).SetClient(client).Build()
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func TestNewIBMCertificateStoreDiscoversPrivateTestEndpoint(t *testing.T) {
	var requestedResource bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"expiration":4102444800}`))
		case "/v2/resource_instances/sm-1":
			requestedResource = r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer test-token"
			_, _ = w.Write([]byte(`{"id":"sm-1","guid":"sm-1","region_id":"eu-gb","state":"active","dashboard_url":"https://sm-1.private.eu-gb.secrets-manager.test.appdomain.cloud/ui","ignored_sensitive_response_field":"not-retained"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = time.Second
	store, err := newIBMCertificateStoreWithHTTPClient(context.Background(), testSecretsManagerPolicy(), config.Endpoints{IAM: server.URL, ResourceController: server.URL}, []string{"IC_API_KEY=test-api-key"}, client)
	if err != nil {
		t.Fatal(err)
	}
	ibmStore, ok := store.(ibmCertificateStore)
	if !ok || !requestedResource || ibmStore.service.Service.GetServiceURL() != "https://sm-1.private.eu-gb.secrets-manager.test.appdomain.cloud" || ibmStore.service.Service.GetHTTPClient().Timeout != time.Second {
		t.Fatalf("store did not use the discovered bounded endpoint")
	}
}

func TestValidateSecretsManagerEndpoint(t *testing.T) {
	policy := testSecretsManagerPolicy()
	valid := resourceControllerInstance{ID: "sm-1", GUID: "sm-1", RegionID: "eu-gb", State: "active"}
	for _, test := range []struct {
		name     string
		instance resourceControllerInstance
		want     string
	}{
		{"private test", withDashboard(valid, "https://sm-1.private.eu-gb.secrets-manager.test.appdomain.cloud"), "https://sm-1.private.eu-gb.secrets-manager.test.appdomain.cloud"},
		{"production", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud/"), "https://sm-1.eu-gb.secrets-manager.appdomain.cloud"},
		{"dashboard UI", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud/ui"), "https://sm-1.eu-gb.secrets-manager.appdomain.cloud"},
		{"wrong instance", withDashboard(resourceControllerInstance{ID: "other", GUID: "other", RegionID: "eu-gb", State: "active"}, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud"), ""},
		{"wrong region", withDashboard(resourceControllerInstance{ID: "sm-1", GUID: "sm-1", RegionID: "us-south", State: "active"}, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud"), ""},
		{"wrong state", withDashboard(resourceControllerInstance{ID: "sm-1", GUID: "sm-1", RegionID: "eu-gb", State: "provisioning"}, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud"), ""},
		{"wrong scheme", withDashboard(valid, "http://sm-1.eu-gb.secrets-manager.appdomain.cloud"), ""},
		{"wrong suffix", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.example.invalid"), ""},
		{"non-root path", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud/private-value"), ""},
		{"dashboard UI child path", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud/ui/"), ""},
		{"escaped dashboard UI path", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud/%75i"), ""},
		{"port", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud:443"), ""},
		{"empty port delimiter", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud:/ui"), ""},
		{"credentials", withDashboard(valid, "https://user:private-value@sm-1.eu-gb.secrets-manager.appdomain.cloud"), ""},
		{"query", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud?private-value"), ""},
		{"forced query", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud/?"), ""},
		{"fragment", withDashboard(valid, "https://sm-1.eu-gb.secrets-manager.appdomain.cloud#private-value"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := validateSecretsManagerEndpoint(test.instance, policy)
			if test.want == "" {
				if err == nil || strings.Contains(err.Error(), "private-value") {
					t.Fatalf("accepted or leaked invalid endpoint: %q, %v", endpoint, err)
				}
				return
			}
			if err != nil || endpoint != test.want {
				t.Fatalf("endpoint = %q, %v; want %q", endpoint, err, test.want)
			}
		})
	}
}

func TestResourceControllerInstanceURLRejectsForcedQuery(t *testing.T) {
	if _, err := resourceControllerInstanceURL("https://allowed-host/?", "sm-1"); err == nil {
		t.Fatal("accepted resource controller endpoint with forced query")
	}
}

func withDashboard(instance resourceControllerInstance, dashboard string) resourceControllerInstance {
	instance.DashboardURL = dashboard
	return instance
}

func TestEndpointDiscoveryHTTPFailuresAreClassifiedWithoutLeaking(t *testing.T) {
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/token" {
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"expiration":4102444800}`))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"private-response-value"}`))
	}))
	defer server.Close()

	for _, test := range []struct {
		status int
		reason string
	}{
		{http.StatusUnauthorized, cleanupReasonAuthentication},
		{http.StatusForbidden, cleanupReasonAuthentication},
		{http.StatusTooManyRequests, cleanupReasonRateLimit},
		{http.StatusServiceUnavailable, cleanupReasonService},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			status = test.status
			client := server.Client()
			client.Timeout = time.Second
			_, err := discoverSecretsManagerEndpoint(context.Background(), client, testIAMAuthenticator(t, client, server.URL), testSecretsManagerPolicy(), server.URL)
			var apiErr certificateAPIError
			if !errors.As(err, &apiErr) || apiErr.reason != test.reason || apiErr.stage != cleanupStageEndpointDiscovery || strings.Contains(err.Error(), "private-response-value") {
				t.Fatalf("error = %v, class = %#v", err, apiErr)
			}
		})
	}
}

func TestEndpointDiscoveryTimeoutReturnsCleanupOutcome(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/token" {
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"expiration":4102444800}`))
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 20 * time.Millisecond
	started := time.Now()
	_, err := discoverSecretsManagerEndpoint(context.Background(), client, testIAMAuthenticator(t, client, server.URL), testSecretsManagerPolicy(), server.URL)
	reason, stage := cleanupError(err, cleanupReasonUnknown, cleanupStageClient)
	outcome := pendingCertificateCleanup(nil, nil, reason, stage)
	if time.Since(started) > time.Second || outcome.Status != cleanupOutcomePending || outcome.Reason != cleanupReasonTransport || outcome.Stage != cleanupStageEndpointDiscovery {
		t.Fatalf("timeout cleanup outcome = %#v", outcome)
	}
}

func TestIAMDiscoveryTimeoutIsBoundedAndClassified(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))

	client := server.Client()
	client.Timeout = 20 * time.Millisecond
	started := time.Now()
	_, err := discoverSecretsManagerEndpoint(context.Background(), client, testIAMAuthenticator(t, client, server.URL), testSecretsManagerPolicy(), server.URL)
	elapsed := time.Since(started)
	close(release)
	server.Close()
	var apiErr certificateAPIError
	if elapsed > time.Second || !errors.As(err, &apiErr) || apiErr.reason != cleanupReasonTransport || apiErr.stage != cleanupStageAuthenticate {
		t.Fatalf("IAM timeout error = %v, class = %#v", err, apiErr)
	}
}
