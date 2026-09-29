package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/bevicted/ict/internal/config"
)

const cleanupLeak = "token://malicious.example.invalid/body-secret"

func TestCertificateCleanupStagesAreBoundedAndValueFree(t *testing.T) {
	policy := AuthPolicy{SecretsManagerID: "instance", SecretsManagerRegion: "us-south", SecretGroupID: "group"}
	t.Run("client", func(t *testing.T) {
		outcome := (Runner{Environ: []string{}}).cleanupCertificates(context.Background(), policy, config.Endpoints{}, "allocation-123", &AuthAttempt{AllocationUID: "allocation-123", AttemptID: "attempt-123"})
		if outcome.Status != cleanupOutcomePending || outcome.Reason != cleanupReasonUnknown || outcome.Stage != cleanupStageClient {
			t.Fatalf("outcome = %#v", outcome)
		}
	})

	for _, test := range []struct {
		name, operation string
		configure       func(*authCertificateStore)
		wantReason      string
		wantStage       cleanupStage
	}{
		{name: "metadata get", operation: "get", configure: func(store *authCertificateStore) { store.getErr = errors.New(cleanupLeak) }, wantReason: cleanupReasonUnknown, wantStage: cleanupStageMetadataGet},
		{name: "metadata list", operation: "list", configure: func(store *authCertificateStore) { store.listErr = errors.New(cleanupLeak) }, wantReason: cleanupReasonList, wantStage: cleanupStageMetadataList},
		{name: "delete", operation: "delete", configure: func(store *authCertificateStore) { store.deleteErr = errors.New(cleanupLeak) }, wantReason: cleanupReasonDelete, wantStage: cleanupStageDelete},
		{name: "ownership mismatch", operation: "ownership", configure: func(store *authCertificateStore) {
			store.metadata["certificate-123"] = CertificateMetadata{ID: "certificate-123", AllocationUID: "other-allocation", AttemptID: "allocation-123"}
		}, wantReason: cleanupReasonOwnershipMismatch, wantStage: cleanupStageMetadataGet},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &authCertificateStore{metadata: map[string]CertificateMetadata{
				"certificate-123": {ID: "certificate-123", AllocationUID: "allocation-123", AttemptID: "attempt-123"},
			}}
			test.configure(store)
			outcome := (Runner{Certificates: store}).cleanupCertificates(context.Background(), policy, config.Endpoints{}, "allocation-123", &AuthAttempt{AllocationUID: "allocation-123", AttemptID: "attempt-123"}, AuthCertificateReference{ID: "certificate-123", AllocationUID: "allocation-123", AttemptID: "attempt-123"})
			if outcome.Status != cleanupOutcomePending || outcome.Reason != test.wantReason || outcome.Stage != test.wantStage {
				t.Fatalf("outcome = %#v", outcome)
			}
			data, err := json.Marshal(outcome)
			if err != nil || strings.Contains(string(data), cleanupLeak) {
				t.Fatalf("serialized outcome = %q, %v", data, err)
			}
		})
	}
}

func TestAttemptScopedCertificateCleanupRejectsMismatchedExplicitReference(t *testing.T) {
	policy := AuthPolicy{SecretGroupID: "group"}
	reference := AuthCertificateReference{ID: "certificate-124", AllocationUID: "allocation-123", AttemptID: "attempt-124"}
	store := &authCertificateStore{metadata: map[string]CertificateMetadata{
		"certificate-124": {ID: "certificate-124", AllocationUID: "allocation-123", AttemptID: "attempt-124"},
	}}

	outcome := (Runner{Certificates: store}).cleanupCertificates(context.Background(), policy, config.Endpoints{}, "allocation-123", &AuthAttempt{AllocationUID: "allocation-123", AttemptID: "attempt-123"}, reference)
	if outcome.Status != cleanupOutcomePending || outcome.Reason != cleanupReasonOwnershipMismatch || outcome.Stage != cleanupStageMetadataGet || outcome.Certificate == nil || *outcome.Certificate != reference || len(store.deleted) != 0 || store.metadata[reference.ID].ID == "" {
		t.Fatalf("outcome = %#v; deleted=%#v; remaining=%#v", outcome, store.deleted, store.metadata)
	}
}

func TestCertificateCleanupClassifiesIAMErrorsWithoutLeakingSDKContent(t *testing.T) {
	for _, test := range []struct {
		name       string
		response   *core.DetailedResponse
		wantReason string
	}{
		{name: "401", response: &core.DetailedResponse{StatusCode: http.StatusUnauthorized, Headers: http.Header{"Authorization": {cleanupLeak}}, RawResult: []byte(cleanupLeak)}, wantReason: cleanupReasonAuthentication},
		{name: "403", response: &core.DetailedResponse{StatusCode: http.StatusForbidden, Headers: http.Header{"Authorization": {cleanupLeak}}, RawResult: []byte(cleanupLeak)}, wantReason: cleanupReasonAuthentication},
		{name: "4xx", response: &core.DetailedResponse{StatusCode: http.StatusBadRequest, Headers: http.Header{"Authorization": {cleanupLeak}}, RawResult: []byte(cleanupLeak)}, wantReason: cleanupReasonRequest},
		{name: "5xx", response: &core.DetailedResponse{StatusCode: http.StatusServiceUnavailable, Headers: http.Header{"Authorization": {cleanupLeak}}, RawResult: []byte(cleanupLeak)}, wantReason: cleanupReasonService},
		{name: "transport", wantReason: cleanupReasonTransport},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := mapCertificateError(nil, &core.AuthenticationError{Err: errors.New(cleanupLeak), HTTPProblem: &core.HTTPProblem{Response: test.response}})
			var apiErr certificateAPIError
			if !errors.As(err, &apiErr) || apiErr.reason != test.wantReason || apiErr.stage != cleanupStageAuthenticate || strings.Contains(err.Error(), cleanupLeak) {
				t.Fatalf("error = %#v", err)
			}
		})
	}

	t.Run("service HTTP problem", func(t *testing.T) {
		err := mapCertificateError(nil, &core.HTTPProblem{IBMProblem: &core.IBMProblem{}, Response: &core.DetailedResponse{StatusCode: http.StatusTooManyRequests, Headers: http.Header{"Authorization": {cleanupLeak}}, RawResult: []byte(cleanupLeak)}})
		var apiErr certificateAPIError
		if !errors.As(err, &apiErr) || apiErr.reason != cleanupReasonRateLimit || apiErr.stage != "" || strings.Contains(err.Error(), cleanupLeak) {
			t.Fatalf("error = %#v", err)
		}
	})
}

func TestAuthCleanupOperationResultIncludesOnlySafeStage(t *testing.T) {
	backend := backendConfig()
	contextPath := authContext(t, backend, "vpn")
	store := ownedCertificateStore()
	store.deleteErr = errors.New(cleanupLeak)
	resultPath := filepath.Join(t.TempDir(), "auth-cleanup-result.json")
	if err := (Runner{Certificates: store}).AuthCleanup(context.Background(), "allocation-123", contextPath, resultPath, []string{"certificate-123"}, "allocation-123", ""); err != nil {
		t.Fatal(err)
	}
	data := mustRead(t, resultPath)
	var result OperationResult
	if err := json.Unmarshal(data, &result); err != nil || result.CleanupOutcome != cleanupOutcomePending || result.CleanupReason != cleanupReasonDelete || result.CleanupStage != cleanupStageDelete || strings.Contains(string(data), cleanupLeak) {
		t.Fatalf("result = %#v, %v", result, err)
	}
}
