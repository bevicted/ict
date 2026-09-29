package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	secretsmanagerv2 "github.com/IBM/secrets-manager-go-sdk/v2/secretsmanagerv2"
	"github.com/bevicted/ict/internal/config"
)

const (
	cleanupOutcomeNotRequired = "not-required"
	cleanupOutcomeCleaned     = "cleaned"
	cleanupOutcomePending     = "pending"

	cleanupReasonOwnershipMismatch = "ownership-mismatch"
	cleanupReasonAuthentication    = "authentication"
	cleanupReasonRateLimit         = "rate-limit"
	cleanupReasonService           = "service"
	cleanupReasonRequest           = "request"
	cleanupReasonTransport         = "transport"
	cleanupReasonList              = "list"
	cleanupReasonDelete            = "delete"
	cleanupReasonUnknown           = "unknown"

	maxCertificateCleanupResults       = 10000
	maxResourceControllerMetadataBytes = 64 * 1024
	certificateHTTPTimeout             = 30 * time.Second
)

type cleanupStage string

const (
	cleanupStageClient            cleanupStage = "client"
	cleanupStageAuthenticate      cleanupStage = "authenticate"
	cleanupStageEndpointDiscovery cleanupStage = "endpoint-discovery"
	cleanupStageMetadataGet       cleanupStage = "metadata-get"
	cleanupStageMetadataList      cleanupStage = "metadata-list"
	cleanupStageDelete            cleanupStage = "delete"
)

func validCleanupStage(stage cleanupStage) bool {
	switch stage {
	case cleanupStageClient, cleanupStageAuthenticate, cleanupStageEndpointDiscovery, cleanupStageMetadataGet, cleanupStageMetadataList, cleanupStageDelete:
		return true
	default:
		return false
	}
}

var errCertificateNotFound = errors.New("certificate not found")

// CertificateMetadata contains the only certificate fields cleanup is allowed to retain.
type CertificateMetadata struct {
	ID            string
	AllocationUID string
	AttemptID     string
}

// CertificateStore isolates metadata-only certificate cleanup from the IBM API.
type CertificateStore interface {
	Get(context.Context, string) (CertificateMetadata, error)
	List(context.Context, string) ([]CertificateMetadata, error)
	Delete(context.Context, string) error
}

type ibmCertificateStore struct {
	service *secretsmanagerv2.SecretsManagerV2
}

// newIBMCertificateStore configures bounded IAM, Resource Controller, and
// Secrets Manager clients without emitting configuration or response values.
func newIBMCertificateStore(ctx context.Context, policy AuthPolicy, endpoints config.Endpoints, environ []string) (CertificateStore, error) {
	return newIBMCertificateStoreWithHTTPClient(ctx, policy, endpoints, environ, certificateHTTPClient(ctx))
}

func newIBMCertificateStoreWithHTTPClient(ctx context.Context, policy AuthPolicy, endpoints config.Endpoints, environ []string, client *http.Client) (CertificateStore, error) {
	apiKey := environmentValue(environ, "IC_API_KEY")
	if apiKey == "" {
		apiKey = environmentValue(environ, "IBMCLOUD_API_KEY")
	}
	if apiKey == "" {
		apiKey = environmentValue(environ, "IBM_CLOUD_API_KEY")
	}
	if apiKey == "" || client == nil {
		return nil, errors.New("certificate client unavailable")
	}
	authenticator, err := core.NewIamAuthenticatorBuilder().SetApiKey(apiKey).SetURL(endpoints.IAM).SetClient(client).Build()
	if err != nil {
		return nil, errors.New("certificate client unavailable")
	}
	endpoint, err := discoverSecretsManagerEndpoint(ctx, client, authenticator, policy, endpoints.ResourceController)
	if err != nil {
		return nil, err
	}
	service, err := secretsmanagerv2.NewSecretsManagerV2(&secretsmanagerv2.SecretsManagerV2Options{
		URL:           endpoint,
		Authenticator: authenticator,
	})
	if err != nil {
		return nil, errors.New("certificate client unavailable")
	}
	service.DisableRetries()
	service.Service.SetHTTPClient(client)
	return ibmCertificateStore{service: service}, nil
}

func certificateHTTPClient(ctx context.Context) *http.Client {
	timeout := certificateHTTPTimeout
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining < timeout {
				timeout = remaining
			}
		}
	}
	if timeout <= 0 {
		timeout = time.Nanosecond
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type resourceControllerInstance struct {
	ID           string `json:"id"`
	GUID         string `json:"guid"`
	RegionID     string `json:"region_id"`
	State        string `json:"state"`
	DashboardURL string `json:"dashboard_url"`
}

func discoverSecretsManagerEndpoint(ctx context.Context, client *http.Client, authenticator *core.IamAuthenticator, policy AuthPolicy, resourceControllerEndpoint string) (string, error) {
	if ctx == nil || authenticator == nil {
		return "", certificateAPIError{reason: cleanupReasonUnknown, stage: cleanupStageEndpointDiscovery}
	}
	requestURL, err := resourceControllerInstanceURL(resourceControllerEndpoint, policy.SecretsManagerID)
	if err != nil {
		return "", certificateAPIError{reason: cleanupReasonRequest, stage: cleanupStageEndpointDiscovery}
	}
	token, err := authenticator.GetToken()
	if err != nil {
		return "", certificateAuthenticationError(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return "", certificateAPIError{reason: cleanupReasonRequest, stage: cleanupStageEndpointDiscovery}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return "", certificateAPIError{reason: cleanupReasonTransport, stage: cleanupStageEndpointDiscovery}
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", certificateHTTPError(response.StatusCode, cleanupStageEndpointDiscovery)
	}
	var instance resourceControllerInstance
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResourceControllerMetadataBytes)).Decode(&instance); err != nil {
		return "", certificateAPIError{reason: cleanupReasonUnknown, stage: cleanupStageEndpointDiscovery}
	}
	endpoint, err := validateSecretsManagerEndpoint(instance, policy)
	if err != nil {
		return "", certificateAPIError{reason: cleanupReasonRequest, stage: cleanupStageEndpointDiscovery}
	}
	return endpoint, nil
}

func resourceControllerInstanceURL(endpoint, instanceID string) (string, error) {
	base, err := url.ParseRequestURI(endpoint)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.Path != "" && base.Path != "/" {
		return "", errors.New("invalid resource controller endpoint")
	}
	base.Path = "/v2/resource_instances/" + url.PathEscape(instanceID)
	base.RawPath = ""
	return base.String(), nil
}

func certificateAuthenticationError(err error) error {
	response, _ := certificateErrorResponse(nil, err)
	if response == nil {
		return certificateAPIError{reason: cleanupReasonTransport, stage: cleanupStageAuthenticate}
	}
	return certificateHTTPError(response.StatusCode, cleanupStageAuthenticate)
}

func certificateHTTPError(status int, stage cleanupStage) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return certificateAPIError{reason: cleanupReasonAuthentication, stage: stage}
	case status == http.StatusTooManyRequests:
		return certificateAPIError{reason: cleanupReasonRateLimit, stage: stage}
	case status >= http.StatusInternalServerError:
		return certificateAPIError{reason: cleanupReasonService, stage: stage}
	case status >= http.StatusBadRequest:
		return certificateAPIError{reason: cleanupReasonRequest, stage: stage}
	default:
		return certificateAPIError{reason: cleanupReasonUnknown, stage: stage}
	}
}

func validateSecretsManagerEndpoint(instance resourceControllerInstance, policy AuthPolicy) (string, error) {
	if (instance.ID != policy.SecretsManagerID && instance.GUID != policy.SecretsManagerID) || instance.RegionID != policy.SecretsManagerRegion || instance.State != "active" {
		return "", errors.New("invalid resource controller metadata")
	}
	endpoint, err := url.ParseRequestURI(instance.DashboardURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Host != endpoint.Hostname() || endpoint.User != nil || endpoint.Port() != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawPath != "" || (endpoint.Path != "" && endpoint.Path != "/" && endpoint.Path != "/ui") || !allowedSecretsManagerHostname(endpoint.Hostname(), policy) {
		return "", errors.New("invalid secrets manager endpoint")
	}
	return (&url.URL{Scheme: "https", Host: endpoint.Host}).String(), nil
}

func allowedSecretsManagerHostname(host string, policy AuthPolicy) bool {
	instance := strings.ToLower(policy.SecretsManagerID)
	region := strings.ToLower(policy.SecretsManagerRegion)
	for _, suffix := range []string{
		"." + region + ".secrets-manager.appdomain.cloud",
		".private." + region + ".secrets-manager.appdomain.cloud",
		"." + region + ".secrets-manager.test.appdomain.cloud",
		".private." + region + ".secrets-manager.test.appdomain.cloud",
	} {
		if host == instance+suffix {
			return true
		}
	}
	return false
}

func (s ibmCertificateStore) Get(ctx context.Context, id string) (CertificateMetadata, error) {
	secret, response, err := s.service.GetSecretMetadataWithContext(ctx, &secretsmanagerv2.GetSecretMetadataOptions{ID: core.StringPtr(id)})
	if err != nil {
		return CertificateMetadata{}, mapCertificateError(response, err)
	}
	return certificateMetadata(secret)
}

func (s ibmCertificateStore) List(ctx context.Context, groupID string) ([]CertificateMetadata, error) {
	const pageSize int64 = 1000
	offset := int64(0)
	var certificates []CertificateMetadata
	for {
		page, response, err := s.service.ListSecretsWithContext(ctx, &secretsmanagerv2.ListSecretsOptions{Offset: core.Int64Ptr(offset), Limit: core.Int64Ptr(pageSize), Groups: []string{groupID}, SecretTypes: []string{"private_cert"}})
		if err != nil {
			return nil, mapCertificateError(response, err)
		}
		if page == nil {
			return nil, errors.New("certificate cleanup list is unavailable")
		}
		for _, secret := range page.Secrets {
			metadata, err := certificateMetadata(secret)
			if err != nil {
				return nil, errors.New("certificate cleanup metadata is unavailable")
			}
			certificates = append(certificates, metadata)
			if len(certificates) > maxCertificateCleanupResults {
				return nil, errors.New("certificate cleanup list is too large")
			}
		}
		if page.Next == nil || page.Next.Href == nil || len(page.Secrets) == 0 {
			return certificates, nil
		}
		next, err := page.GetNextOffset()
		if err != nil || next == nil || *next <= offset {
			return nil, errors.New("certificate cleanup list is incomplete")
		}
		offset = *next
	}
}

func (s ibmCertificateStore) Delete(ctx context.Context, id string) error {
	response, err := s.service.DeleteSecretWithContext(ctx, &secretsmanagerv2.DeleteSecretOptions{ID: core.StringPtr(id)})
	if err != nil {
		return mapCertificateError(response, err)
	}
	return nil
}

type certificateAPIError struct {
	reason string
	stage  cleanupStage
}

func (e certificateAPIError) Error() string { return "certificate API request failed" }

func mapCertificateError(response *core.DetailedResponse, err error) error {
	response, authentication := certificateErrorResponse(response, err)
	stage := cleanupStage("")
	if authentication {
		stage = cleanupStageAuthenticate
	}
	if response == nil {
		if err != nil {
			return certificateAPIError{reason: cleanupReasonTransport, stage: stage}
		}
		return certificateAPIError{reason: cleanupReasonUnknown, stage: stage}
	}
	if !authentication && response.StatusCode == http.StatusNotFound {
		return errCertificateNotFound
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return certificateAPIError{reason: cleanupReasonAuthentication, stage: stage}
	case response.StatusCode == http.StatusTooManyRequests:
		return certificateAPIError{reason: cleanupReasonRateLimit, stage: stage}
	case response.StatusCode >= http.StatusInternalServerError:
		return certificateAPIError{reason: cleanupReasonService, stage: stage}
	case response.StatusCode >= http.StatusBadRequest:
		return certificateAPIError{reason: cleanupReasonRequest, stage: stage}
	default:
		return certificateAPIError{reason: cleanupReasonUnknown, stage: stage}
	}
}

// certificateErrorResponse reads only the SDK's status code carrier, never its
// headers, URL, body, result, or error text.
func certificateErrorResponse(response *core.DetailedResponse, err error) (*core.DetailedResponse, bool) {
	var authentication *core.AuthenticationError
	if errors.As(err, &authentication) {
		if authentication != nil && authentication.HTTPProblem != nil && authentication.Response != nil {
			return authentication.Response, true
		}
		return response, true
	}
	var problem *core.HTTPProblem
	if errors.As(err, &problem) && problem != nil && problem.Response != nil {
		return problem.Response, false
	}
	return response, false
}

func certificateMetadata(secret secretsmanagerv2.SecretMetadataIntf) (CertificateMetadata, error) {
	certificate, ok := secret.(*secretsmanagerv2.PrivateCertificateMetadata)
	if !ok || certificate.ID == nil {
		return CertificateMetadata{}, errors.New("not a private certificate")
	}
	return CertificateMetadata{
		ID:            *certificate.ID,
		AllocationUID: metadataValue(certificate.CustomMetadata, "ict_allocation_uid"),
		AttemptID:     metadataValue(certificate.CustomMetadata, "ict_auth_attempt_id"),
	}, nil
}

func metadataValue(metadata map[string]any, key string) string {
	value, ok := metadata[key].(string)
	if !ok {
		return ""
	}
	return value
}

type certificateCleanupOutcome struct {
	Status      string
	Reason      string
	Stage       cleanupStage
	Certificate *AuthCertificateReference
}

func (r Runner) certificates(ctx context.Context, policy AuthPolicy, endpoints config.Endpoints) (CertificateStore, error) {
	if r.Certificates != nil {
		return r.Certificates, nil
	}
	return newIBMCertificateStore(ctx, policy, endpoints, r.authEnvironment(endpoints, ""))
}

// cleanupCertificates deletes only certificates in its ownership scope. A
// supplied attempt restricts both explicit and listed certificates to its exact
// allocation and attempt IDs; nil permits allocation-wide owner cleanup.
func (r Runner) cleanupCertificates(ctx context.Context, policy AuthPolicy, endpoints config.Endpoints, allocationUID string, attempt *AuthAttempt, explicit ...AuthCertificateReference) certificateCleanupOutcome {
	outcome := certificateCleanupOutcome{Status: cleanupOutcomeCleaned}
	store, err := r.certificates(ctx, policy, endpoints)
	if err != nil {
		reason, stage := cleanupError(err, cleanupReasonUnknown, cleanupStageClient)
		return pendingCertificateCleanup(attempt, firstCertificateReference(explicit), reason, stage)
	}
	// Reconcile explicit persisted references before listing. This remains safe
	// when a list page is delayed or incomplete: Get verifies current ownership.
	for _, reference := range explicit {
		if reference.ID == "" || reference.AllocationUID != allocationUID || attempt != nil && (reference.AllocationUID != attempt.AllocationUID || reference.AttemptID != attempt.AttemptID) {
			return certificateCleanupOutcome{Status: cleanupOutcomePending, Reason: cleanupReasonOwnershipMismatch, Stage: cleanupStageMetadataGet, Certificate: &reference}
		}
		reason, stage := deleteOwnedCertificate(ctx, store, reference)
		if reason != "" {
			return pendingCertificateCleanup(attempt, &reference, reason, stage)
		}
	}
	certificates, err := store.List(ctx, policy.SecretGroupID)
	if err != nil {
		reason, stage := cleanupError(err, cleanupReasonList, cleanupStageMetadataList)
		return pendingCertificateCleanup(attempt, firstCertificateReference(explicit), reason, stage)
	}
	for _, certificate := range certificates {
		reference := certificateReference(certificate)
		if !sameCertificateCleanupScope(reference, allocationUID, attempt) {
			continue
		}
		if reason, stage := deleteOwnedCertificate(ctx, store, reference); reason != "" {
			return pendingCertificateCleanup(attempt, firstCertificateReference(explicit), reason, stage)
		}
	}
	return outcome
}

func firstCertificateReference(references []AuthCertificateReference) *AuthCertificateReference {
	if len(references) == 0 {
		return nil
	}
	reference := references[0]
	return &reference
}

func deleteOwnedCertificate(ctx context.Context, store CertificateStore, reference AuthCertificateReference) (string, cleanupStage) {
	metadata, err := store.Get(ctx, reference.ID)
	if errors.Is(err, errCertificateNotFound) {
		return "", ""
	}
	if err != nil {
		return cleanupError(err, cleanupReasonUnknown, cleanupStageMetadataGet)
	}
	if metadata.ID != reference.ID || metadata.AllocationUID != reference.AllocationUID || metadata.AttemptID == "" || reference.AttemptID != "" && metadata.AttemptID != reference.AttemptID {
		return cleanupReasonOwnershipMismatch, cleanupStageMetadataGet
	}
	if err := store.Delete(ctx, reference.ID); err != nil && !errors.Is(err, errCertificateNotFound) {
		return cleanupError(err, cleanupReasonDelete, cleanupStageDelete)
	}
	return "", ""
}

func cleanupError(err error, fallback string, stage cleanupStage) (string, cleanupStage) {
	var apiErr certificateAPIError
	if errors.As(err, &apiErr) {
		if validCleanupStage(apiErr.stage) {
			return apiErr.reason, apiErr.stage
		}
		return apiErr.reason, stage
	}
	return fallback, stage
}

func pendingCertificateCleanup(attempt *AuthAttempt, reference *AuthCertificateReference, reason string, stage cleanupStage) certificateCleanupOutcome {
	if reference == nil && attempt != nil {
		reference = &AuthCertificateReference{AllocationUID: attempt.AllocationUID, AttemptID: attempt.AttemptID}
	}
	return certificateCleanupOutcome{Status: cleanupOutcomePending, Reason: reason, Stage: stage, Certificate: reference}
}

func certificateReference(metadata CertificateMetadata) AuthCertificateReference {
	return AuthCertificateReference{ID: metadata.ID, AllocationUID: metadata.AllocationUID, AttemptID: metadata.AttemptID}
}

func sameCertificateCleanupScope(reference AuthCertificateReference, allocationUID string, attempt *AuthAttempt) bool {
	if reference.ID == "" || reference.AllocationUID != allocationUID || reference.AttemptID == "" {
		return false
	}
	return attempt == nil || reference.AllocationUID == attempt.AllocationUID && reference.AttemptID == attempt.AttemptID
}
