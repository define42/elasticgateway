package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/elastic"
	"github.com/define42/elasticgateway/internal/ingest"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
)

const maxIngestRequestBodyBytes = int64(512 * 1024 * 1024)

var (
	errIngestAuthRequired = errors.New("ingest authentication required")
	errIngestForbidden    = errors.New("ingest user is not allowed to write to this index")
)

// IngestResponse is returned to clients after a successful ingest request.
type IngestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

// BulkIngestResponse is returned after a successful bulk ingest request.
type BulkIngestResponse struct {
	Took                int                                 `json:"took,omitempty"`
	Errors              bool                                `json:"errors"`
	Documents           int                                 `json:"documents"`
	WriteAliases        []string                            `json:"write_aliases"`
	BootstrappedAliases []string                            `json:"bootstrapped_write_aliases,omitempty"`
	Items               []map[string]elastic.BulkItemResult `json:"items"`
}

func gatewayIngestRequestPath(path string) string {
	if path == gatewayIngestPath {
		return "/ingest"
	}
	if strings.HasPrefix(path, gatewayIngestPath+"/") {
		return "/ingest" + strings.TrimPrefix(path, gatewayIngestPath)
	}
	return path
}

func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	ingestPath := gatewayIngestRequestPath(r.URL.Path)
	if isBulkIngestPath(ingestPath) {
		g.handleBulkIngest(w, r, ingestPath)
		return
	}

	indexName, err := ingest.ParsePath(ingestPath)
	if err != nil {
		writeIngestPathError(w, r, err)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	spaceName, err := g.authorizeIngestRequest(r, indexName)
	if err != nil {
		g.writeIngestAuthError(w, r, err)
		return
	}

	document, writeAlias, status, err := decodeIngestDocument(w, r, indexName)
	if err != nil {
		writeErrorJSON(w, status, err.Error())
		return
	}

	if err := g.Client.EnsureKibanaDataView(r.Context(), spaceName, indexName); err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "kibana_setup", err)
		return
	}

	bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), writeAlias)
	if err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_bootstrap", err)
		return
	}

	indexed, err := g.Client.IndexDocument(r.Context(), writeAlias, document)
	if err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_ingest", err)
		return
	}

	writeJSON(w, http.StatusCreated, IngestResponse{
		Result:       indexed.Result,
		WriteAlias:   writeAlias,
		DocumentID:   indexed.ID,
		Bootstrapped: bootstrapped,
	})
}

func (g *Gateway) handleBulkIngest(w http.ResponseWriter, r *http.Request, ingestPath string) {
	indexName, err := ingest.ParseBulkPath(ingestPath)
	if err != nil {
		writeIngestPathError(w, r, err)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	spaceName, err := g.authorizeIngestRequest(r, indexName)
	if err != nil {
		g.writeIngestAuthError(w, r, err)
		return
	}

	documents, status, err := decodeBulkIngestDocuments(w, r, indexName)
	if err != nil {
		writeErrorJSON(w, status, err.Error())
		return
	}

	if err := g.Client.EnsureKibanaDataView(r.Context(), spaceName, indexName); err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "kibana_setup", err)
		return
	}

	aliases := bulkWriteAliases(documents)
	bootstrappedAliases := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), alias)
		if err != nil {
			g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_bootstrap", err)
			return
		}
		if bootstrapped {
			bootstrappedAliases = append(bootstrappedAliases, alias)
		}
	}

	indexed, err := g.Client.BulkIndexDocuments(r.Context(), documents)
	if err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_bulk_ingest", err)
		return
	}

	writeJSON(w, http.StatusOK, BulkIngestResponse{
		Took:                indexed.Took,
		Errors:              indexed.Errors,
		Documents:           len(documents),
		WriteAliases:        aliases,
		BootstrappedAliases: bootstrappedAliases,
		Items:               indexed.Items,
	})
}

func (g *Gateway) authorizeIngestRequest(r *http.Request, indexName string) (string, error) {
	username, access, err := g.ingestAccess(r)
	if err != nil {
		if errors.Is(err, ldappkg.ErrUnauthorized) {
			g.logIngestAuthorizationDenied(r, username, indexName, access, err)
		}
		return "", err
	}
	namespace, ok := authz.ResolveIngestWriteNamespace(access, indexName)
	if !ok {
		g.logIngestAuthorizationDenied(r, username, indexName, access, errIngestForbidden)
		return "", errIngestForbidden
	}
	return namespace, nil
}

func (g *Gateway) logIngestAuthorizationDenied(r *http.Request, username, indexName string, access []authz.Access, err error) {
	attrs := []any{
		slog.String("event", "ingest_authorization_denied"),
		slog.String("username", strings.TrimSpace(username)),
		slog.String("requested_index", indexName),
		slog.Int("http_status", http.StatusForbidden),
		slog.Any("access_map", accessLogMap(access)),
	}
	attrs = append(attrs, g.requestLogAttrs(r)...)
	if err != nil {
		attrs = append(attrs,
			slog.String("reason", ingestAuthorizationDenialReason(err)),
			slog.String("error", err.Error()),
		)
	}

	g.logger().WarnContext(r.Context(), "ingest authorization denied", attrs...)
}

func ingestAuthorizationDenialReason(err error) string {
	if errors.Is(err, ldappkg.ErrUnauthorized) {
		return "no_authorized_groups"
	}
	return "forbidden_index"
}

func (g *Gateway) ingestAccess(r *http.Request) (string, []authz.Access, error) {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		if sessionData, ok := g.currentSession(r); ok {
			return sessionLogUsername(sessionData), sessionData.Access, nil
		}
		return "", nil, errIngestAuthRequired
	}

	username, password, ok := r.BasicAuth()
	username = strings.TrimSpace(username)
	if !ok || username == "" || password == "" {
		return username, nil, errIngestAuthRequired
	}

	cachedUsername, access, _, err := g.IngestAuthCache.Resolve(ingest.AuthCacheKey(username, password), func() (string, []authz.Access, error) {
		return g.lookupIngestAccess(username, password)
	})
	if err != nil {
		return username, nil, err
	}
	return cachedUsername, access, nil
}

func (g *Gateway) lookupIngestAccess(username, password string) (string, []authz.Access, error) {
	user, access, err := g.Authenticate(username, password)
	if err != nil {
		return "", nil, err
	}

	cachedUsername := username
	if user != nil && strings.TrimSpace(user.Name) != "" {
		cachedUsername = strings.TrimSpace(user.Name)
	}
	return cachedUsername, access, nil
}

func writeIngestPathError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ingest.ErrRouteNotFound) {
		http.NotFound(w, r)
		return
	}
	writeErrorJSON(w, http.StatusBadRequest, err.Error())
}

func (g *Gateway) writeIngestAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errIngestAuthRequired), errors.Is(err, ldappkg.ErrInvalidCredentials), errors.Is(err, ldappkg.ErrUserNotFound):
		writeIngestAuthRequired(w, "LDAP username and password are required for ingest")
	case errors.Is(err, ldappkg.ErrUnauthorized), errors.Is(err, errIngestForbidden):
		writeErrorJSON(w, http.StatusForbidden, "your LDAP account is not allowed to ingest into this index")
	default:
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "ldap_authentication", err)
	}
}

func isBulkIngestPath(path string) bool {
	return strings.HasSuffix(strings.TrimSuffix(path, "/"), "/_bulk")
}

func decodeIngestDocument(w http.ResponseWriter, r *http.Request, indexName string) (map[string]any, string, int, error) {
	return decodeIngestDocumentWithLimit(w, r, indexName, maxIngestRequestBodyBytes)
}

func decodeIngestDocumentWithLimit(w http.ResponseWriter, r *http.Request, indexName string, maxBodyBytes int64) (map[string]any, string, int, error) {
	mediaType := strings.TrimSpace(r.Header.Get("Content-Type"))
	contentType, _, err := mime.ParseMediaType(mediaType)
	if err != nil || contentType != "application/json" {
		return nil, "", http.StatusUnsupportedMediaType, errors.New("content type must be application/json")
	}

	body, err := limitedIngestBody(w, r, maxBodyBytes)
	if err != nil {
		return nil, "", http.StatusRequestEntityTooLarge, err
	}

	document, err := ingest.DecodeJSONObject(body)
	if err != nil {
		if isRequestBodyTooLarge(err) {
			return nil, "", http.StatusRequestEntityTooLarge, requestBodyTooLargeError(maxBodyBytes)
		}
		return nil, "", http.StatusBadRequest, err
	}

	eventTime, err := ingest.ParseEventTime(document)
	if err != nil {
		return nil, "", http.StatusBadRequest, err
	}

	writeAlias := ingest.BuildWriteAlias(indexName, eventTime)
	firstIndex := ingest.BuildFirstBackingIndex(writeAlias)
	if len(writeAlias) > ingest.MaxIndexNameBytes || len(firstIndex) > ingest.MaxIndexNameBytes {
		return nil, "", http.StatusBadRequest, errors.New("generated alias or backing index name exceeds Elasticsearch limits")
	}

	document["event_time"] = eventTime.UTC().Format(time.RFC3339)
	return document, writeAlias, 0, nil
}

func decodeBulkIngestDocuments(w http.ResponseWriter, r *http.Request, indexName string) ([]elastic.BulkIndexDocument, int, error) {
	return decodeBulkIngestDocumentsWithLimit(w, r, indexName, maxIngestRequestBodyBytes)
}

func decodeBulkIngestDocumentsWithLimit(w http.ResponseWriter, r *http.Request, indexName string, maxBodyBytes int64) ([]elastic.BulkIndexDocument, int, error) {
	mediaType := strings.TrimSpace(r.Header.Get("Content-Type"))
	contentType, _, err := mime.ParseMediaType(mediaType)
	if err != nil || contentType != "application/x-ndjson" {
		return nil, http.StatusUnsupportedMediaType, errors.New("content type must be application/x-ndjson")
	}

	body, err := limitedIngestBody(w, r, maxBodyBytes)
	if err != nil {
		return nil, http.StatusRequestEntityTooLarge, err
	}

	decoded, err := ingest.DecodeBulkNDJSON(body)
	if err != nil {
		if isRequestBodyTooLarge(err) {
			return nil, http.StatusRequestEntityTooLarge, requestBodyTooLargeError(maxBodyBytes)
		}
		return nil, http.StatusBadRequest, err
	}

	documents := make([]elastic.BulkIndexDocument, 0, len(decoded))
	for _, item := range decoded {
		writeAlias, err := normalizeIngestDocument(indexName, item.Document)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("bulk source line %d: %w", item.Line, err)
		}

		documents = append(documents, elastic.BulkIndexDocument{
			Action:   item.Action,
			Index:    writeAlias,
			Metadata: item.Metadata,
			Document: item.Document,
		})
	}
	return documents, 0, nil
}

func limitedIngestBody(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) (io.Reader, error) {
	if r.ContentLength > maxBodyBytes {
		return nil, requestBodyTooLargeError(maxBodyBytes)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	return r.Body, nil
}

func isRequestBodyTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func requestBodyTooLargeError(maxBodyBytes int64) error {
	return fmt.Errorf("request body exceeds %s limit", byteLimitLabel(maxBodyBytes))
}

func byteLimitLabel(maxBodyBytes int64) string {
	const bytesPerMegabyte = 1024 * 1024
	if maxBodyBytes%bytesPerMegabyte == 0 {
		return fmt.Sprintf("%d MB", maxBodyBytes/bytesPerMegabyte)
	}
	return fmt.Sprintf("%d bytes", maxBodyBytes)
}

func normalizeIngestDocument(indexName string, document map[string]any) (string, error) {
	eventTime, err := ingest.ParseEventTime(document)
	if err != nil {
		return "", err
	}

	writeAlias := ingest.BuildWriteAlias(indexName, eventTime)
	firstIndex := ingest.BuildFirstBackingIndex(writeAlias)
	if len(writeAlias) > ingest.MaxIndexNameBytes || len(firstIndex) > ingest.MaxIndexNameBytes {
		return "", errors.New("generated alias or backing index name exceeds Elasticsearch limits")
	}

	document["event_time"] = eventTime.UTC().Format(time.RFC3339)
	return writeAlias, nil
}

func bulkWriteAliases(documents []elastic.BulkIndexDocument) []string {
	seen := make(map[string]struct{}, len(documents))
	for _, document := range documents {
		seen[document.Index] = struct{}{}
	}

	aliases := make([]string, 0, len(seen))
	for alias := range seen {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
}

func writeIngestAuthRequired(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="ElasticGateway ingest"`)
	writeErrorJSON(w, http.StatusUnauthorized, message)
}
