// Package ingest contains ingest-route parsing, document validation, and
// short-lived LDAP auth caching for the ingest endpoint.
package ingest

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
)

const (
	// CacheTTL is the lifetime of successful Basic Auth LDAP cache entries.
	CacheTTL = 5 * time.Minute
	// MaxIndexNameBytes is the maximum Elasticsearch alias or index name length.
	MaxIndexNameBytes = 255
	rolloverSuffix    = "-rollover"
	backingIndexSeed  = "-000001"
	bulkPathSuffix    = "/_bulk"
)

var (
	indexNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	// ErrRouteNotFound reports a path that does not target /ingest.
	ErrRouteNotFound = errors.New("route not found")
)

// AuthCache caches successful LDAP-backed ingest authorizations.
type AuthCache struct {
	mu       sync.Mutex
	now      func() time.Time
	entries  map[string]authCacheEntry
	inflight map[string]*authCacheCall
	hits     uint64
	misses   uint64
	expired  uint64
}

// AuthCacheStats describes current cache counters and live entry count.
type AuthCacheStats struct {
	Hits    uint64
	Misses  uint64
	Expired uint64
	Entries uint64
}

// BulkDocument is one validated Elasticsearch bulk action/source pair.
type BulkDocument struct {
	Action   string
	Metadata map[string]any
	Document map[string]any
	Line     int
}

type authCacheEntry struct {
	Username  string
	Access    []authz.Access
	ExpiresAt time.Time
}

type authCacheCall struct {
	done  chan struct{}
	entry authCacheEntry
	err   error
}

// NewAuthCache constructs an empty ingest auth cache.
func NewAuthCache() *AuthCache {
	return &AuthCache{
		now:      time.Now,
		entries:  make(map[string]authCacheEntry),
		inflight: make(map[string]*authCacheCall),
	}
}

// SetNow overrides the cache clock, which is primarily useful for tests.
func (c *AuthCache) SetNow(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// AuthCacheKey returns a stable, non-reversible cache key for credentials.
func AuthCacheKey(username, password string) string {
	sum := sha256.Sum256([]byte(username + ":" + password))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Resolve returns cached access for key or fetches, stores, and returns it.
func (c *AuthCache) Resolve(key string, fetch func() (string, []authz.Access, error)) (string, []authz.Access, bool, error) {
	if c == nil {
		username, access, err := fetch()
		return username, authz.CloneAccess(access), false, err
	}

	c.mu.Lock()
	now := c.currentTime()

	if entry, ok := c.entries[key]; ok {
		if !now.After(entry.ExpiresAt) {
			entry.ExpiresAt = now.Add(CacheTTL)
			c.entries[key] = entry
			c.hits++
			username := entry.Username
			access := authz.CloneAccess(entry.Access)
			c.mu.Unlock()
			return username, access, true, nil
		}

		delete(c.entries, key)
		c.expired++
	}

	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-call.done
		if call.err != nil {
			return "", nil, false, call.err
		}
		return call.entry.Username, authz.CloneAccess(call.entry.Access), false, nil
	}

	call := &authCacheCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.misses++
	c.mu.Unlock()

	username, access, err := fetch()

	c.mu.Lock()
	delete(c.inflight, key)
	if err == nil {
		call.entry = authCacheEntry{
			Username:  username,
			Access:    authz.CloneAccess(access),
			ExpiresAt: c.currentTime().Add(CacheTTL),
		}
		c.entries[key] = call.entry
	}
	call.err = err
	close(call.done)
	c.mu.Unlock()

	if err != nil {
		return "", nil, false, err
	}
	return username, authz.CloneAccess(access), false, nil
}

// ForgetUser drops every cached entry whose stored username equals username.
// It is called on logout so a session-terminated user cannot continue ingesting
// via cached Basic-auth credentials. In-flight lookups are not cancelled, but
// their results are not stored if the entry was forgotten in the meantime.
func (c *AuthCache) ForgetUser(username string) {
	if c == nil || username == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if entry.Username == username {
			delete(c.entries, key)
		}
	}
}

// Stats returns the current cache counters and entry count.
func (c *AuthCache) Stats() AuthCacheStats {
	if c == nil {
		return AuthCacheStats{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return AuthCacheStats{
		Hits:    c.hits,
		Misses:  c.misses,
		Expired: c.expired,
		Entries: uint64(len(c.entries)),
	}
}

// ParsePath validates and extracts the index name from /ingest/<index>[/].
func ParsePath(path string) (string, error) {
	if !strings.HasPrefix(path, "/ingest/") {
		return "", ErrRouteNotFound
	}

	indexName := strings.TrimPrefix(path, "/ingest/")
	indexName = strings.TrimSuffix(indexName, "/")
	if indexName == "" {
		return "", errors.New("path must be /ingest/<index>/")
	}
	if strings.Contains(indexName, "/") {
		return "", errors.New("path must be /ingest/<index>/")
	}
	if !ValidIndexName(indexName) {
		return "", errors.New("index name must start with a lowercase letter or digit and contain only lowercase letters, digits, '-' or '_'")
	}
	return indexName, nil
}

// ParseBulkPath validates and extracts the index name from /ingest/<index>/_bulk.
func ParseBulkPath(path string) (string, error) {
	if !strings.HasPrefix(path, "/ingest/") {
		return "", ErrRouteNotFound
	}

	path = strings.TrimSuffix(path, "/")
	if !strings.HasSuffix(path, bulkPathSuffix) {
		return "", ErrRouteNotFound
	}

	indexName := strings.TrimPrefix(path, "/ingest/")
	indexName = strings.TrimSuffix(indexName, bulkPathSuffix)
	if indexName == "" {
		return "", errors.New("path must be /ingest/<index>/_bulk")
	}
	if strings.Contains(indexName, "/") {
		return "", errors.New("path must be /ingest/<index>/_bulk")
	}
	if !ValidIndexName(indexName) {
		return "", errors.New("index name must start with a lowercase letter or digit and contain only lowercase letters, digits, '-' or '_'")
	}
	return indexName, nil
}

// DecodeJSONObject decodes exactly one top-level JSON object from body.
func DecodeJSONObject(body io.Reader) (map[string]any, error) {
	decoder := json.NewDecoder(body)

	var value any
	if err := decoder.Decode(&value); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("request body must be a JSON object")
		}
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("request body must be a JSON object")
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("request body must contain a single JSON object")
		}
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	return object, nil
}

// DecodeBulkNDJSON decodes Elasticsearch-style bulk index/create action pairs.
func DecodeBulkNDJSON(body io.Reader) ([]BulkDocument, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var docs []BulkDocument
	lineNumber := 0
	for {
		actionLine, actionLineNumber, ok, err := nextNonEmptyBulkLine(scanner, &lineNumber)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}

		action, metadata, err := parseBulkActionLine(actionLine)
		if err != nil {
			return nil, finishBulkParseError(scanner, fmt.Errorf("bulk action line %d: %w", actionLineNumber, err))
		}

		sourceLine, sourceLineNumber, ok, err := nextNonEmptyBulkLine(scanner, &lineNumber)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("bulk action line %d has no source document", actionLineNumber)
		}

		document, err := parseBulkSourceLine(sourceLine)
		if err != nil {
			return nil, finishBulkParseError(scanner, fmt.Errorf("bulk source line %d: %w", sourceLineNumber, err))
		}
		docs = append(docs, BulkDocument{
			Action:   action,
			Metadata: metadata,
			Document: document,
			Line:     sourceLineNumber,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read bulk body: %w", err)
	}
	if len(docs) == 0 {
		return nil, errors.New("bulk body must contain at least one action/source pair")
	}
	return docs, nil
}

func finishBulkParseError(scanner *bufio.Scanner, parseErr error) error {
	if err := drainBulkScanner(scanner); err != nil {
		return fmt.Errorf("%w: %w", parseErr, err)
	}
	return parseErr
}

func drainBulkScanner(scanner *bufio.Scanner) error {
	for scanner.Scan() {
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read bulk body: %w", err)
	}
	return nil
}

func nextNonEmptyBulkLine(scanner *bufio.Scanner, lineNumber *int) (string, int, bool, error) {
	for scanner.Scan() {
		*lineNumber++
		if err := scanner.Err(); err != nil {
			return "", 0, false, fmt.Errorf("read bulk body: %w", err)
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		return line, *lineNumber, true, nil
	}
	if err := scanner.Err(); err != nil {
		return "", 0, false, fmt.Errorf("read bulk body: %w", err)
	}
	return "", 0, false, nil
}

func parseBulkActionLine(line string) (string, map[string]any, error) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &value); err != nil {
		return "", nil, fmt.Errorf("invalid action JSON: %w", err)
	}
	if len(value) != 1 {
		return "", nil, errors.New("action must contain exactly one operation")
	}

	for action, rawMetadata := range value {
		if action != "index" && action != "create" {
			return "", nil, fmt.Errorf("unsupported action %q; only index and create are supported", action)
		}

		var metadata map[string]any
		if len(rawMetadata) > 0 && string(rawMetadata) != "null" {
			if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
				return "", nil, fmt.Errorf("invalid action metadata: %w", err)
			}
		}
		if metadata == nil {
			metadata = map[string]any{}
		}
		return action, metadata, nil
	}
	return "", nil, errors.New("action must contain an operation")
}

func parseBulkSourceLine(line string) (map[string]any, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(line), &document); err != nil {
		return nil, fmt.Errorf("invalid source JSON: %w", err)
	}
	if document == nil {
		return nil, errors.New("source document must be a JSON object")
	}
	return document, nil
}

// ParseEventTime validates and parses the required event_time field.
func ParseEventTime(document map[string]any) (time.Time, error) {
	rawValue, ok := document["event_time"]
	if !ok {
		return time.Time{}, errors.New(`missing required field "event_time"`)
	}

	value, ok := rawValue.(string)
	if !ok {
		return time.Time{}, errors.New(`field "event_time" must be a string`)
	}
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New(`field "event_time" must be a UTC RFC3339 timestamp ending in "Z"`)
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New(`field "event_time" must be a valid RFC3339 timestamp`)
	}
	return parsed.UTC(), nil
}

// BuildWriteAlias derives the daily rollover alias for indexName and eventTime.
func BuildWriteAlias(indexName string, eventTime time.Time) string {
	return fmt.Sprintf("%s-%s%s", indexName, eventTime.UTC().Format("20060102"), rolloverSuffix)
}

// BuildFirstBackingIndex returns the initial backing index name for alias.
func BuildFirstBackingIndex(alias string) string {
	return alias + backingIndexSeed
}

// ValidIndexName reports whether indexName is safe for Elasticsearch routing.
func ValidIndexName(indexName string) bool {
	return indexNamePattern.MatchString(indexName)
}

func (c *AuthCache) currentTime() time.Time {
	if c == nil || c.now == nil {
		return time.Now()
	}
	return c.now()
}
