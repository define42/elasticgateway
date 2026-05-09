package ingest

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeBulkNDJSONDrainsAfterMalformedActionLine(t *testing.T) {
	t.Parallel()

	trailingErr := errors.New("trailing read failed")
	_, err := DecodeBulkNDJSON(&malformedLineThenErrorReader{err: trailingErr})

	if !errors.Is(err, trailingErr) {
		t.Fatalf("expected trailing read error to be surfaced, got %v", err)
	}
	if !strings.Contains(err.Error(), "bulk action line 1") {
		t.Fatalf("expected malformed action context, got %v", err)
	}
}

func TestDecodeBulkNDJSONPreservesMalformedActionLineErrorAfterDrain(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("{bad}\n" +
		"{\"index\":{}}\n" +
		"{\"event_time\":\"2024-12-30T10:11:12Z\"}\n")

	_, err := DecodeBulkNDJSON(body)

	if err == nil || !strings.Contains(err.Error(), "bulk action line 1: invalid action JSON") {
		t.Fatalf("expected malformed action error, got %v", err)
	}
}

func TestDecodeJSONObjectRejectsEmptyAndTrailingInput(t *testing.T) {
	t.Parallel()

	if _, err := DecodeJSONObject(strings.NewReader("")); err == nil || err.Error() != "request body must be a JSON object" {
		t.Fatalf("expected empty-body decode error, got %v", err)
	}

	if _, err := DecodeJSONObject(strings.NewReader(`{} {}`)); err == nil || !strings.Contains(err.Error(), "single JSON object") {
		t.Fatalf("expected trailing-json decode error, got %v", err)
	}
}

type malformedLineThenErrorReader struct {
	read bool
	err  error
}

func (r *malformedLineThenErrorReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, r.err
	}
	r.read = true
	return copy(p, "{bad}\n"), nil
}
