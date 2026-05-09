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

func TestDecodeBulkNDJSONRejectsMalformedBodies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty body",
			body: "",
			want: "bulk body must contain at least one action/source pair",
		},
		{
			name: "blank only body",
			body: "\n \n\t\n",
			want: "bulk body must contain at least one action/source pair",
		},
		{
			name: "action without source",
			body: "{\"index\":{}}\n\n",
			want: "bulk action line 1 has no source document",
		},
		{
			name: "unsupported action",
			body: "{\"delete\":{}}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			want: `bulk action line 1: unsupported action "delete"; only index and create are supported`,
		},
		{
			name: "multiple actions",
			body: "{\"index\":{},\"create\":{}}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			want: "bulk action line 1: action must contain exactly one operation",
		},
		{
			name: "invalid action metadata",
			body: "{\"index\":\"not metadata\"}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			want: "bulk action line 1: invalid action metadata",
		},
		{
			name: "invalid source json",
			body: "{\"index\":{}}\n{bad}\n",
			want: "bulk source line 2: invalid source JSON",
		},
		{
			name: "null source document",
			body: "{\"index\":{}}\nnull\n",
			want: "bulk source line 2: source document must be a JSON object",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeBulkNDJSON(strings.NewReader(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestDecodeBulkNDJSONDrainsAfterMalformedSourceLine(t *testing.T) {
	t.Parallel()

	trailingErr := errors.New("trailing read failed")
	_, err := DecodeBulkNDJSON(&malformedSourceThenErrorReader{err: trailingErr})

	if !errors.Is(err, trailingErr) {
		t.Fatalf("expected trailing read error to be surfaced, got %v", err)
	}
	if !strings.Contains(err.Error(), "bulk source line 2") {
		t.Fatalf("expected malformed source context, got %v", err)
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

type malformedSourceThenErrorReader struct {
	read bool
	err  error
}

func (r *malformedSourceThenErrorReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, r.err
	}
	r.read = true
	return copy(p, "{\"index\":{}}\n{bad}\n"), nil
}
