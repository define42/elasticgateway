package elastic

import (
	"errors"
	"net/http"
	"testing"
)

func TestIsRetryableBootstrapConflict(t *testing.T) {
	t.Parallel()

	if !IsRetryableBootstrapConflict(&ResponseError{StatusCode: http.StatusBadRequest, Body: `{"error":{"type":"resource_already_exists_exception"}}`}) {
		t.Fatal("expected 400 resource_already_exists_exception to be retryable")
	}
	if IsRetryableBootstrapConflict(errors.New("plain error")) {
		t.Fatal("expected plain error not to be retryable")
	}
}
