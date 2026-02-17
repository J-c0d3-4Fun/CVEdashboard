package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleWare(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	testHandler := PathLogging(handler)

	req, _ := http.NewRequest(http.MethodGet, "/test-path", nil)
	resp := httptest.NewRecorder()

	testHandler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.Code)
	}

	t.Logf("Got a Successful response status: %d OK", resp.Code)
}
