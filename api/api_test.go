package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// First time writing any test using: https://quii.gitbook.io/learn-go-with-tests

// need to find a way to test syncing?

func TestGithubData(t *testing.T) {
	t.Run("Confirming we are receiving Data from Github ", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/github", nil)
		resp := httptest.NewRecorder()

		getVulnsGithub(resp, req)

		var data []any
		err := json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			t.Fatalf("Failed to decode JSON: %v. Body was: %s", err, resp.Body.String())
		}

		t.Logf("Successfully decoded data of type: %T", data)

	})

}

func TestNVDData(t *testing.T) {
	t.Run("Confirming we are receiving Data from NVD ", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/nvd", nil)
		resp := httptest.NewRecorder()

		getVulns(resp, req)

		var data []any
		err := json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			t.Fatalf("Failed to decode JSON: %v. Body was: %s", err, resp.Body.String())
		}
		if resp.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.Code)
		}

		t.Logf("Successfully decoded data of type: %T", data)

	})
}

func TestGithubPath(t *testing.T) {
	t.Run("Confirming Github Path gives a 200 OK", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/github", nil)
		resp := httptest.NewRecorder()

		getVulnsGithub(resp, req)

		if resp.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.Code)
		}
		t.Logf("Successfully got a 200 OK response : %d OK from Github", resp.Code)

	})
}

func TestNVDPath(t *testing.T) {
	t.Run("Confirming Github Path gives a 200 OK", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/nvd", nil)
		resp := httptest.NewRecorder()

		getVulns(resp, req)

		if resp.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.Code)
		}
		t.Logf("Successfully got a 200 OK response : %d OK from NVD", resp.Code)
	})
}

func TestGithubContentType(t *testing.T) {
	t.Run("Confirming we Receive JSON as the Content Type Github", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/github", nil)
		resp := httptest.NewRecorder()

		getVulnsGithub(resp, req)

		want := "application/json"
		if resp.Result().Header.Get("content-type") != want {
			t.Errorf("response did not have content-type of %s, got %v", want, resp.Result().Header)
		}
		t.Logf("Successfully recieve JSON response from Github")
	})
}

func TestNVDContentType(t *testing.T) {
	t.Run("Confirming we Receive JSON as the Content Type from NVD", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/github", nil)
		resp := httptest.NewRecorder()

		getVulns(resp, req)

		want := "application/json"
		if resp.Result().Header.Get("content-type") != want {
			t.Errorf("response did not have content-type of %s, got %v", want, resp.Result().Header)
		}
		t.Logf("Successfully recieve JSON response from NVD")
	})
}
