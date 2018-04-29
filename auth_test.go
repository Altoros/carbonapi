package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-graphite/carbonapi/auth"
)

func TestUsersManagement(t *testing.T) {
	// TODO: ugly dependency injection needed to make userFromContext work
	config.Auth.Enable = true

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "sqlite3://:memory:"
	}

	db, err := auth.Open(databaseURL, "seasalt")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Clean()

	h := http.NewServeMux()
	h.HandleFunc("/users/", authAdmin(usersHandler(db), "admin", "secret"))
	h.HandleFunc("/", authUser(func(w http.ResponseWriter, r *http.Request) {
		u := userFromContext(r.Context())
		if u == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}, db))

	// create user
	testRequest(t, h, "admin", "secret",
		httptest.NewRequest(http.MethodPost, "/users/", strings.NewReader(`{
		"username": "user",
		"password": "1234",
		"globs": ["*"]
	}`)))

	// update user and set right password that we'll use
	testRequest(t, h, "admin", "secret",
		httptest.NewRequest(http.MethodPost, "/users/", strings.NewReader(`{
		"username": "user",
		"password": "secret",
		"globs": ["*"]
	}`)))

	// test the show user action
	testRequest(t, h, "admin", "secret",
		httptest.NewRequest(http.MethodGet, "/users/user", nil))

	// test user access
	testRequest(t, h, "user", "secret",
		httptest.NewRequest(http.MethodGet, "/", nil))

	// test delete user
	testRequest(t, h, "admin", "secret",
		httptest.NewRequest(http.MethodDelete, "/users/user", nil))
}

func testRequest(t *testing.T, h http.Handler, username, password string, r *http.Request) {
	w := httptest.NewRecorder()
	r.SetBasicAuth(username, password)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("%s %s status = %d body = %q, want %d", r.Method, r.URL.Path, w.Code, w.Body.String(), http.StatusOK)
	}
}
