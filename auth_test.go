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
	// TODO: ugly dependency injection
	// needed to make userFromContext work
	Config.Auth.Enable = true

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
	h.HandleFunc("/users", authAdmin(usersHandler(db), "admin", "secret"))
	h.HandleFunc("/", authUser(func(w http.ResponseWriter, r *http.Request) {
		u := userFromContext(r.Context())
		if u == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}, db))

	// create user
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{
		"username": "user",
		"password": "secret",
		"globs": ["*"]
	}`))
	r.SetBasicAuth("admin", "secret")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /users %d, want %d", w.Code, http.StatusOK)
	}

	// test access
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/test-access", nil)
	r.SetBasicAuth("user", "secret")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / %d, want %d", w.Code, http.StatusOK)
	}
}
