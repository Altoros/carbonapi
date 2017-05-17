package main

import (
	"context"
	"os"
	"testing"
)

func TestUser_Can(t *testing.T) {
	t.Parallel()

	u := User{Globs: []string{"a.*", "b", "c.*.c", "z.*.*.z", "y.**"}}
	for q, want := range map[string]bool{
		"a.b":       true,
		"a.bc":      true,
		"a.b.c":     false,
		"a":         false,
		"b":         true,
		"bc":        false,
		"ab":        false,
		"c.c.c":     true,
		"c.c.z":     false,
		"c.c.cc":    false,
		"z.ab.bc.z": true,
		"z.a.b.zz":  false,
		"y.a":       true,
		"y.a.a.b":   true,
	} {
		got := u.Can(q)
		if got != want {
			t.Errorf("Can(%q) = %t, want %t", q, got, want)
		}
	}
}

func TestDB(t *testing.T) {
	u := &User{
		Username: "user",
		Password: "secret",
		Globs:    []string{"foo.*"},
	}

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "sqlite3://:memory:"
	}

	db, err := Open(databaseURL, "seasalt")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Clean()

	if err = db.Save(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	u2, err := db.FindByUsernameAndPassword(context.Background(), "user", "secret")
	if err != nil {
		t.Fatal(err)
	}

	if u.Username != u2.Username &&
		u.Password != u2.Password &&
		len(u.Globs) != len(u2.Globs) {
		t.Error("users are not equal")
	}

	if err = db.Delete(context.Background(), "user"); err != nil {
		t.Fatal(err)
	}

	_, err = db.FindByUsernameAndPassword(context.Background(), "user", "secret")
	if err != ErrNotFound {
		t.Errorf("err = %v, want %v", err, ErrNotFound)
	}
}
