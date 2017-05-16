package main

import (
	"context"
	"os"
	"testing"
)

func TestUser_Can(t *testing.T) {
	t.Parallel()

	u := User{Globs: []string{"foo.*", "baz.*", "bam"}}
	for q, want := range map[string]bool{
		"*":       false,
		"bar.*":   false,
		"foo.*":   true,
		"foo.bar": true,
		"foo":     false,
		"baz.a":   true,
		"bam":     true,
		"bam1":    false,
		"ba":      false,
	} {
		if u.Can(q) != want {
			t.Errorf("Can(%q) = %t, want %t", q, u.Can(q), want)
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
