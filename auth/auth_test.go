package auth

import (
	"context"
	"os"
	"testing"
)

func TestUser_Can(t *testing.T) {
	t.Parallel()
	testUser(t)
}

func BenchmarkUser_Can(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testUser(b)
	}
}

func testUser(t interface{Errorf(string, ...interface{})}) {
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

func TestDB_All(t *testing.T) {
	for name, key := range map[string]string{
		"sqlite": "TEST_SQLITE_DATABASE_URL",
		"mysql":  "TEST_MYSQL_DATABASE_URL",
		"pgsql":  "TEST_PGSQL_DATABASE_URL",
	} {
		t.Run(name, func(t *testing.T) {
			u := &User{
				Username: "user",
				Password: "secret",
				Globs:    []string{"foo.*"},
			}

			databaseURL := os.Getenv(key)
			if databaseURL == "" {
				t.Skipf(`os.Getenv(%q) = ""`, key)
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

			if !usersAreEqual(u, u2) {
				t.Error("FindByUsernameAndPassword: users are not equal")
			}

			u2, err = db.FindByUsername(context.Background(), "user")
			if err != nil {
				t.Fatal(err)
			}

			if !usersAreEqual(u, u2) {
				t.Fatal("FindByUsername: users are not equal")
			}

			if err = db.Delete(context.Background(), "user"); err != nil {
				t.Fatal(err)
			}

			_, err = db.FindByUsernameAndPassword(context.Background(), "user", "secret")
			if err != ErrNotFound {
				t.Errorf("FindByUsernameAndPassword: err = %v, want %v", err, ErrNotFound)
			}
		})
	}
}

func usersAreEqual(u1, u2 *User) bool {
	if u1.Username != u2.Username || len(u1.Globs) != len(u2.Globs) {
		return false
	}
	for i := 0; i < len(u1.Globs); i++ {
		if u1.Globs[i] != u2.Globs[i] {
			return false
		}
	}
	return true
}
