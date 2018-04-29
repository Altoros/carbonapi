package auth

import "testing"

func TestUser_Can(t *testing.T) {
	t.Parallel()
	testUser(t)
}

func BenchmarkUser_Can(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testUser(b)
	}
}

func testUser(t interface {
	Errorf(string, ...interface{})
}) {
	u := User{Globs: []string{"a.*", "bb", "c.*.c", "z.*.*.z", "y.**", "m**", "n*"}}
	for q, want := range map[string]bool{
		"a.b":       true,
		"a.bc":      true,
		"a.b.c":     false,
		"a":         true,
		"b":         false,
		"bb":        true,
		"bbm":       false,
		"bc":        false,
		"ab":        false,
		"c.bbb":     true,
		"c.c.c":     true,
		"c.c.z":     false,
		"c.c.cc":    false,
		"z.ab.bc.z": true,
		"z.a.b.zz":  false,
		"y.a":       true,
		"y.a.a.b":   true,
		"m":         true,
		"mm":        true,
		"mmmmm":     true,
		"n":         true,
	} {
		got := u.Can(q)
		if got != want {
			t.Errorf("Can(%q) = %t, want %t", q, got, want)
		}
	}
}
