package auth

// User is user entity representation.
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password,omitempty"`
	Globs    []string `json:"globs"`
}

// Can returns true when s matches at least one of user's globs.
// See README.md for documentation and examples.
func (u *User) Can(s string) bool {
	for _, g := range u.Globs {
		for i, j := 0, 0; ; i++ {
			// enter wildcard
			if g[j] == '*' {
				// next symbol is * as well
				if len(g) > j+1 && g[j+1] == '*' {
					return true
				}

				// end of s is reached
				if len(s) == i+1 {
					return true
				}

				// everything except . matches *
				if s[i] != '.' {
					continue
				}

				// end of g is reached
				if len(g) == j+1 {
					break
				}

				// end of *
				j++
			}

			// compare bytes
			if s[i] != g[j] {
				break
			}

			// last s and g positions
			if len(s) == i+1 && len(g) == j+1 {
				return true
			}

			// end of g is reached
			if len(g) == j+1 {
				break
			}

			// end of s is reached
			if len(s) == i+1 {
				// next g symbol is `.` or `*`, so:
				// glob `abc.*` matches `abc` only, not `a` or `ab`
				return g[j+1] == '.' || g[j+1] == '*'
			}

			j++
		}
	}
	return false
}
