package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	_ "github.com/cznic/sqlite"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// User is user entity representation
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password,omitempty"`
	Globs    []string `json:"globs"`
}

// Can returns true when s matches at least one of user's globs.
//
// Glob syntax:
// *  matches everything except .
// ** matches everything
func (u *User) Can(s string) bool {
	for _, g := range u.Globs {
		for i, j := 0, 0;; i++ {
			// enter wildcard
			if g[j] == '*' {
				// next symbol is * as well
				if len(g) > j+1 && g[j+1] == '*' {
					return true
				}

				// end of is reached
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
				// rest of g are *
				r := g[j+1:]
				if len(r) > 0 {
					for _, c := range r {
						if c != '*' {
							return false
						}
					}
					return true
				}
				return false
			}

			j++
		}
	}
	return false
}

type DB struct {
	*sql.DB

	salt   string
	scheme string
}

const (
	schemeMySQL    = "mysql"
	schemePostgres = "postgres"
	schemeSQLite   = "sqlite"
	schemeSQLite3  = "sqlite3"
)

func Open(url, salt string) (*DB, error) {
	chunks := strings.Split(url, "://")
	if len(chunks) != 2 {
		return nil, errors.New("malformed database url")
	}

	switch chunks[0] {
	case schemeMySQL:
	case schemePostgres:
	case schemeSQLite:
	case schemeSQLite3:
	default:
		return nil, fmt.Errorf("%q scheme is not supported", chunks[0])
	}

	switch chunks[0] {
	case schemePostgres:
		chunks[1] = url
	case schemeSQLite3:
		chunks[0] = schemeSQLite
	}

	db, err := sql.Open(chunks[0], chunks[1])
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	// create tables
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username VARCHAR(32) NOT NULL PRIMARY KEY,
		password VARCHAR(32) NOT NULL,
		globs    TEXT
	)`)

	if err != nil {
		// close db since we are returning an error here
		db.Close()
		return nil, err
	}

	return &DB{DB: db, salt: salt, scheme: chunks[0]}, nil
}

var placeholderRegexp = regexp.MustCompile("\\$\\d+")

// DB or Tx
type conn interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

// exec executes a query without returning rows
func (db *DB) exec(c conn, ctx context.Context, q string, v ...interface{}) (sql.Result, error) {
	return c.ExecContext(ctx, db.prep(q), v...)
}

// query executes a query that returns rows
func (db *DB) query(c conn, ctx context.Context, q string, v ...interface{}) (*sql.Rows, error) {
	return c.QueryContext(ctx, db.prep(q), v...)
}

// prep is needed for mysql compatibility
// it replaces postgres $ placeholders with ?
func (db *DB) prep(q string) string {
	switch db.scheme {
	case schemeMySQL, schemeSQLite:
		return placeholderRegexp.ReplaceAllString(q, "?")
	default:
		return q
	}
}

// Clean closes db connection and drops all tables
func (db *DB) Clean() error {
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		return err
	}
	return db.Close()
}

// ValidationError returned when model validation fails.
type ValidationError string

// Error is string representation.
func (e ValidationError) Error() string {
	return string(e)
}

var (
	ErrInvalidUsername = ValidationError("username is too short, len < 4")
	ErrInvalidPassword = ValidationError("password is too short, len < 4")
	ErrInvalidGlobs    = ValidationError("globs cannot be empty, len = 0")
	ErrInvalidGlob     = ValidationError("glob cannot be an empty string")
)

// UserSave creates or updates existing user
func (db *DB) Save(ctx context.Context, u *User) (err error) {
	if len(u.Username) < 4 {
		return ErrInvalidUsername
	} else if len(u.Password) < 4 {
		return ErrInvalidPassword
	} else if len(u.Globs) == 0 {
		return ErrInvalidGlobs
	}

	for _, g := range u.Globs {
		if g == "" {
			return ErrInvalidGlob
		}
	}

	// we need to use transactions here to make sure that
	// query and exec are using the same underlying connection.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = tx.Rollback()
		}
	}()

	q := "SELECT 1 FROM users WHERE username = $1"
	if db.scheme != schemeSQLite {
		q += " FOR UPDATE"
	}

	rows, err := db.query(tx, ctx, q, u.Username)
	if err != nil {
		return err
	}
	defer rows.Close()

	// hash password
	u.Password = hash(u.Password, db.salt)

	globs, err := marshalStringSlice(u.Globs)
	if err != nil {
		return err
	}

	if rows.Next() {
		// update existing
		_, err = db.exec(tx, ctx, "UPDATE users SET password = $1, globs = $2 WHERE username = $3",
			u.Password, globs, u.Username)
	} else {
		// create a new record
		_, err = db.exec(tx, ctx, "INSERT INTO users (username, password, globs) VALUES ($1, $2, $3)",
			u.Username, u.Password, globs)
	}

	if err != nil {
		return err
	}
	return tx.Commit()
}

// ErrNotFound returned when user cannot be found
var ErrNotFound = errors.New("user not found")

// List is list of users
func (db DB) List(ctx context.Context) ([]*User, error) {
	rows, err := db.query(db, ctx, "SELECT username, password, globs FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	uu := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		uu = append(uu, u)
	}
	return uu, nil
}

// FindByUsername finds user by user name or returns ErrNotFound
func (db DB) FindByUsername(ctx context.Context, username string) (*User, error) {
	rows, err := db.query(db, ctx, `
		SELECT username, password, globs
		FROM users
		WHERE username = $1
		LIMIT 1
	`, username)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, ErrNotFound
	}
	return scanUser(rows)
}

// FindByUsernameAndPassword
func (db *DB) FindByUsernameAndPassword(ctx context.Context, username, password string) (*User, error) {
	rows, err := db.query(db, ctx, `
		SELECT username, password, globs
		FROM users
		WHERE username = $1
		AND password = $2
		LIMIT 1
	`, username, hash(password, db.salt))

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, ErrNotFound
	}
	return scanUser(rows)
}

func scanUser(rows *sql.Rows) (*User, error) {
	var u User
	var b []byte
	if err := rows.Scan(&u.Username, &u.Password, &b); err != nil {
		return nil, err
	}

	globs, err := unmarshalStringSlice(b)
	if err != nil {
		return nil, err
	}
	u.Globs = globs
	u.Password = "" // hide password hash

	return &u, nil
}

// UserDelete deletes the named user
func (db *DB) Delete(ctx context.Context, username string) error {
	_, err := db.exec(db, ctx, "DELETE FROM users WHERE username = $1", username)
	return err
}

// hash returns base64 encoded hash of the provided string plus salt
func hash(s, salt string) string {
	h := sha256.New()
	h.Write([]byte(s))
	h.Write([]byte(salt))

	// base16 is 64 bytes long we need only 32
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

// marshalStringSlice dumps a slice of strings into byte encoding
func marshalStringSlice(ss []string) ([]byte, error) {
	return json.Marshal(&ss)
}

// unmarshalStringSlice converts byte encoding into a slice of strings
func unmarshalStringSlice(b []byte) ([]string, error) {
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return nil, err
	}
	return ss, nil
}
