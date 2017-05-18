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

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// User is user entity representation
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password,omitempty"`
	Globs    []string `json:"globs"`
}

// Can returns true when s matches at least one of user's globs
func (u *User) Can(s string) bool {
	for _, g := range u.Globs {
		for i, j := 0, 0; i < len(s); i++ {
			// enter wildcard
			if g[j] == '*' {
				// next symbol is * as well
				if len(g)-1 > j && g[j+1] == '*' {
					return true
				}

				// end of s reached
				if len(s)-1 == i {
					return true
				}

				// everything except . matches *
				if s[i] != '.' {
					continue
				}

				// end of g is reached
				if len(g)-1 == j {
					break
				}

				// end of *
				j++
			}

			// compare bytes
			if s[i] != g[j] {
				break
			}

			// last s and g position
			if len(s)-1 == i && len(g)-1 == j {
				return true
			}

			// end of g reached
			if len(g)-1 == j {
				break
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
	schemeSQLite   = "sqlite3"
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
	default:
		return nil, fmt.Errorf("%q scheme is not supported", chunks[0])
	}

	switch chunks[0] {
	case schemePostgres:
		chunks[1] = url
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

// exec executes a query without returning rows
func (db *DB) exec(ctx context.Context, q string, v ...interface{}) (sql.Result, error) {
	return db.ExecContext(ctx, db.prep(q), v...)
}

// query executes a query that returns rows
func (db *DB) query(ctx context.Context, q string, v ...interface{}) (*sql.Rows, error) {
	return db.QueryContext(ctx, db.prep(q), v...)
}

// prep is needed for mysql compatibility
// it replaces postgres $ placeholders with ?
func (db *DB) prep(q string) string {
	switch db.scheme {
	case "mysql", "sqlite3":
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
	errInvalidUsername = ValidationError("username is too short, len < 4")
	errInvalidPassword = ValidationError("password is too short, len < 4")
	errInvalidGlobs    = ValidationError("globs cannot be empty, len = 0")
	errInvalidGlob     = ValidationError("glob cannot be an empty string")
)

// UserSave creates or updates existing user
func (db *DB) Save(ctx context.Context, u *User) (error) {
	if len(u.Username) < 4 {
		return errInvalidUsername
	} else if len(u.Password) < 4 {
		return errInvalidPassword
	} else if len(u.Globs) == 0 {
		return errInvalidGlobs
	}

	for _, g := range u.Globs {
		if g == "" {
			return errInvalidGlob
		}
	}

	q := "SELECT 1 FROM users WHERE username = $1"
	if db.scheme != schemeSQLite {
		q += " FOR UPDATE"
	}

	rows, err := db.query(ctx, q, u.Username)
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
		_, err = db.exec(ctx, "UPDATE users SET password = $1, globs = $2 WHERE username = $3",
			u.Password, globs, u.Username)
	} else {
		// create a new record
		_, err = db.exec(ctx, "INSERT INTO users (username, password, globs) VALUES ($1, $2, $3)",
			u.Username, u.Password, globs)
	}
	return err
}

// ErrNotFound returned when user cannot be found
var ErrNotFound = errors.New("user not found")

// List is list of users
func (db DB) List(ctx context.Context) ([]*User, error) {
	rows, err := db.query(ctx, "SELECT username, password, globs FROM users")
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
	rows, err := db.query(ctx, `
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
	rows, err := db.query(ctx, `
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
	_, err := db.exec(ctx, "DELETE FROM users WHERE username = $1", username)
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