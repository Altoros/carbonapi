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
	"os"
)

// Store is users management unit.
type Store struct {
	db     *sql.DB
	salt   string
	scheme string
}

const (
	schemeMySQL    = "mysql"
	schemePostgres = "postgres"
	schemeSQLite   = "sqlite"
	schemeSQLite3  = "sqlite3"
)

// Open opens the named database url and uses the provided
// salt for passwords hashing.
func Open(databaseURL, salt string) (*Store, error) {
	chunks := strings.Split(databaseURL, "://")
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
		chunks[1] = databaseURL
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
		username VARCHAR(64) NOT NULL PRIMARY KEY,
		password VARCHAR(64) NOT NULL,
		globs    TEXT
	)`)

	if err != nil {
		// close s since we are returning an error here
		db.Close()
		return nil, err
	}

	return &Store{db: db, salt: salt, scheme: chunks[0]}, nil
}

var placeholderRegexp = regexp.MustCompile("\\$\\d+")

// conn is a database interface, `*sql.Store` or `*sql.Tx`
type conn interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

// exec executes a query without returning rows.
func (s *Store) exec(c conn, ctx context.Context, q string, v ...interface{}) (sql.Result, error) {
	return c.ExecContext(ctx, s.prep(q), v...)
}

// query executes a query that returns rows.
func (s *Store) query(c conn, ctx context.Context, q string, v ...interface{}) (*sql.Rows, error) {
	return c.QueryContext(ctx, s.prep(q), v...)
}

// prep replaces postgres placeholders `$n` with `?`,
// needed for multi sql driver support.
func (s *Store) prep(q string) string {
	switch s.scheme {
	case schemeMySQL, schemeSQLite:
		return placeholderRegexp.ReplaceAllString(q, "?")
	default:
		return q
	}
}

// Close closes s connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Clean closes s connection and drops all tables.
func (s *Store) Clean() error {
	if _, err := s.db.Exec("DROP TABLE users"); err != nil {
		return err
	}
	return s.db.Close()
}

// ValidationError returned when model validation fails.
type ValidationError string

// Error is string representation.
func (e ValidationError) Error() string {
	return string(e)
}

var (
	ErrInvalidUsername = ValidationError("username length is less than 4")
	ErrInvalidPassword = ValidationError("password length is less than 4")
	ErrInvalidGlobs    = ValidationError("globs is an empty array")
	ErrInvalidGlob     = ValidationError("one of globs is an empty string")
)

// UserSave creates or updates existing user.
func (s *Store) Save(ctx context.Context, u *User) (err error) {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rErr := tx.Rollback(); rErr != nil {
				fmt.Fprintf(os.Stderr, "tx.Rollback() = %v\n", rErr)
			}
			return
		}
		err = tx.Commit()
	}()

	q := "SELECT 1 FROM users WHERE username = $1"
	if s.scheme != schemeSQLite {
		q += " FOR UPDATE"
	}

	rows, err := s.query(tx, ctx, q, u.Username)
	if err != nil {
		return err
	}
	defer rows.Close()

	// hash password
	u.Password = hash(u.Password, s.salt)

	globs, err := marshalStringSlice(u.Globs)
	if err != nil {
		return err
	}

	if rows.Next() {
		// update existing
		_, err = s.exec(tx, ctx, "UPDATE users SET password = $1, globs = $2 WHERE username = $3",
			u.Password, globs, u.Username)
	} else {
		// create a new record
		_, err = s.exec(tx, ctx, "INSERT INTO users (username, password, globs) VALUES ($1, $2, $3)",
			u.Username, u.Password, globs)
	}
	return err
}

// ErrNotFound returned when user cannot be found.
var ErrNotFound = errors.New("user not found")

// List is list of users.
func (s *Store) List(ctx context.Context) ([]*User, error) {
	rows, err := s.query(s.db, ctx, "SELECT username, password, globs FROM users")
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

// FindByUsername finds user by user name,
// `ErrNotFound` returned when it fails.
func (s *Store) FindByUsername(ctx context.Context, username string) (*User, error) {
	rows, err := s.query(s.db, ctx, `
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

// FindByUsernameAndPassword finds user by username and password,
// `ErrNotFound` returned when it fails.
func (s *Store) FindByUsernameAndPassword(ctx context.Context, username, password string) (*User, error) {
	rows, err := s.query(s.db, ctx, `
		SELECT username, password, globs
		FROM users
		WHERE username = $1
		AND password = $2
		LIMIT 1
	`, username, hash(password, s.salt))

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

// Delete deletes the named user.
func (s *Store) Delete(ctx context.Context, username string) error {
	_, err := s.exec(s.db, ctx, "DELETE FROM users WHERE username = $1", username)
	return err
}

// hash returns base64 encoded hash of the provided string plus salt.
func hash(s, salt string) string {
	h := sha256.New()
	h.Write([]byte(s))
	h.Write([]byte(salt))

	// sha256 is 64 bytes long
	return fmt.Sprintf("%x", h.Sum(nil))
}

// marshalStringSlice dumps a slice of strings into byte encoding.
func marshalStringSlice(ss []string) ([]byte, error) {
	return json.Marshal(&ss)
}

// unmarshalStringSlice converts byte encoding into a slice of strings.
func unmarshalStringSlice(b []byte) ([]string, error) {
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return nil, err
	}
	return ss, nil
}
