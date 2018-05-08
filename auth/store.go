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

// ValidationError returned when model validation fails.
type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}

var (
	ErrInvalidUsername = ValidationError("username length is less than 4")
	ErrInvalidPassword = ValidationError("password length is less than 4")
	ErrInvalidGlobs    = ValidationError("globs is an empty array")
	ErrInvalidGlob     = ValidationError("one of globs is an empty string")
	ErrNotFound        = errors.New("user not found")
)

// Store is users management unit.
type Store struct {
	db   *sql.DB
	salt string

	// prepared statements
	listStmt                      *sql.Stmt
	saveStmt                      *sql.Stmt
	findByUsernameStmt            *sql.Stmt
	findByUsernameAndPasswordStmt *sql.Stmt
	deleteStmt                    *sql.Stmt
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

	s := &Store{db: db, salt: salt}
	if err = s.init(chunks[0]); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// init creates database structure and prepares statements.
// It's not an actual migration process because we just try to
// create tables when they don't exist and we don't keep track
// of changes.
func (s *Store) init(scheme string) error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username VARCHAR(64) NOT NULL PRIMARY KEY,
		password VARCHAR(64) NOT NULL,
		globs    TEXT
	)`)

	if err != nil {
		return err
	}

	s.listStmt, err = s.prep(scheme, "SELECT username, password, globs FROM users")
	if err != nil {
		return err
	}

	var saveSQL string
	if scheme == schemePostgres {
		saveSQL = `
			INSERT INTO users (username, password, globs) VALUES ($1, $2, $3)
			ON CONFLICT (username) DO UPDATE SET password = $2, globs = $3`
	} else {
		saveSQL = "REPLACE INTO users (username, password, globs) VALUES ($1, $2, $3)"
	}

	s.saveStmt, err = s.prep(scheme, saveSQL)
	if err != nil {
		return err
	}

	s.deleteStmt, err = s.prep(scheme, "DELETE FROM users WHERE username = $1")
	if err != nil {
		return err
	}

	s.findByUsernameStmt, err = s.prep(scheme, `
		SELECT username, password, globs
		FROM users
		WHERE username = $1
		LIMIT 1
	`)
	if err != nil {
		return err
	}

	s.findByUsernameAndPasswordStmt, err = s.prep(scheme, `
		SELECT username, password, globs
		FROM users
		WHERE username = $1
		AND password = $2
		LIMIT 1
	`)
	if err != nil {
		return err
	}

	return nil
}

var placeholderRegexp = regexp.MustCompile("\\$\\d+")

// prep prepares a statement and replaces postgres
// placeholders `$n` with `?` when driver is different.
func (s *Store) prep(scheme, query string) (*sql.Stmt, error) {
	if scheme == schemeMySQL || scheme == schemeSQLite {
		query = placeholderRegexp.ReplaceAllString(query, "?")
	}
	return s.db.Prepare(query)
}

// Close closes s connection and all prepared statements.
func (s *Store) Close() error {
	if s.listStmt != nil {
		s.listStmt.Close()
	}
	if s.saveStmt != nil {
		s.saveStmt.Close()
	}
	if s.findByUsernameStmt != nil {
		s.findByUsernameStmt.Close()
	}
	if s.findByUsernameAndPasswordStmt != nil {
		s.findByUsernameAndPasswordStmt.Close()
	}
	if s.deleteStmt != nil {
		s.deleteStmt.Close()
	}
	return s.db.Close()
}

// Clean closes s connection and drops all tables.
func (s *Store) Clean() error {
	if _, err := s.db.Exec("DROP TABLE users"); err != nil {
		return err
	}
	return s.db.Close()
}

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

	// hash password
	password := hash(u.Password, s.salt)
	globs, err := marshalStringSlice(u.Globs)
	if err != nil {
		return err
	}

	_, err = s.saveStmt.ExecContext(ctx, u.Username, password, globs)
	return err
}

// List is list of users.
func (s *Store) List(ctx context.Context) ([]*User, error) {
	rows, err := s.listStmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	uu := make([]*User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		uu = append(uu, u)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return uu, nil
}

// FindByUsername finds user by user name,
// `ErrNotFound` returned when it fails.
func (s *Store) FindByUsername(ctx context.Context, username string) (*User, error) {
	row := s.findByUsernameStmt.QueryRowContext(ctx, username)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		err = ErrNotFound
	}
	return u, err
}

// FindByUsernameAndPassword finds user by username and password,
// `ErrNotFound` returned when it fails.
func (s *Store) FindByUsernameAndPassword(ctx context.Context, username, password string) (*User, error) {
	row := s.findByUsernameAndPasswordStmt.QueryRowContext(ctx, username, hash(password, s.salt))
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		err = ErrNotFound
	}
	return u, err
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanUser(s scanner) (*User, error) {
	var u User
	var b []byte
	if err := s.Scan(&u.Username, &u.Password, &b); err != nil {
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
	_, err := s.deleteStmt.ExecContext(ctx, username)
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
