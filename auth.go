package main

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
		for i := 0; i < len(s) && i < len(g); i++ {
			if g[i] == '*' {
				return true
			}

			if g[i] != s[i] {
				break
			}

			if i == len(s)-1 && i == len(g)-1 {
				return true
			}
		}
	}
	return false
}

type DB struct {
	*sql.DB

	salt   string
	scheme string
}

func Open(url, salt string) (*DB, error) {
	chunks := strings.Split(url, "://")
	if len(chunks) != 2 {
		return nil, errors.New("malformed database url")
	}

	switch chunks[0] {
	case "mysql":
	case "postgres":
	case "sqlite3":
	default:
		return nil, fmt.Errorf("%q scheme is not supported", chunks[0])
	}

	switch chunks[0] {
	case "postgres":
		chunks[1] = url
	}

	db, err := sql.Open(chunks[0], chunks[1])
	if err != nil {
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

// placeholderRegexp looks for postgres $ placeholders
var placeholderRegexp = regexp.MustCompile("\\$\\d+")

// exec executes a query without returning rows
func (db *DB) exec(ctx context.Context, tx *sql.Tx, q string, v ...interface{}) (sql.Result, error) {
	if tx == nil {
		return db.ExecContext(ctx, db.prep(q), v...)
	}
	return tx.ExecContext(ctx, db.prep(q), v...)
}

// query executes a query that returns rows
func (db *DB) query(ctx context.Context, tx *sql.Tx, q string, v ...interface{}) (*sql.Rows, error) {
	if tx == nil {
		return db.QueryContext(ctx, db.prep(q), v...)
	}
	return tx.QueryContext(ctx, db.prep(q), v...)
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
	if err := db.Close(); err != nil {
		return err
	}
	_, err := db.Exec("DROP TABLE users")
	return err
}

// UserSave creates or updates existing user
func (db *DB) Save(ctx context.Context, u *User) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
		err = tx.Commit()
	}()

	rows, err := db.query(ctx, tx, `SELECT 1 FROM users WHERE username = $1`, u.Username)
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

	// update existing user if it exists
	if rows.Next() {
		_, err = db.exec(ctx, tx, `UPDATE users SET password = $1, globs = $2 WHERE username = $3`,
			u.Password, globs, u.Username)
		return err
	}

	// create a new record
	_, err = db.exec(ctx, tx, `INSERT INTO users (username, password, globs) VALUES ($1, $2, $3)`,
		u.Username, u.Password, globs)
	return err
}

// ErrNotFound returned when user cannot be found
var ErrNotFound = errors.New("user not found")

// List is list of users
func (db DB) List(ctx context.Context) ([]*User, error) {
	rows, err := db.query(ctx, nil, `
		SELECT username, password, globs
		FROM users`)

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
	rows, err := db.query(ctx, nil, `
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
	rows, err := db.query(ctx, nil, `
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
	_, err := db.exec(ctx, nil, `DELETE FROM users WHERE username = $1`, username)
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
