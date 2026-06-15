package store

import (
	"database/sql"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const databaseURLEnv = "PDP_DATABASE_URL"

type DB struct {
	*sql.DB
}

type Tx struct {
	*sql.Tx
}

func openPostgres(databaseURL string) (*DB, error) {
	raw, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	raw.SetMaxOpenConns(20)
	raw.SetMaxIdleConns(10)
	raw.SetConnMaxLifetime(30 * time.Minute)
	return &DB{DB: raw}, nil
}

func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.DB.Exec(rebindPostgres(query), args...)
}

func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.DB.Query(rebindPostgres(query), args...)
}

func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.DB.QueryRow(rebindPostgres(query), args...)
}

func (db *DB) Begin() (*Tx, error) {
	tx, err := db.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx}, nil
}

func (tx *Tx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.Tx.Exec(rebindPostgres(query), args...)
}

func (tx *Tx) Query(query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.Query(rebindPostgres(query), args...)
}

func (tx *Tx) QueryRow(query string, args ...any) *sql.Row {
	return tx.Tx.QueryRow(rebindPostgres(query), args...)
}

func rebindPostgres(query string) string {
	var out strings.Builder
	out.Grow(len(query) + 8)

	inSingleQuote := false
	inDoubleQuote := false
	position := 1
	for i := 0; i < len(query); i++ {
		ch := query[i]
		switch ch {
		case '\'':
			out.WriteByte(ch)
			if !inDoubleQuote {
				if inSingleQuote && i+1 < len(query) && query[i+1] == '\'' {
					i++
					out.WriteByte(query[i])
				} else {
					inSingleQuote = !inSingleQuote
				}
			}
		case '"':
			out.WriteByte(ch)
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '?':
			if inSingleQuote || inDoubleQuote {
				out.WriteByte(ch)
				continue
			}
			out.WriteByte('$')
			out.WriteString(intString(position))
			position++
		default:
			out.WriteByte(ch)
		}
	}
	return out.String()
}

func intString(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
