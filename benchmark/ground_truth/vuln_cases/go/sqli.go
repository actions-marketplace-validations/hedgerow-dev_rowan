package store

import "database/sql"

func FindUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT id, email FROM users WHERE name = '" + name + "'")
}
