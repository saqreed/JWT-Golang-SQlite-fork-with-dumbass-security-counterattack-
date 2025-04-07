package database

import (
	"database/sql"
	"fmt"
	"log"
	_ "modernc.org/sqlite"
)

func SQLite() *sql.DB {
	db, err := sql.Open("sqlite", "file:sqlite.db")
	if err != nil {
		log.Fatalf(err.Error())
	}

	if err = db.Ping(); err != nil {
		log.Fatalf(fmt.Sprintf("Неактивное подключение: %w", err))
	}

	return db
}
