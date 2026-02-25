package db

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

// CWE-798: Hardcoded Credentials — database username, password, and host
// are embedded directly in source code instead of read from environment/config.
const (
	dbHost     = "localhost"
	dbPort     = "5432"
	dbUser     = "admin"
	dbPassword = "P@ssw0rd123"
	dbName     = "appdb"
)

var DB *sql.DB

func Init() {
	connStr := "host=" + dbHost +
		" port=" + dbPort +
		" user=" + dbUser +
		" password=" + dbPassword +
		" dbname=" + dbName +
		" sslmode=disable"

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
}
