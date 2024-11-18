package apiserver

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/BespalovVV/INKOT0/internal/app/mw"
	"github.com/BespalovVV/INKOT0/internal/app/store/sqlstore"
)

func Start(config *Config) error {
	db, err := newDB(config.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	store := sqlstore.New(db)

	srv := newServer(store, config)

	handler := mw.CorsSettings().Handler(srv.router)

	log.Printf("Starting server on %s", config.BindAddr)
	return http.ListenAndServe(config.BindAddr, handler)
}

func newDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	log.Println("Successfully connected to database")
	return db, nil
}
