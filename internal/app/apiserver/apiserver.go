package apiserver

import (
	"database/sql"
	"net/http"

	"github.com/BespalovVV/INKOT0/internal/app/mw"
	"github.com/BespalovVV/INKOT0/internal/app/store/sqlstore"
)

func Start(config *Config) error {
	db, err := newDB(config.DatabaseURL)
	if err != nil {
		return err
	}

	defer db.Close()

	store := sqlstore.New(db)
	srv := newServer(store)
	handler := mw.CorsSettings().Handler(srv.router)

	return http.ListenAndServe(config.BindAddr, handler)
}

func newDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
