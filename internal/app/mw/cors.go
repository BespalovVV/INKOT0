package mw

import (
	"net/http"

	"github.com/rs/cors"
)

func CorsSettings() *cors.Cors {
	c := cors.New(cors.Options{
		AllowedMethods: []string{
			http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete,
		},
		AllowedOrigins: []string{
			"http://localhost", "http://localhost:3000",
		},
		AllowCredentials: true,
		AllowedHeaders: []string{
			"Content-Type",
			"X-Request-ID",
			"Authorization",
			"X-Total-Count",
		},
		OptionsPassthrough: false,
		ExposedHeaders: []string{
			"Content-Type",
			"X-Total-Count",
		},
		Debug: true,
	})

	return c
}
