package mw

import (
	"net/http"

	"github.com/rs/cors"
)

func CorsSettings() *cors.Cors {

	c := cors.New(cors.Options{
		AllowedMethods: []string{
			http.MethodGet, http.MethodPost,
		},
		AllowedOrigins: []string{
			"http://localhost:3000",
		},
		AllowCredentials: true,
		AllowedHeaders: []string{
			"content-type", "x-request-id", "0", "authorization", "x-total-count",
		},
		OptionsPassthrough: false,
		ExposedHeaders: []string{
			"content-type",
		},
		Debug: true,
	})
	return c
}
