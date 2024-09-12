package main

import (
	"log"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver"
)

func main() {
	s := apiserver.New()
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}

}
