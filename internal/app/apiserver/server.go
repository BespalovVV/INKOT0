package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/context"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	auth "github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/auth"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/auth/token"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/comment"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/friend"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/invite"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/post"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/user"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const (
	authorizationHeader = "Authorization"
)

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
	config *Config
}

func newServer(store store.Store, config *Config) *server {
	s := &server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  store,
		config: config,
	}

	s.configureRouter()

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.Use(s.logRequest)

	handler := auth.NewHandler(s.store, (*auth.Config)(s.config))
	handler.Register(s.router)

	api := s.router.PathPrefix("/api").Subrouter()
	api.Use(s.authenticateUser)

	handlers := []struct {
		handler handlers.Handler
	}{
		{user.NewHandler(s.store)},
		{post.NewHandler(s.store)},
		{comment.NewHandler(s.store)},
		{friend.NewHandler(s.store)},
		{invite.NewHandler(s.store)},
	}

	for _, h := range handlers {
		h.handler.Register(api)
	}
}
func (s *server) authenticateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get(authorizationHeader)
		if header == "" {
			s.Error(w, r, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}

		headerParts := strings.Split(header, " ")
		if len(headerParts) != 2 {
			s.Error(w, r, http.StatusUnauthorized, errors.New("invalid header"))
			return
		}

		userID, err := token.ParseToken(headerParts[1], (*token.Config)(s.config))
		if err != nil {
			s.Error(w, r, http.StatusUnauthorized, err)
			return
		}

		ctx := context.SetUser(r.Context(), userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LOGGER
func (s *server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"method":      r.Method,
			"uri":         r.RequestURI,
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		})
		logger.Infof("Request started")

		start := time.Now()

		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		status := rw.code
		statusText := http.StatusText(status)

		var level logrus.Level
		if status >= 500 {
			level = logrus.ErrorLevel
		} else if status >= 400 {
			level = logrus.WarnLevel
		} else {
			level = logrus.InfoLevel
		}

		logger.WithFields(logrus.Fields{
			"status":      status,
			"status_text": statusText,
			"duration":    duration,
		}).Log(level, "Request completed")
	})
}

func (s *server) Error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.Respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) Respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
