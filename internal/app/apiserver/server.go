package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/context"
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
	authorizationHeader        = "Authorization"
	tokenTTL                   = 2 * time.Hour
	ctxkeyUser          ctxkey = iota
	signingKey                 = "wqigowqieqwe21429832ywqeiuey8239y"
	salt                       = "sdhfkojsdjlkfjsdkeeeeedd"
	userCtx                    = "userId"
	usersURL                   = "/users"
	userURL                    = "/users/{id}"
)

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
}
type ctxkey int8

func newServer(store store.Store) *server {
	s := &server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  store,
	}

	s.configureRouter()

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.Use(s.logRequest)
	// AUTH
	handler := auth.NewHandler(s.store)
	handler.Register(s.router)

	api := s.router.PathPrefix("/api").Subrouter()
	api.Use(s.authenticateUser)
	// юзер сервис
	handler = user.NewHandler(s.store)
	handler.Register(api)
	// сервис постов
	handler = post.NewHandler(s.store)
	handler.Register(api)
	// сервис комментариев
	handler = comment.NewHandler(s.store)
	handler.Register(api)
	// сервис друзей
	handler = friend.NewHandler(s.store)
	handler.Register(api)
	// сервис запросов
	handler = invite.NewHandler(s.store)
	handler.Register(api)
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

		userID, err := token.ParseToken(headerParts[1])
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
			"remote_addr": r.RemoteAddr,
		})
		logger.Infof("started %s %s", r.Method, r.RequestURI)

		start := time.Now()
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		var level logrus.Level
		switch {
		case rw.code >= 500:
			level = logrus.ErrorLevel
		case rw.code >= 400:
			level = logrus.WarnLevel
		default:
			level = logrus.InfoLevel
		}
		logger.Logf(
			level,
			"completed with %d %s in %v",
			rw.code,
			http.StatusText(rw.code),
			time.Since(start),
		)
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
