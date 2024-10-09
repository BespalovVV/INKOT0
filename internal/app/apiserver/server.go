package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

const (
	tokenTTL                  = 2 * time.Hour
	signingKey                = "wqigowqieqwe21429832ywqeiuey8239y"
	salt                      = "sdhfkojsdjlkfjsdkeeeeedd"
	autorizationHeader        = "Authorization"
	userCtx                   = "userId"
	ctxkeyUser         ctxkey = iota
	sessionCookieName         = "user-cookie"
)

var (
	errIncorrectEmailOrPassword = errors.New("incorrect email or password")
	errNotAuthenticated         = errors.New("not authenticated")
)

type tokenClaims struct {
	jwt.StandardClaims
	UserId int `json:"user_id"`
}

type server struct {
	router       *mux.Router
	logger       *logrus.Logger
	store        store.Store
	sessionStore sessions.Store
}
type ctxkey int8

func newServer(store store.Store, sessionStore sessions.Store) *server {
	s := &server{
		router:       mux.NewRouter(),
		logger:       logrus.New(),
		store:        store,
		sessionStore: sessionStore,
	}

	s.configureRouter()

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.HandleFunc("/", s.handleHomePage())
	s.router.HandleFunc("/login", s.handleSessionsCreate()).Methods("POST")
	s.router.HandleFunc("/registration", s.handleUsersCreate()).Methods("POST")

	api := s.router.PathPrefix("/api").Subrouter()
	api.Use(s.authenticateUser)
	api.HandleFunc("/whoami", s.handleWhoAmI()).Methods("GET")
	api.HandleFunc("/logout", s.handleSessionDelete()).Methods("POST")
	api.HandleFunc("/posts", s.handlePosts())
	api.HandleFunc("/posts/{id}/comments", s.handleCommentsForPost())
	api.HandleFunc("/posts/{id}", s.handlePostShow())
	api.HandleFunc("/profile/{id}", s.hendleProfileShow())
}

func (s *server) handlePosts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		posts, count, err := s.store.Post().Show()
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		s.respond(w, r, http.StatusOK, posts)
	}
}

func (s *server) handleCommentsForPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/posts/"):(len(r.URL.Path) - len("/comments"))]
		fmt.Print(r.URL.Path)
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, 455, err)
			return
		}
		comments, count, err := s.store.Comment().ShowComments(num)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		s.respond(w, r, http.StatusOK, comments)
	}
}

func (s *server) handlePostShow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/posts/"):]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, 455, err)
			return
		}
		post, err := s.store.Post().Find(num)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, post)
	}
}

func (s *server) handleHomePage() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		templ := template.Must(template.ParseFiles("templates/homepage.html"))
		templ.Execute(w, nil)
		s.respond(w, r, http.StatusOK, nil)
	})
}

func (s *server) hendleProfileShow() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/profile/"):]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		if u, err := s.store.User().Find(num); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			u.Sanitize()
			s.respond(w, r, http.StatusOK, u)
		}
	})
}

func (s *server) authenticateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get(autorizationHeader)
		if header == "" {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}
		headerParts := strings.Split(header, " ")
		if len(headerParts) != 2 {
			s.error(w, r, http.StatusUnauthorized, errors.New("invalid header"))
			return
		}
		UserId, err := s.ParseToken(headerParts[1])
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}
		fmt.Println(UserId)
		ctx := context.WithValue(r.Context(), ctxkeyUser, UserId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *server) ParseToken(accessToken string) (int, error) {
	token, err := jwt.ParseWithClaims(accessToken, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(*tokenClaims)
	if !ok {
		return 0, errors.New("token claims are not of type *tokenClaims")
	}
	return claims.UserId, nil
}

func (s *server) handleUsersCreate() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password,omitempty"`
		Age      int    `json:"age"`
		Name     string `json:"name"`
		Surname  string `json:"surname"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		u := &model.User{
			Name:        req.Name,
			Surname:     req.Surname,
			Email:       req.Email,
			Password:    req.Password,
			Age:         req.Age,
			Description: "",
		}
		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		u.Sanitize()
		s.respond(w, r, http.StatusOK, nil)

	}
}

func (s *server) handleSessionsCreate() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u, err := s.store.User().FindByEmail(req.Email)
		if err != nil || !u.ComparePassword(req.Password) {
			s.error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &tokenClaims{
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(tokenTTL).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
			u.ID,
		})
		tokenr, err := token.SignedString([]byte(signingKey))
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, nil)
			return
		}
		type User struct {
			ID    int
			Token string
		}
		user := User{Token: tokenr, ID: u.ID}
		s.respond(w, r, http.StatusOK, user)
	}
}

func (s *server) handleSessionDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
	}
}

func (s *server) handleWhoAmI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
	}
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, _ *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
