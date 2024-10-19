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

	auth "github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/auth"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/user"
	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
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
	postURL                   = "/post/:id"
	postsURL                  = "/posts"
)

var (
	errNotAuthenticated = errors.New("not authenticated")
)

type tokenClaims struct {
	jwt.StandardClaims
	UserId int `json:"user_id"`
}

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
	s.router.HandleFunc("/", s.handleHomePage())
	// AUTH
	handler := auth.NewHandler(s.store)
	handler.Register(s.router)

	api := s.router.PathPrefix("/api").Subrouter()
	api.Use(s.authenticateUser)
	// юзер сервис
	handler = user.NewHandler(s.store)
	handler.Register(api)
	api.HandleFunc("/users/notfriends", s.handleUsersNotFriends()).Methods("GET")
	api.HandleFunc("/users/friends", s.handleUsersFriends()).Methods("GET")
	api.HandleFunc("/users/invite", s.handleUsersInvite()).Methods("POST")
	api.HandleFunc("/users/friends/accept", s.handleUsersFriendAccept()).Methods("POST")
	api.HandleFunc("/users/invite/delete", s.handleUsersInviteDelete()).Methods("POST")
	api.HandleFunc("/users/invite", s.handleUsersInvitesShow()).Methods("GET")
	// сервис постов
	api.HandleFunc("/posts", s.handlePosts()).Methods("GET")
	api.HandleFunc("/posts", s.handlePostsCreate()).Methods("POST")
	api.HandleFunc("/posts/::id", s.handlePostShow())
	api.HandleFunc("/whoami", s.handleWhoAmI()).Methods("GET")
	api.HandleFunc("/posts/{id}/comments", s.handleCommentsForPost())
	api.HandleFunc("/profile/{id}/posts", s.handleProfilePostsShow()).Methods("GET")
	api.HandleFunc("/logout", s.handleSessionDelete()).Methods("POST")
	// сервис друзей
	// сервис запросов
	// other routes
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

// AUTH
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
		ctx := context.WithValue(r.Context(), ctxkeyUser, UserId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// token
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

// reuse
func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, _ *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// USER SERVISE

func (s *server) handleUsersInvitesShow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		invites, count, err := s.store.User().ShowInvites(p)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		s.respond(w, r, http.StatusOK, invites)
	}
}
func (s *server) handleUsersInvite() http.HandlerFunc {
	type request struct {
		To_user_id int `json:"to_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		err := s.store.User().SendInvite(p, req.To_user_id)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusCreated, nil)
	}
}
func (s *server) handleUsersInviteDelete() http.HandlerFunc {
	type request struct {
		Front_user_id int `json:"front_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		err := s.store.User().DeleteInvite(p, req.Front_user_id)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) handleUsersFriendAccept() http.HandlerFunc {
	type request struct {
		From_user_id int `json:"from_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		err := s.store.User().AddFriend(p, req.From_user_id)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusCreated, nil)
	}
}

func (s *server) handlePosts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		posts, count, err := s.store.Post().Show(p)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		s.respond(w, r, http.StatusOK, posts)
	}
}

func (s *server) handleUsersFriends() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		users, count, err := s.store.User().ShowFriends(p)
		if err != nil || users == nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		s.respond(w, r, http.StatusOK, users)
	}
}

func (s *server) handleUsersNotFriends() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		users, count, err := s.store.User().ShowUsers(p)
		if err != nil || users == nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		s.respond(w, r, http.StatusOK, users)
	}
}

func (s *server) handleProfilePostsShow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/profile/"):(len(r.URL.Path) - len("/posts"))]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, 455, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		posts, count, err := s.store.Post().FindByOwnerIdPublic(num)
		if err != nil || posts == nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if r.Context().Value(ctxkeyUser) != num || s.store.User().IsFriend(num, p) {
			posts, count, err = s.store.Post().FindByOwnerId(num)
			if err != nil || posts == nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
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

func (s *server) handlePostsCreate() http.HandlerFunc {
	type request struct {
		Title     string `json:"title"`
		Body      string `json:"body"`
		IsPrivate bool   `json:"isprivate"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p0 := c.(int)
		p := &model.Post{
			Owner_id:  p0,
			Title:     req.Title,
			Body:      req.Body,
			IsPrivate: req.IsPrivate,
		}
		if err := s.store.Post().Create(p); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, nil)
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
