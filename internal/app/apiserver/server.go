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
	usersURL                  = "/users"
	userURL                   = "/users/{id}"
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
	s.router.HandleFunc("/", s.HomePage())
	// AUTH
	handler := auth.NewHandler(s.store)
	handler.Register(s.router)

	api := s.router.PathPrefix("/api").Subrouter()
	api.Use(s.authenticateUser)
	// юзер сервис
	handler = user.NewHandler(s.store)
	handler.Register(api)
	api.HandleFunc(userURL, s.PatchUser()).Methods(http.MethodPatch)

	// сервис постов
	api.HandleFunc("/posts", s.Posts()).Methods(http.MethodGet)
	api.HandleFunc("/posts", s.PostCreate()).Methods(http.MethodPost)
	api.HandleFunc("/posts/{id}", s.Post()).Methods(http.MethodGet)
	api.HandleFunc("/posts/{id}", s.PostDelete()).Methods(http.MethodDelete)
	api.HandleFunc("/posts/{id}", s.PostPatch()).Methods(http.MethodPatch)
	api.HandleFunc("/posts/{id}/comments", s.CommentsForPost()).Methods(http.MethodGet)
	api.HandleFunc("/comments/{id}", s.CommentDelete()).Methods(http.MethodDelete)
	api.HandleFunc("/comments/{id}", s.CommentPatch()).Methods(http.MethodPatch)
	api.HandleFunc("/users/{id}/posts", s.UserPostsShow()).Methods(http.MethodGet)
	// сервис друзей
	api.HandleFunc("/users/notfriends", s.UsersNotFriends()).Methods(http.MethodGet)
	api.HandleFunc("/users/friends", s.UserFriends()).Methods(http.MethodGet)
	api.HandleFunc("/friends/{id}", s.UserFriendDelete()).Methods(http.MethodDelete)
	// сервис запросов
	api.HandleFunc("/users/invite", s.UserInvitesShow()).Methods(http.MethodGet)
	api.HandleFunc("/users/invite", s.CreateUserInvite()).Methods(http.MethodPost)
	api.HandleFunc("/users/invite/{id}", s.UserInviteAccept()).Methods(http.MethodPost)
	api.HandleFunc("/users/invite/{id}", s.UserInviteDelete()).Methods(http.MethodDelete)
	// other routes
	api.HandleFunc("/logout", s.SessionDelete()).Methods(http.MethodPost)
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
func (s *server) PatchUser() http.HandlerFunc {
	type request struct {
		Email       string `json:"email,omitempty"`
		Password    string `json:"password,omitempty"`
		Age         int    `json:"age,omitempty"`
		Name        string `json:"name,omitempty"`
		Surname     string `json:"surname,omitempty"`
		Description string `json:"description,omitempty"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		p := 0
		c := r.Context().Value(ctxkeyUser)
		if c == nil {
			s.error(w, r, 455, errNotAuthenticated)
			return
		} else {
			p = c.(int)
		}
		if p != num || p == 0 {
			s.error(w, r, 455, errNotAuthenticated)
			return
		}
		user, err := s.store.User().Find(p)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if req.Age != user.Age && req.Age != 0 {
			user.Age = req.Age
		}
		if req.Email != user.Email && req.Email != "" {
			user.Email = req.Email
		}
		if !user.ComparePassword(req.Password) && req.Password != "" {
			err = user.BeforeCreate()
			if err != nil {
				s.error(w, r, http.StatusBadRequest, err)
				return
			}
		} else {
			fmt.Print("HFIOSDOFJODJJSJDPJSLK")
		}
		if req.Name != user.Name && req.Name != "" {
			user.Name = req.Name
		}
		if req.Surname != user.Surname && req.Surname != "" {
			user.Surname = req.Surname
		}
		if req.Description != user.Description && req.Description != "" {
			user.Description = req.Description
		}
		if user1, err := s.store.User().PatchUser(p, user); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			s.respond(w, r, http.StatusOK, user1)
		}
	})
}

// postservise
// create post
func (s *server) PostCreate() http.HandlerFunc {
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
func (s *server) PostDelete() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p0 := c.(int)
		p, err := s.store.Post().Find(num)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if p0 != p.Owner_id {
			s.error(w, r, 455, errNotAuthenticated)
			return
		}
		if err := s.store.Post().Delete(num); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, nil)
	}
}
func (s *server) PostPatch() http.HandlerFunc {
	type request struct {
		Title     string `json:"title,omitempty"`
		Body      string `json:"body,omitempty"`
		IsPrivate bool   `json:"isprivate,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p0 := c.(int)
		p, err := s.store.Post().Find(num)
		if err != nil {
			s.error(w, r, 455, errNotAuthenticated)
			return
		}
		if p.Owner_id != p0 {
			s.error(w, r, 455, errNotAuthenticated)
			return
		}
		if p.Title != req.Title && req.Title != "" {
			p.Title = req.Title
		}
		if p.Body != req.Body && req.Body != "" {
			p.Body = req.Body
		}
		if req.IsPrivate {
			p.IsPrivate = !p.IsPrivate
		}
		if err := s.store.Post().Update(p.ID, p); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, nil)
	}
}

// show all posts
func (s *server) Posts() http.HandlerFunc {
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

// showonepost
func (s *server) Post() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
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

// users posts
func (s *server) UserPostsShow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		posts, count, err := s.store.Post().FindByOwnerIdPublic(num)
		if err != nil || posts == nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if p == num || s.store.User().IsFriend(num, p) {
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

//endpostservise

// inviteservise
// show user invites
func (s *server) UserInvitesShow() http.HandlerFunc {
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

// create invites
func (s *server) CreateUserInvite() http.HandlerFunc {
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

// delete invite
func (s *server) UserInviteDelete() http.HandlerFunc {
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

// accept invite
func (s *server) UserInviteAccept() http.HandlerFunc {
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

// friends servise
// show friends
func (s *server) UserFriends() http.HandlerFunc {
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

// show users no friends
func (s *server) UsersNotFriends() http.HandlerFunc {
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
func (s *server) UserFriendDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		err = s.store.User().DeleteFriend(p, num)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, nil)
	}
}

// end friends

// comments
func (s *server) CommentsForPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
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

func (s *server) CommentDelete() http.HandlerFunc {
	type request struct {
		CommentID int `json:"id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		post, err := s.store.Post().Find(num)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		comment, err := s.store.Comment().Find(req.CommentID)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if post.Owner_id != p && comment.Owner_id != p {
			s.error(w, r, 455, errNotAuthenticated)
			return
		}
		err = s.store.Comment().Delete(req.CommentID)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) CommentPatch() http.HandlerFunc {
	type request struct {
		CBody string `json:"body,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		comment, err := s.store.Comment().Find(num)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		if req.CBody == comment.Body || req.CBody == "" {
			s.error(w, r, http.StatusBadRequest, errors.New("noChange"))
			return
		}
		comment.Body = req.CBody
		c := r.Context().Value(ctxkeyUser)
		p := c.(int)
		if comment.Owner_id != p {
			s.error(w, r, 455, errNotAuthenticated)
			return
		}
		err = s.store.Comment().Update(num, comment)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		s.respond(w, r, http.StatusOK, comment)
	}
}

// homepage
func (s *server) HomePage() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		templ := template.Must(template.ParseFiles("templates/homepage.html"))
		templ.Execute(w, nil)
		s.respond(w, r, http.StatusOK, nil)
	})
}

// sessiondelete
func (s *server) SessionDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Context().Value(ctxkeyUser)
	}
}
