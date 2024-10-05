package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

const (
	sessionName        = "vlad"
	ctxKeyUser  ctxKey = iota
	ctxKeyRequestID
)

var (
	errIncorrectEmailOrPassword = errors.New("incorrect email or password")
	errNotAuthenticated         = errors.New("not authenticated")
)

type ctxKey int8

type server struct {
	router       *mux.Router
	logger       *logrus.Logger
	store        store.Store
	sessionStore sessions.Store
}

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
	s.router.PathPrefix("/static").Handler(http.StripPrefix("/static", http.FileServer(http.Dir("static"))))
	s.router.Use(s.setRequestID)
	s.router.Use(s.logRequest)
	s.router.Use(handlers.CORS(handlers.AllowedOrigins([]string{"*"})))
	s.router.HandleFunc("/", s.handleHomePage())
	s.router.HandleFunc("/userstest", s.handleUsersCreateTest()).Methods("POST")
	s.router.HandleFunc("/profile/{id}", s.hendleProfileShow())
	s.router.HandleFunc("/posts/{id}", s.handlePostShow())
	s.router.HandleFunc("/posts/{id}/comments", s.handleCommentsForPost())
	s.router.HandleFunc("/sessions", s.handleSessionsCreate()).Methods("POST")
	s.router.HandleFunc("/registration", s.handleUsersCreate())
	s.router.HandleFunc("/posts", s.handlePosts())

	private := s.router.PathPrefix("/private").Subrouter()
	private.Use(s.authenticateUser)
	private.HandleFunc("/whoami", s.handleWhoami())
}

func (s *server) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
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
		id := r.URL.Path[len(r.URL.Path)-len("/comments"):]
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
		id := r.URL.Path[len("/posts/"):]
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

func (s *server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(ctxKeyRequestID),
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

func (s *server) handleHomePage() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		templ := template.Must(template.ParseFiles("templates/homepage.html"))
		templ.Execute(w, nil)
		s.respond(w, r, http.StatusOK, nil)
	})
}

func (s *server) hendleProfileShow() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idString := mux.Vars(r)["id"]
		id, err := strconv.Atoi(idString)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
		}
		if u, err := s.store.User().Find(id); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			templ := template.Must(template.ParseFiles("templates/profile.html"))
			templ.Execute(w, u)
			s.respond(w, r, http.StatusOK, nil)
		}
	})
}

func (s *server) handleUsersCreateTest() http.HandlerFunc {
	type request struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		Name        string `json:"name"`
		Surname     string `json:"surname"`
		Age         string `json:"age"`
		Gender      string `json:"gender"`
		Description string `json:"description"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u := &model.User{
			Email:       req.Email,
			Password:    req.Password,
			Age:         req.Age,
			Gender:      req.Gender,
			Name:        req.Name,
			Surname:     req.Surname,
			Description: req.Description,
		}
		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		s.respond(w, r, http.StatusCreated, u)
	}
}

func (s *server) authenticateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		id, ok := session.Values["user_id"]
		if !ok {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		u, err := s.store.User().Find(id.(int))
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, u)))
	})
}

func (s *server) handleUsersCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			err := r.ParseForm()
			if err != nil {
				s.error(w, r, 434, err)
			}
			u := &model.User{
				Name:        r.FormValue("name"),
				Surname:     r.FormValue("surname"),
				Email:       r.FormValue("email"),
				Password:    r.FormValue("password"),
				Age:         r.FormValue("age"),
				Gender:      r.FormValue("gender"),
				Description: "",
			}
			if err := s.store.User().Create(u); err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
			if u1, err := s.store.User().FindByEmail(u.Email); err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			} else {
				http.Redirect(w, r, "/profile/"+fmt.Sprint(u1.ID), http.StatusMovedPermanently)
			}
		} else {
			http.ServeFile(w, r, "templates/index.html")
		}
	}
}

func (s *server) handleSessionsCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Email := r.PostFormValue("email")
		Password := r.PostFormValue("password")

		u, err := s.store.User().FindByEmail(Email)
		if err != nil || !u.ComparePassword(Password) {
			s.error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
			return
		}

		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		session.Values["user_id"] = u.ID
		if err := s.sessionStore.Save(r, w, session); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) handleWhoami() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			session, _ := s.sessionStore.Get(r, sessionName)
			session.Values = nil
			session.Options.MaxAge = 0
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
		} else {

			templ := template.Must(template.ParseFiles("templates/logout.html"))
			templ.Execute(w, r.Context().Value(ctxKeyUser).(*model.User))
		}
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
