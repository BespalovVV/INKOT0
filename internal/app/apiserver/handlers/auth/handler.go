package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var _ handlers.Handler = &handler{}
var (
	errIncorrectEmailOrPassword = errors.New("incorrect email or password")
)

const (
	loginURL           = "/login"
	registrationURL    = "/registration"
	tokenTTL           = 2 * time.Hour
	signingKey         = "wqigowqieqwe21429832ywqeiuey8239y"
	salt               = "sdhfkojsdjlkfjsdkeeeeedd"
	autorizationHeader = "Authorization"
)

type tokenClaims struct {
	jwt.StandardClaims
	UserId int `json:"user_id"`
}

type handler struct {
	store store.Store
}

// Register implements handlers.Handler.
func (h *handler) Register(router *mux.Router) {
	router.HandleFunc(loginURL, h.Login()).Methods(http.MethodPost)
	router.HandleFunc(registrationURL, h.Registration()).Methods(http.MethodPost)
}

func NewHandler(store store.Store) handlers.Handler {
	h := &handler{
		store: store,
	}
	return h
}

func (h *handler) Registration() http.HandlerFunc {
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
			h.error(w, r, http.StatusBadRequest, err)
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
		if err := h.store.User().Create(u); err != nil {
			h.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		u.Sanitize()
		h.respond(w, r, http.StatusOK, nil)
	}
}

func (h *handler) Login() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			h.error(w, r, http.StatusBadRequest, err)
			return
		}

		u, err := h.store.User().FindByEmail(req.Email)
		if err != nil || !u.ComparePassword(req.Password) {
			h.error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
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
			h.error(w, r, http.StatusUnauthorized, nil)
			return
		}
		type User struct {
			ID    int
			Token string
		}
		user := User{Token: tokenr, ID: u.ID}
		h.respond(w, r, http.StatusOK, user)
	}
}

func (h *handler) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	h.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (h *handler) respond(w http.ResponseWriter, _ *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
