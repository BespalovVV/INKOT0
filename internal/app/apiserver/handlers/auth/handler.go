package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers/auth/token"
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
	loginURL            = "/login"
	registrationURL     = "/registration"
	refreshURL          = "/refresh"
	signingKey          = "wqigowqieqwe21429832ywqeiuey8239y"
	salt                = "sdhfkojsdjlkfjsdkeeeeedd"
	authorizationHeader = "Authorization"
	tokenTTL            = 20 * time.Minute
	refreshTokenTTL     = 2 * time.Hour
)

type handler struct {
	handlers.BaseHandler
	store store.Store
}

func NewHandler(store store.Store) handlers.Handler {
	return &handler{
		BaseHandler: handlers.BaseHandler{},
		store:       store,
	}
}

func (h *handler) Register(router *mux.Router) {
	router.HandleFunc(loginURL, h.Login()).Methods(http.MethodPost)
	router.HandleFunc(registrationURL, h.Registration()).Methods(http.MethodPost)
	router.HandleFunc(refreshURL, h.RefreshToken()).Methods(http.MethodPost)
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
			h.Error(w, r, http.StatusBadRequest, err)
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
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		u.Sanitize()
		h.Respond(w, r, http.StatusOK, nil)
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
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}

		u, err := h.store.User().FindByEmail(req.Email)
		if err != nil || !u.ComparePassword(req.Password) {
			h.Error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
			return
		}

		accessToken, refreshToken, err := token.GenerateTokens(u.ID)
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}

		type User struct {
			ID           int    `json:"id"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}
		user := User{Token: accessToken, ID: u.ID, RefreshToken: refreshToken}

		h.Respond(w, r, http.StatusOK, user)
	}
}

func (h *handler) RefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Чтение JSON из тела запроса
		var requestBody struct {
			RefreshToken string `json:"refresh_token"`
		}

		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil || requestBody.RefreshToken == "" {
			h.Error(w, r, http.StatusBadRequest, errors.New("refresh_token is required"))
			return
		}

		refreshToken := requestBody.RefreshToken
		claims := &jwt.StandardClaims{}

		_, _ = jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(signingKey), nil
		})
		UserID, err := token.ParseToken(refreshToken)
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		if claims.ExpiresAt < time.Now().Unix() {
			h.Error(w, r, http.StatusUnauthorized, errors.New("invalid or expired refresh token"))
			return
		}
		fmt.Println("Claims:", claims)
		fmt.Println("User ID from token:", claims.Subject)
		accessToken, newRefreshToken, err := token.GenerateTokens(UserID)
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		response := map[string]string{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
		}

		h.Respond(w, r, http.StatusOK, response)
	}
}
