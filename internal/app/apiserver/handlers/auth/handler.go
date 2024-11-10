package auth

import (
	"encoding/json"
	"errors"
	"fmt"
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
	refreshURL         = "/refresh"
	tokenTTL           = 20 * time.Second
	signingKey         = "wqigowqieqwe21429832ywqeiuey8239y"
	salt               = "sdhfkojsdjlkfjsdkeeeeedd"
	autorizationHeader = "Authorization"
	refreshTokenTTL    = 2 * time.Hour
)

type tokenClaims struct {
	jwt.StandardClaims
	UserID int `json:"user_id"`
}

type handler struct {
	store store.Store
}

// Register implements handlers.Handler.
func (h *handler) Register(router *mux.Router) {
	router.HandleFunc(loginURL, h.Login()).Methods(http.MethodPost)
	router.HandleFunc(registrationURL, h.Registration()).Methods(http.MethodPost)
	router.HandleFunc(refreshURL, h.RefreshToken()).Methods(http.MethodPost)
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

func generateToken(userID int) (string, error) {
	claims := &tokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserID: userID, // Добавляем ID пользователя в payload
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписываем токен с использованием секретного ключа
	tokenStr, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

// Функция для генерации JWT refresh token
func generateRefreshToken(userID int) (string, error) {
	claims := &tokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(refreshTokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserID: userID, // Добавляем ID пользователя в payload
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshToken, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}
func (h *handler) ParseToken(accessToken string) (int, error) {
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
	return claims.UserID, nil
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

		// Получаем пользователя из хранилища по email
		u, err := h.store.User().FindByEmail(req.Email)
		if err != nil || !u.ComparePassword(req.Password) {
			h.error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
			return
		}

		// Генерация токенов
		accessToken, err := generateToken(u.ID)
		if err != nil {
			h.error(w, r, http.StatusUnauthorized, nil)
			return
		}

		refreshToken, err := generateRefreshToken(u.ID)
		if err != nil {
			h.error(w, r, http.StatusUnauthorized, nil)
			return
		}

		// Создаем структуру с данными пользователя и токеном
		type User struct {
			ID           int    `json:"id"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}
		user := User{Token: accessToken, ID: u.ID, RefreshToken: refreshToken}

		// Отправляем ответ с access токеном
		h.respond(w, r, http.StatusOK, user)
	}
}

func (h *handler) RefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Чтение JSON из тела запроса
		var requestBody struct {
			RefreshToken string `json:"refresh_token"` // Извлекаем refresh_token из JSON
		}

		// Декодируем JSON из тела запроса
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil || requestBody.RefreshToken == "" {
			h.error(w, r, http.StatusBadRequest, errors.New("refresh_token is required"))
			return
		}

		// Разбираем refresh token
		refreshToken := requestBody.RefreshToken
		claims := &jwt.StandardClaims{}

		// Проверяем токен и извлекаем claims
		_, _ = jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
			// Здесь можно добавить проверку метода подписи, если нужно
			return []byte(signingKey), nil
		})
		UserID, err := h.ParseToken(refreshToken)
		if err != nil {
			h.error(w, r, http.StatusUnauthorized, err)
			return
		}

		if claims.ExpiresAt < time.Now().Unix() {
			h.error(w, r, http.StatusUnauthorized, errors.New("invalid or expired refresh token"))
			return
		}

		// Выводим claims для отладки
		fmt.Println("Claims:", claims)
		fmt.Println("User ID from token:", claims.Subject)

		// Генерация нового access token

		accessToken, err := generateToken(UserID)
		if err != nil {
			h.error(w, r, http.StatusInternalServerError, errors.New("failed to generate access token"))
			return
		}

		// Генерация нового refresh token
		newRefreshToken, err := generateRefreshToken(UserID)
		if err != nil {
			h.error(w, r, http.StatusInternalServerError, errors.New("failed to generate refresh token"))
			return
		}

		// Отправляем новый access token и refresh token в JSON
		response := map[string]string{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken, // Используем новое имя для refresh токена
		}

		h.respond(w, r, http.StatusOK, response)
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
