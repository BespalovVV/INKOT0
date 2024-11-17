package token

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	loginURL           = "/login"
	registrationURL    = "/registration"
	refreshURL         = "/refresh"
	signingKey         = "wqigowqieqwe21429832ywqeiuey8239y"
	salt               = "sdhfkojsdjlkfjsdkeeeeedd"
	autorizationHeader = "Authorization"
	tokenTTL           = 20 * time.Minute
	refreshTokenTTL    = 2 * time.Hour
)

type tokenClaims struct {
	jwt.StandardClaims
	UserID int `json:"user_id"`
}

func GenerateToken(userID int) (string, error) {
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
func GenerateRefreshToken(userID int) (string, error) {
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
func ParseToken(accessToken string) (int, error) {
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

func GenerateTokens(userID int) (string, string, error) {
	accessToken, err := GenerateToken(userID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateRefreshToken(userID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
