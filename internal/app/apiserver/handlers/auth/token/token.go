package token

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Config struct {
	BindAddr        string `toml:"bind_addr"`
	LogLevel        string `toml:"log_level"`
	DatabaseURL     string `toml:"database_url"`
	SessionKey      string `toml:"session_key"`
	SigningKey      string `toml:"singing_key"`
	Salt            string `toml:"salt"`
	TokenTTL        int64  `toml:"token_ttl"`
	RefreshTokenTTL int64  `toml:"refresh_token_ttl"`
}

type tokenClaims struct {
	jwt.StandardClaims
	UserID int `json:"user_id"`
}

func GenerateToken(userID int, config *Config) (string, error) {
	claims := &tokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(config.TokenTTL) * time.Second).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserID: userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString([]byte(config.SigningKey))
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func GenerateRefreshToken(userID int, config *Config) (string, error) {
	claims := &tokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(config.RefreshTokenTTL) * time.Second).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		UserID: userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshToken, err := token.SignedString([]byte(config.SigningKey))
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}
func ParseToken(accessToken string, config *Config) (int, error) {
	token, err := jwt.ParseWithClaims(accessToken, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(config.SigningKey), nil
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

func GenerateTokens(userID int, config *Config) (string, string, error) {
	accessToken, err := GenerateToken(userID, config)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateRefreshToken(userID, config)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
