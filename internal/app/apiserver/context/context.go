package context

import (
	"context"
	"errors"
)

type key string

const (
	UserKey key = "user"
)

// SetUser встраивает информацию о пользователе в контекст
func SetUser(ctx context.Context, userID int) context.Context {
	return context.WithValue(ctx, UserKey, userID)
}

// GetUser извлекает информацию о пользователе из контекста
func GetUser(ctx context.Context) (int, error) {
	userID, ok := ctx.Value(UserKey).(int)
	if !ok {
		return 0, errors.New("user not found in context")
	}
	return userID, nil
}
