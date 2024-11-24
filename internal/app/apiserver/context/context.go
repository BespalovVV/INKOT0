package context

import (
	"context"
	"errors"
)

type key string

const (
	UserKey key = "user"
)

func SetUser(ctx context.Context, userID int) context.Context {
	return context.WithValue(ctx, UserKey, userID)
}

func GetUser(ctx context.Context) (int, error) {
	userID, ok := ctx.Value(UserKey).(int)
	if !ok {
		return 0, errors.New("user not found in context")
	}
	return userID, nil
}
