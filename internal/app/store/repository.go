package store

import "github.com/BespalovVV/INKOT0/internal/app/model"

type UserRepository interface {
	Create(*model.User) error
	FindByEmail(string) (*model.User, error)
	Find(int) (*model.User, error)
}

type PostRepository interface {
	Create(*model.Post) error
	Show() ([]*model.Post, string, error)
	Find(int) (*model.Post, error)
}
type CommentRepository interface {
	Create(*model.Comment) error
	ShowComments(int) ([]*model.Comment, string, error)
}
