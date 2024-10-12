package store

import "github.com/BespalovVV/INKOT0/internal/app/model"

type UserRepository interface {
	Create(*model.User) error
	FindByEmail(string) (*model.User, error)
	Find(int) (*model.User, error)
	IsFriend(int, int) bool
	ShowUsers(int) ([]*model.User, string, error)
	AddFriend(int, int) error
	SendInvite(int, int) error
	ShowFriends(int) ([]*model.User, string, error)
	ShowInvites(int) ([]*model.Invite, string, error)
	DeleteInvite(int, int) error
}

type PostRepository interface {
	Create(*model.Post) error
	Show(int) ([]*model.Post, string, error)
	Find(int) (*model.Post, error)
	FindByOwnerId(int) ([]*model.Post, string, error)
	FindByOwnerIdPublic(int) ([]*model.Post, string, error)
}
type CommentRepository interface {
	Create(*model.Comment) error
	ShowComments(int) ([]*model.Comment, string, error)
}
