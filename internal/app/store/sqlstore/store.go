package sqlstore

import (
	"database/sql"

	"github.com/BespalovVV/INKOT0/internal/app/store"
	_ "github.com/lib/pq"
)

type Store struct {
	db                *sql.DB
	userRepository    *UserRepository
	postRepository    *PostRepository
	commentRepository *CommentRepository
}

func New(db *sql.DB) *Store {
	return &Store{
		db: db,
	}
}

func (s *Store) User() store.UserRepository {
	if s.userRepository != nil {
		return s.userRepository
	}
	s.userRepository = &UserRepository{
		store: s,
	}
	return s.userRepository
}
func (s *Store) Post() store.PostRepository {
	if s.postRepository != nil {
		return s.postRepository
	}
	s.postRepository = &PostRepository{
		store: s,
	}
	return s.postRepository
}
func (s *Store) Comment() store.CommentRepository {
	if s.commentRepository != nil {
		return s.commentRepository
	}
	s.commentRepository = &CommentRepository{
		store: s,
	}
	return s.commentRepository
}
