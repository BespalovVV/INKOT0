package store

type Store interface {
	User() UserRepository
	Post() PostRepository
	Comment() CommentRepository
}
