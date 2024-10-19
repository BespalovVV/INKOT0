package sqlstore

import (
	"database/sql"

	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
)

type PostRepository struct {
	store *Store
}

func (r *PostRepository) Create(p *model.Post) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return r.store.db.QueryRow(
		"INSERT INTO posts(owner_id, title, body, private) VALUES ($1, $2, $3, $4) RETURNING id",
		p.Owner_id, p.Title, p.Body, p.IsPrivate,
	).Scan(&p.ID)
}

func (r *PostRepository) Show(id int) ([]*model.Post, string, error) {
	rows, err := r.store.db.Query("SELECT id, owner_id, title, body FROM posts WHERE owner_id != $1 AND private = false", id)
	count := ""
	r.store.db.QueryRow("SELECT COUNT(*) FROM posts WHERE owner_id != $1 AND private = false", id).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	posts := make([]*model.Post, 0)
	for rows.Next() {
		post := new(model.Post)
		err := rows.Scan(&post.ID, &post.Owner_id, &post.Title, &post.Body)
		if err != nil {
			return nil, "", err
		}
		posts = append(posts, post)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return posts, count, nil
}
func (r *PostRepository) Find(id int) (*model.Post, error) {
	p := &model.Post{}
	if err := r.store.db.QueryRow("SELECT id, title, body FROM posts WHERE ID = $1", id).Scan(
		&p.ID,
		&p.Title,
		&p.Body,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}
	}

	return p, nil
}
func (r *PostRepository) FindByOwnerId(id int) ([]*model.Post, string, error) {
	rows, err := r.store.db.Query("SELECT id, owner_id, title, body FROM posts WHERE owner_id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	count := ""
	err = r.store.db.QueryRow("SELECT COUNT(*) FROM posts WHERE owner_id = $1", id).Scan(&count)
	if err != nil || count == "0" {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	posts := make([]*model.Post, 0)
	for rows.Next() {
		post := new(model.Post)
		err := rows.Scan(&post.ID, &post.Owner_id, &post.Title, &post.Body)
		if err != nil {
			return nil, "", err
		}
		posts = append(posts, post)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return posts, count, nil
}

func (r *PostRepository) FindByOwnerIdPublic(id int) ([]*model.Post, string, error) {
	rows, err := r.store.db.Query("SELECT id, owner_id, title, body FROM posts WHERE owner_id = $1 AND private = false", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	count := ""
	err = r.store.db.QueryRow("SELECT COUNT(*) FROM posts WHERE owner_id = $1 AND private = false", id).Scan(&count)
	if err != nil || count == "0" {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	posts := make([]*model.Post, 0)
	for rows.Next() {
		post := new(model.Post)
		err := rows.Scan(&post.ID, &post.Owner_id, &post.Title, &post.Body)
		if err != nil {
			return nil, "", err
		}
		posts = append(posts, post)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return posts, count, nil
}
