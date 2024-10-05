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
		"INSERT INTO posts(owner_id, post_name, post_body, img_ref) VALUES ($1, $2, $3, $4) RETURNING id",
		p.Owner_id, p.PostName, p.PostBody, p.ImgRef,
	).Scan(&p.ID)
}

func (r *PostRepository) Show() ([]*model.Post, string, error) {
	rows, err := r.store.db.Query("SELECT id, owner_id, post_name, post_body, img_ref FROM posts")
	count := ""
	r.store.db.QueryRow("SELECT COUNT(*) FROM posts").Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	posts := make([]*model.Post, 0)
	for rows.Next() {
		post := new(model.Post)
		err := rows.Scan(&post.ID, &post.Owner_id, &post.PostName, &post.PostBody, &post.ImgRef)
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
	if err := r.store.db.QueryRow("SELECT id, post_name, post_body FROM posts WHERE ID = $1", id).Scan(
		&p.ID,
		&p.PostName,
		&p.PostBody,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}
	}

	return p, nil
}
