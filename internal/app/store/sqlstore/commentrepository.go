package sqlstore

import (
	"database/sql"

	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
)

type CommentRepository struct {
	store *Store
}

func (r *CommentRepository) Create(c *model.Comment) error {
	if err := c.Validate(); err != nil {
		return err
	}

	return r.store.db.QueryRow(
		"INSERT INTO posts(owner_id, post_id, body) VALUES ($1, $2, $3) RETURNING id",
		c.Owner_id, c.Post_id, c.Body,
	).Scan(&c.ID)
}

func (c *CommentRepository) ShowComments(id int) ([]*model.Comment, string, error) {
	rows, err := c.store.db.Query("SELECT id, owner_id, post_id, body FROM comments WHERE post_id = $1", id)
	count := ""
	c.store.db.QueryRow("SELECT COUNT(*) FROM comments WHERE post_id = $1", id).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	comments := make([]*model.Comment, 0)
	for rows.Next() {
		comment := new(model.Comment)
		err := rows.Scan(&comment.ID, &comment.Owner_id, &comment.Post_id, &comment.Body)
		if err != nil {
			return nil, "", err
		}
		comments = append(comments, comment)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	return comments, count, nil
}
