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
		"INSERT INTO comments(owner_id, post_id, body) VALUES ($1, $2, $3) RETURNING id",
		c.Owner_id, c.Post_id, c.Body,
	).Scan(&c.ID)
}
func (r *CommentRepository) Delete(id int) error {
	_, err := r.store.db.Exec("DELETE FROM comments WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}
func (r *CommentRepository) Update(id int, comment *model.Comment) error {
	err := r.store.db.QueryRow("UPDATE comments SET body = $2 WHERE id = $1", id, comment.Body)
	if err != nil {
		return err.Err()
	}
	return nil
}
func (r *CommentRepository) Find(id int) (*model.Comment, error) {
	comment := &model.Comment{}
	err := r.store.db.QueryRow("SELECT id, owner_id, body, post_id FROM comments WHERE id = $1", id).Scan(&comment.ID, &comment.Owner_id, &comment.Body, &comment.Post_id)
	if err != nil {
		return nil, err
	}
	return comment, nil
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
