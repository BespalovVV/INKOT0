package model

import (
	"database/sql"

	validation "github.com/go-ozzo/ozzo-validation"
)

type Post struct {
	ID       int            `json:"id"`
	Owner_id int            `json:"owner_id"`
	PostName string         `json:"post_name"`
	PostBody string         `json:"post_body"`
	ImgRef   sql.NullString `json:"img_ref"`
}

func (p *Post) Validate() error {
	return validation.ValidateStruct(
		p,
		validation.Field(&p.Owner_id, validation.Required, validation.NotNil),
		validation.Field(&p.PostBody, validation.Required, validation.NotNil),
		validation.Field(&p.PostName, validation.Required, validation.NotNil),
	)
}

func (p *Post) BeforeCreate() error {
	return nil
}
