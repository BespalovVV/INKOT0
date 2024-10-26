package model

import (
	"database/sql"

	validation "github.com/go-ozzo/ozzo-validation"
)

type Post struct {
	ID        int            `json:"id"`
	Owner_id  int            `json:"owner_id"`
	Title     string         `json:"title"`
	Body      string         `json:"body"`
	IsPrivate bool           `json:"isprivate"`
	Image     sql.NullString `json:"image,omitempty"`
}

func (p *Post) Validate() error {
	return validation.ValidateStruct(
		p,
		validation.Field(&p.Owner_id, validation.Required, validation.NotNil),
		validation.Field(&p.Body, validation.Required, validation.NotNil),
		validation.Field(&p.Title, validation.Required, validation.NotNil),
	)
}

func (p *Post) BeforeCreate() error {
	return nil
}
