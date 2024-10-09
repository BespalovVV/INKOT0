package model

import (
	validation "github.com/go-ozzo/ozzo-validation"
)

type Comment struct {
	ID       int    `json:"id"`
	Owner_id int    `json:"owner_id"`
	Post_id  int    `json:"post_id"`
	Body     string `json:"body"`
}

func (c *Comment) Validate() error {
	return validation.ValidateStruct(
		c,
		validation.Field(&c.Owner_id, validation.Required, validation.NotNil),
		validation.Field(&c.Body, validation.Required, validation.NotNil),
	)
}

func (c *Comment) BeforeCreate() error {
	return nil
}
