package model

type Invite struct {
	ID      int `json:"id"`
	To_id   int `json:"to_id"`
	From_id int `json:"from_id"`
}
