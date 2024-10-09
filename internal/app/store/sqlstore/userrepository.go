package sqlstore

import (
	"database/sql"

	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
)

type UserRepository struct {
	store *Store
}

func (r *UserRepository) Create(u *model.User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	if err := u.BeforeCreate(); err != nil {
		return err
	}

	return r.store.db.QueryRow(
		"INSERT INTO users(email, encrypted_password, age, name, surname, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		u.Email, u.EncryptedPassword, u.Age, u.Name, u.Surname, u.Description,
	).Scan(&u.ID)
}

func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	u := &model.User{}
	if err := r.store.db.QueryRow("SELECT id, email, encrypted_password, age, name, surname, description FROM users WHERE email = $1", email).Scan(
		&u.ID,
		&u.Email,
		&u.EncryptedPassword,
		&u.Age,
		&u.Name,
		&u.Surname,
		&u.Description,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}
	}

	return u, nil
}

func (r *UserRepository) Find(id int) (*model.User, error) {
	u := &model.User{}
	if err := r.store.db.QueryRow("SELECT id, email, encrypted_password, age, name, surname, description FROM users WHERE ID = $1", id).Scan(
		&u.ID,
		&u.Email,
		&u.EncryptedPassword,
		&u.Age,
		&u.Name,
		&u.Surname,
		&u.Description,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, store.ErrRecordNotFound
		}
	}

	return u, nil
}
