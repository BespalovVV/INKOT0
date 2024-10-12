package sqlstore

import (
	"database/sql"
	"fmt"
	"strconv"

	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
)

type UserRepository struct {
	store *Store
}

// AddFriends implements store.UserRepository.
func (r *UserRepository) AddFriend(temp_uid int, inviter_id int) error {
	err := r.store.db.QueryRow("CALL AddFriend($1, $2)", temp_uid, inviter_id)
	if err != nil {
		return err.Err()
	}

	return nil
}

func (r *UserRepository) DeleteInvite(temp_uid int, inviter_id int) error {
	err := r.store.db.QueryRow("CALL DeleteInvite($1, $2)", temp_uid, inviter_id)
	if err != nil {
		return err.Err()
	}
	return nil
}

func (r *UserRepository) ShowInvites(id int) ([]*model.Invite, string, error) {
	rows, err := r.store.db.Query("SELECT id, to_id, from_id FROM invites WHERE to_id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	count := ""
	err = r.store.db.QueryRow("SELECT COUNT(*) FROM invites WHERE to_id = $1", id).Scan(&count)
	defer rows.Close()
	invites := make([]*model.Invite, 0)
	for rows.Next() {
		invite := new(model.Invite)
		rows.Scan(&invite.ID, &invite.To_id, &invite.From_id)
		if err != nil {
			return nil, "", err
		}
		invites = append(invites, invite)
	}
	return invites, count, nil
}

// SendInvite implements store.UserRepository.
func (r *UserRepository) SendInvite(from_id int, to_id int) error {
	err := r.store.db.QueryRow(
		"INSERT INTO invites(to_id, from_id) VALUES ($1, $2) RETURNING id", to_id, from_id)
	if err != nil {
		return err.Err()
	}
	return nil
}

// ShowFriends implements store.UserRepository.
func (r *UserRepository) ShowFriends(id int) ([]*model.User, string, error) {
	rows, err := r.store.db.Query("SELECT friend_id FROM friends WHERE user_id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	ids := "" + strconv.Itoa(id)
	id0 := ""
	for rows.Next() {
		rows.Scan(&id0)
		if err != nil {
			return nil, "", err
		}
		ids += ", " + id0
	}
	fmt.Print("IDS::  ", ids)
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	rows0, err := r.store.db.Query(fmt.Sprintf("SELECT id, email, age, name, surname, description FROM users WHERE id IN (%v) AND id != (%d)", ids, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	count := ""
	r.store.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM users WHERE id IN (%v)", ids)).Scan(&count)
	defer rows0.Close()
	users := make([]*model.User, 0)
	for rows0.Next() {
		user := new(model.User)
		err := rows0.Scan(
			&user.ID,
			&user.Email,
			&user.Age,
			&user.Name,
			&user.Surname,
			&user.Description,
		)
		if err != nil {
			return nil, "", err
		}
		users = append(users, user)
	}
	if err = rows0.Err(); err != nil {
		return nil, "", err
	}
	return users, count, nil
}

// ShowUsers implements store.UserRepository.
func (r *UserRepository) ShowUsers(id int) ([]*model.User, string, error) {
	rows, err := r.store.db.Query("SELECT friend_id FROM friends WHERE user_id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	defer rows.Close()
	ids := "" + strconv.Itoa(id)
	id0 := ""
	for rows.Next() {
		rows.Scan(&id0)
		if err != nil {
			return nil, "", err
		}
		ids += ", " + id0
	}
	fmt.Print("IDS::  ", ids)
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	rows0, err := r.store.db.Query(fmt.Sprintf("SELECT id, email, age, name, surname, description FROM users WHERE id NOT IN (%v)", ids))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", store.ErrRecordNotFound
		}
	}
	count := ""
	r.store.db.QueryRow("SELECT COUNT(*) FROM users WHERE id NOT IN ($1) AND id != $2").Scan(&count)
	defer rows0.Close()
	users := make([]*model.User, 0)
	for rows0.Next() {
		user := new(model.User)
		err := rows0.Scan(
			&user.ID,
			&user.Email,
			&user.Age,
			&user.Name,
			&user.Surname,
			&user.Description,
		)
		if err != nil {
			return nil, "", err
		}
		users = append(users, user)
	}
	if err = rows0.Err(); err != nil {
		return nil, "", err
	}
	return users, count, nil
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

func (r *UserRepository) IsFriend(id int, id1 int) bool {
	count := 0
	if err := r.store.db.QueryRow("SELECT COUNT(*) FROM friends WHERE user_id = $1 AND friend_id = $2", id, id1).Scan(&count); err != nil {
		return false
	}
	if count > 0 {
		return true
	}
	return false
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
