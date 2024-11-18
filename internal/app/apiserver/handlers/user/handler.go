package user

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/context"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/gorilla/mux"
)

var _ handlers.Handler = &handler{}

const (
	usersURL = "/users"
	userURL  = "/users/{id}"
)

type handler struct {
	handlers.BaseHandler
	store store.Store
}

func NewHandler(store store.Store) handlers.Handler {
	return &handler{
		BaseHandler: handlers.BaseHandler{},
		store:       store,
	}
}

func (h *handler) Register(router *mux.Router) {
	router.HandleFunc(userURL, h.GetUser()).Methods(http.MethodGet)
	router.HandleFunc(usersURL, h.GetUsers()).Methods(http.MethodGet)
	router.HandleFunc(userURL, h.DeleteUser()).Methods(http.MethodDelete)
	router.HandleFunc(userURL, h.PatchUser()).Methods(http.MethodPatch)
}

func (h *handler) GetUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		u, err := h.store.User().Find(num)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		u.Sanitize()
		h.Respond(w, r, http.StatusOK, u)
	}
}

func (h *handler) GetUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, count, err := h.store.User().GetAll()
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		h.Respond(w, r, http.StatusOK, users)
	}
}

func (h *handler) DeleteUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		err = h.store.User().DeleteUser(num)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, true)
	}
}

func (h *handler) PatchUser() http.HandlerFunc {
	type request struct {
		Image       string `json:"image,omitempty"`
		Email       string `json:"email,omitempty"`
		Password    string `json:"password,omitempty"`
		Age         int    `json:"age,omitempty"`
		Name        string `json:"name,omitempty"`
		Surname     string `json:"surname,omitempty"`
		Description string `json:"description,omitempty"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		if userID != num || userID == 0 {
			h.Error(w, r, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		user, err := h.store.User().Find(userID)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if req.Age != user.Age && req.Age != 0 {
			user.Age = req.Age
		}
		if req.Email != user.Email && req.Email != "" {
			user.Email = req.Email
		}
		if !user.ComparePassword(req.Password) && req.Password != "" {
			err = user.BeforeCreate()
			if err != nil {
				h.Error(w, r, http.StatusBadRequest, err)
				return
			}
		}
		if req.Name != user.Name && req.Name != "" {
			user.Name = req.Name
		}
		if req.Surname != user.Surname && req.Surname != "" {
			user.Surname = req.Surname
		}
		if req.Description != user.Description && req.Description != "" {
			user.Description = req.Description
		}
		if req.Image != user.Image.String {
			user.Image.String = req.Image
		}
		if user1, err := h.store.User().PatchUser(userID, user); err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			h.Respond(w, r, http.StatusOK, user1)
		}
	})
}
