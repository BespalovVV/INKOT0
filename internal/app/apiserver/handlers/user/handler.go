package user

import (
	"encoding/json"
	"net/http"
	"strconv"

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
	store store.Store
}

func NewHandler(store store.Store) handlers.Handler {
	h := &handler{
		store: store,
	}
	return h
}

func (h *handler) Register(router *mux.Router) {
	router.HandleFunc(userURL, h.GetUser()).Methods(http.MethodGet)
	router.HandleFunc(usersURL, h.GetUsers()).Methods(http.MethodGet)
	router.HandleFunc(userURL, h.DeleteUser()).Methods(http.MethodDelete)
}

func (h *handler) GetUser() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.error(w, r, http.StatusBadRequest, err)
			return
		}
		if u, err := h.store.User().Find(num); err != nil {
			h.error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			u.Sanitize()
			h.respond(w, r, http.StatusOK, u)
		}
	})
}

func (h *handler) GetUsers() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if users, count, err := h.store.User().GetAll(); err != nil {
			h.error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			w.Header().Set("x-total-count", count)
			h.respond(w, r, http.StatusOK, users)
		}
	})
}

func (h *handler) DeleteUser() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.error(w, r, http.StatusBadRequest, err)
			return
		}
		if err := h.store.User().DeleteUser(num); err != nil {
			h.error(w, r, http.StatusUnprocessableEntity, err)
			return
		} else {
			h.respond(w, r, http.StatusOK, true)
		}
	})
}

func (h *handler) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	h.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (h *handler) respond(w http.ResponseWriter, _ *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
