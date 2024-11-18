package invite

import (
	"encoding/json"
	"net/http"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/context"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/gorilla/mux"
)

var (
	_ handlers.Handler = &handler{}
)

const (
	invitesURL = "/invites"
	inviteURL  = "/invites/{id}"
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
	router.HandleFunc(invitesURL, h.UserInvitesShow()).Methods(http.MethodGet)
	router.HandleFunc(invitesURL, h.CreateUserInvite()).Methods(http.MethodPost)
	router.HandleFunc("/inviteaccept", h.UserInviteAccept()).Methods(http.MethodPost)
	router.HandleFunc(invitesURL, h.UserInviteDelete()).Methods(http.MethodDelete)
}

func (h *handler) UserInvitesShow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		invites, count, err := h.store.User().ShowInvites(userID)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, invites)
	}
}

func (h *handler) CreateUserInvite() http.HandlerFunc {
	type request struct {
		To_user_id int `json:"to_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		err = h.store.User().SendInvite(userID, req.To_user_id)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusCreated, nil)
	}
}

func (h *handler) UserInviteDelete() http.HandlerFunc {
	type request struct {
		Front_user_id int `json:"front_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		err = h.store.User().DeleteInvite(userID, req.Front_user_id)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, nil)
	}
}

func (h *handler) UserInviteAccept() http.HandlerFunc {
	type request struct {
		From_user_id int `json:"from_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		err = h.store.User().AddFriend(userID, req.From_user_id)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusCreated, nil)
	}
}
