package friend

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/context"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/gorilla/mux"
)

var (
	_ handlers.Handler = &handler{}
)

const (
	friendsURL = "/friends"
	friendURL  = "/friends/{id}"
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
	router.HandleFunc("/notfriends", h.UsersNotFriends()).Methods(http.MethodGet)
	router.HandleFunc(friendsURL, h.UserFriends()).Methods(http.MethodGet)
	router.HandleFunc(friendURL, h.IsFriends()).Methods(http.MethodGet)
	router.HandleFunc(friendURL, h.UserFriendDelete()).Methods(http.MethodDelete)
}

func (h *handler) UserFriends() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		users, count, err := h.store.User().ShowFriends(userID)
		if err != nil || users == nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, users)
	}
}
func (h *handler) IsFriends() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		state := h.store.User().IsFriend(userID, num)
		fmt.Print(state)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, state)
	}
}

func (h *handler) UsersNotFriends() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		users, count, err := h.store.User().ShowUsers(userID)
		if err != nil || users == nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, users)
	}
}
func (h *handler) UserFriendDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		err = h.store.User().DeleteFriend(userID, num)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, nil)
	}
}
