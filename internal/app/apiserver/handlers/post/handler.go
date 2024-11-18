package post

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/BespalovVV/INKOT0/internal/app/apiserver/context"
	"github.com/BespalovVV/INKOT0/internal/app/apiserver/handlers"
	"github.com/BespalovVV/INKOT0/internal/app/model"
	"github.com/BespalovVV/INKOT0/internal/app/store"
	"github.com/gorilla/mux"
)

var (
	errNotAuthenticated                  = errors.New("not authenticated")
	_                   handlers.Handler = &handler{}
)

const (
	postsURL = "/posts"
	postURL  = "/posts/{id}"
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
	router.HandleFunc(postsURL, h.Posts()).Methods(http.MethodGet)
	router.HandleFunc(postsURL, h.PostCreate()).Methods(http.MethodPost)
	router.HandleFunc(postURL, h.Post()).Methods(http.MethodGet)
	router.HandleFunc(postURL, h.PostDelete()).Methods(http.MethodDelete)
	router.HandleFunc(postURL, h.PostPatch()).Methods(http.MethodPatch)
	router.HandleFunc("/users/{id}/posts", h.UserPostsShow()).Methods(http.MethodGet)
}

func (h *handler) PostCreate() http.HandlerFunc {
	type request struct {
		Title     string `json:"title"`
		Body      string `json:"body"`
		IsPrivate bool   `json:"isprivate"`
		Image     string `json:"imageurl"`
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

		var image sql.NullString
		if req.Image != "" {
			image = sql.NullString{String: req.Image, Valid: true}
		} else {
			image = sql.NullString{Valid: false}
		}

		post := &model.Post{
			Owner_id:  userID,
			Title:     req.Title,
			Body:      req.Body,
			IsPrivate: req.IsPrivate,
			Image:     image,
		}

		if err := h.store.Post().Create(post); err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, nil)
	}
}
func (h *handler) PostDelete() http.HandlerFunc {
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
		p, err := h.store.Post().Find(num)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if userID != p.Owner_id {
			h.Error(w, r, 455, errNotAuthenticated)
			return
		}
		if err := h.store.Post().Delete(num); err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, nil)
	}
}
func (h *handler) PostPatch() http.HandlerFunc {
	type request struct {
		Title     string `json:"title,omitempty"`
		Body      string `json:"body,omitempty"`
		IsPrivate bool   `json:"isprivate,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
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
		p, err := h.store.Post().Find(num)
		if err != nil {
			h.Error(w, r, 455, errNotAuthenticated)
			return
		}
		if p.Owner_id != userID {
			h.Error(w, r, 455, errNotAuthenticated)
			return
		}
		if p.Title != req.Title && req.Title != "" {
			p.Title = req.Title
		}
		if p.Body != req.Body && req.Body != "" {
			p.Body = req.Body
		}
		if req.IsPrivate {
			p.IsPrivate = !p.IsPrivate
		}
		if err := h.store.Post().Update(p.ID, p); err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, nil)
	}
}

func (h *handler) Posts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		posts, count, err := h.store.Post().Show(userID)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, posts)
	}
}

func (h *handler) Post() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		post, err := h.store.Post().Find(num)
		if post == nil {
			h.Error(w, r, http.StatusNotFound, errors.New("пост не найден"))
			return
		}
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		ok := h.store.User().IsFriend(post.Owner_id, userID) || !post.IsPrivate || post.Owner_id == userID
		if !ok {
			h.Error(w, r, http.StatusUnauthorized, errors.New("нет доступа"))
			return
		}
		h.Respond(w, r, http.StatusOK, post)
	}
}

func (h *handler) UserPostsShow() http.HandlerFunc {
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
		posts, count, err := h.store.Post().FindByOwnerIdPublic(num)
		if err != nil || posts == nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if userID == num || h.store.User().IsFriend(num, userID) {
			posts, count, err = h.store.Post().FindByOwnerId(num)
			if err != nil || posts == nil {
				h.Error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, posts)
	}
}
