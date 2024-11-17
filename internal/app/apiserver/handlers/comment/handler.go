package comment

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
	commentsURL = "/comments"
	commentURL  = "/comments/{id}"
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
	router.HandleFunc("/posts/{id}/comments", h.CommentsForPost()).Methods(http.MethodGet)
	router.HandleFunc(commentsURL, h.CreateComment()).Methods(http.MethodPost)
	router.HandleFunc(commentURL, h.CommentDelete()).Methods(http.MethodDelete)
	router.HandleFunc(commentURL, h.CommentPatch()).Methods(http.MethodPatch)
}

func (h *handler) CreateComment() http.HandlerFunc {
	type request struct {
		Body   string `json:"body"`
		PostID int    `json:"post_id"`
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
		post, err := h.store.Post().Find(req.PostID)
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, errors.New("нет доступа"))
		}
		ok := h.store.User().IsFriend(post.Owner_id, userID) || !post.IsPrivate || post.Owner_id == userID
		if !ok {
			h.Error(w, r, http.StatusUnauthorized, errors.New("нет доступа"))
			return
		}
		comment := &model.Comment{
			Body:     req.Body,
			Owner_id: userID,
			Post_id:  req.PostID,
		}
		err = h.store.Comment().Create(comment)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, comment)
	}
}
func (h *handler) CommentsForPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		num, err := strconv.Atoi(id)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		comments, count, err := h.store.Comment().ShowComments(num)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		w.Header().Set("x-total-count", count)
		w.Header().Add("Access-Control-Expose-Headers", "x-total-count")
		h.Respond(w, r, http.StatusOK, comments)
	}
}

func (h *handler) CommentDelete() http.HandlerFunc {
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
		comment, err := h.store.Comment().Find(num)
		if err != nil {
			if err == sql.ErrNoRows {
				h.Error(w, r, http.StatusNotFound, err)
				return
			}
			h.Error(w, r, http.StatusInternalServerError, err)
			return
		}
		post, err := h.store.Post().Find(comment.Post_id)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		if post.Owner_id != userID && comment.Owner_id != userID {
			h.Error(w, r, http.StatusUnauthorized, errors.New("нет доступа"))
			return
		}
		err = h.store.Comment().Delete(comment.ID)
		if err != nil {
			h.Error(w, r, http.StatusInternalServerError, err)
			return
		}
		h.Respond(w, r, http.StatusOK, nil)
	}
}

func (h *handler) CommentPatch() http.HandlerFunc {
	type request struct {
		CBody string `json:"body,omitempty"`
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
		comment, err := h.store.Comment().Find(num)
		if err != nil {
			h.Error(w, r, http.StatusBadRequest, err)
			return
		}
		if req.CBody == comment.Body || req.CBody == "" {
			h.Error(w, r, http.StatusBadRequest, errors.New("noChange"))
			return
		}
		comment.Body = req.CBody
		userID, err := context.GetUser(r.Context())
		if err != nil {
			h.Error(w, r, http.StatusUnauthorized, err)
			return
		}
		if comment.Owner_id != userID {
			h.Error(w, r, 455, errNotAuthenticated)
			return
		}
		err = h.store.Comment().Update(num, comment)
		if err != nil {
			h.Error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		h.Respond(w, r, http.StatusOK, comment)
	}
}
