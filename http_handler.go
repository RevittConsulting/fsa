package auth

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/didip/tollbooth_chi"
	"github.com/didip/tollbooth/v7"
)

type Handler struct {
	auth *Auth
}

func NewHandler(r chi.Router, auth *Auth) *Handler {
	h := &Handler{
		auth: auth,
	}
	h.SetupRoutes(r)
	return h
}

func (h *Handler) SetupRoutes(router chi.Router) {
	fmt.Println("setting up routes for auth")

	limiter := tollbooth.NewLimiter(float64(h.auth.Cfg.RateLimitPerSecond), nil)
	limiter.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"})

	router.Group(func(r chi.Router) {
		if h.auth.Cfg.RateLimitPerSecond > 0 {
			r.Use(tollbooth_chi.LimitHandler(limiter))
		}
		r.Get("/auth/login", h.Login)
		r.Get("/auth/confirm", h.ConfirmCode)
		r.Get("/auth/refresh", h.RefreshToken)
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	returnUrl := r.URL.Query().Get("returnUrl")

	ctx := r.Context()

	if len(email) == 0 {
		WriteErr(w, fmt.Errorf("email required"), http.StatusBadRequest)
		return
	}

	if len(returnUrl) == 0 {
		returnUrl = h.auth.Cfg.ReturnUrls[0]
	}

	validReturnUrl := false
	for _, url := range h.auth.Cfg.ReturnUrls {
		if url == returnUrl {
			validReturnUrl = true
			break
		}
	}

	if !validReturnUrl {
		WriteErr(w, fmt.Errorf("invalid return url"), http.StatusBadRequest)
		return
	}

	err := h.auth.LoginStep1SendVerificationCode(ctx, email, returnUrl)
	if err != nil {
		WriteErr(w, err, http.StatusInternalServerError)
		return
	}

	WriteJSON(w, "ok")
}

func (h *Handler) ConfirmCode(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	email := r.URL.Query().Get("email")

	ctx := r.Context()

	if len(code) == 0 || len(email) == 0 {
		WriteErr(w, fmt.Errorf("code and email required"), http.StatusBadRequest)
		return
	}

	confirmed, jwt, err := h.auth.LoginStep2ConfirmCode(ctx, email, code)
	if err != nil {
		WriteErr(w, err, http.StatusInternalServerError)
		return
	}

	if !confirmed {
		WriteErr(w, fmt.Errorf("error confirming code"), http.StatusBadRequest)
		return
	}

	WriteJSON(w, jwt)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	ctx := r.Context()

	if len(token) == 0 {
		WriteErr(w, fmt.Errorf("token required"), http.StatusBadRequest)
		return
	}

	jwt, err := h.auth.RefreshToken(ctx, token)
	if err != nil {
		WriteErr(w, err, http.StatusInternalServerError)
		return
	}

	WriteJSON(w, jwt)
}
