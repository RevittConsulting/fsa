package fsa

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrorAuthHeaderMissing = errors.New("authorization header is missing")
	ErrorInvalidAuthHeader = errors.New("invalid authorization header format")
)

type AuthMiddleware struct {
	Cfg *Config
}

func NewChiMiddleware(cfg *Config) *AuthMiddleware {
	return &AuthMiddleware{
		Cfg: cfg,
	}
}

func (am *AuthMiddleware) VerifyAuthenticationToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, ErrorAuthHeaderMissing.Error(), http.StatusUnauthorized)
			return
		}

		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) != 2 {
			http.Error(w, ErrorInvalidAuthHeader.Error(), http.StatusUnauthorized)
			return
		}

		jwtToken := splitToken[1]
		claims, err := parseTokenString(jwtToken, am.Cfg.AccessTokenSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsKey, claims)
		ctx = context.WithValue(ctx, UserEmailKey, claims["email"])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func parseTokenString(input string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(input, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
