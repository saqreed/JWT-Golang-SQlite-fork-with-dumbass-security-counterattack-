package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

var SECRET_KEY = []byte("bsdicuy2389[aSKLCNVWI")

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
}
