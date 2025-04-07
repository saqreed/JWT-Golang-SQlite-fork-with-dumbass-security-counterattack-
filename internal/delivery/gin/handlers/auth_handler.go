package handlers

import (
	"JWT/internal/entity"
	"JWT/pkg/auth"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

type DtoUser struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (u *UserHandler) Register(c *gin.Context) {
	var user entity.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := user.HashPassword(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	createUser, err := u.UseCase.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var DUser = DtoUser{
		ID:    createUser.ID,
		Name:  createUser.Name,
		Email: createUser.Email,
	}

	c.JSON(http.StatusOK, DUser)
}

func (u *UserHandler) Login(c *gin.Context) {
	var data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}

	user, err := u.UseCase.GetUserByEmail(data.Email)
	if err != nil {
		if errors.Is(err, entity.NotFoundUser) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Ошибка сервера: %w", err.Error())})
		return
	}

	if user.CheckPassword(data.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неправильный пароль"})
		return
	}

	accessExpireAt := time.Now().Add(15 * time.Minute)
	refreshExpireAt := time.Now().Add(7 * 24 * time.Hour)

	accessClaims := &auth.Claims{
		Email: data.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpireAt),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(auth.SECRET_KEY)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Ошибка генерации access токена: %w", err),
		})
		return
	}

	refreshClaims := &auth.Claims{
		Email: data.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpireAt),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(auth.SECRET_KEY)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Ошибка генерации refresh токена: %w", err),
		})
		return
	}

	err = u.UseCase.Login(user, refreshTokenString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, auth.TokenResponse{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    accessExpireAt.Unix(),
	})
}

func (u *UserHandler) Refresh(c *gin.Context) {
	var request struct {
		RefreshToken *string `json:"refreshToken"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	claims := &auth.Claims{}
	token, err := jwt.ParseWithClaims(*request.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return auth.SECRET_KEY, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": fmt.Errorf("Невалидный refresh токен: %w", err),
		})
		return
	}

	user, err := u.UseCase.GetUserByEmail(claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}

	if user.RefreshToken != request.RefreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Невалидный refresh токен",
		})
		return
	}

	accessExpirationTime := time.Now().Add(15 * time.Minute)
	accessClaim := &auth.Claims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpirationTime),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaim)
	accessTokenString, err := accessToken.SignedString(auth.SECRET_KEY)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Errorf("Ошибка генерации access токена: %w", err.Error()),
		})
		return
	}

	c.JSON(http.StatusOK, auth.TokenResponse{
		AccessToken: accessTokenString,
		ExpiresAt:   accessExpirationTime.Unix(),
	})
}
