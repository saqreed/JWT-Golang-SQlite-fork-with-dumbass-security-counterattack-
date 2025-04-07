package handlers

import (
	"JWT/internal/entity"
	"JWT/internal/usecase"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

var (
	ErrBadParam = errors.New("Невалидные параметры")
)

type UserHandler struct {
	UseCase usecase.UserUseCase
}

func (u *UserHandler) GetUserByID(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrBadParam})
		return
	}
	user, err := u.UseCase.GetUserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	user.Password = ""
	c.JSON(http.StatusOK, user)
}

func (u *UserHandler) GetAll(c *gin.Context) {
	users, err := u.UseCase.GetAll()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	safeUsers := make([]entity.User, len(users))
	for i, user := range users {
		safeUsers[i] = user
		safeUsers[i].Password = ""
	}
	c.JSON(http.StatusOK, safeUsers)
}

func (u *UserHandler) GetUserByEmail(c *gin.Context) {
	email := c.Param("email")
	user, err := u.UseCase.GetUserByEmail(email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	user.Password = ""
	c.JSON(http.StatusOK, user)
}

func (u *UserHandler) DeleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrBadParam})
	}
	err = u.UseCase.DeleteUser(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, fmt.Sprintf("Пользователь ID: %d удален", id))
}
