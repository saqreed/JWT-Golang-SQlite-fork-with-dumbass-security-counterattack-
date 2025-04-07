package entity

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	GetAll() ([]User, error)
	GetByID(id int) (User, error)
	GetByEmail(email string) (User, error)
	Create(user User) (User, error)
	Delete(id int) error
	Login(user User, refresh string) error
}

var (
	ErrSearchUsers           = errors.New("Ошибка поиска пользователей")
	NotFoundUser             = errors.New("Пользователь не найден")
	ErrDeleteUser            = errors.New("Ошибка удаления пользователя")
	ErrUserAlreadyRegistered = errors.New("Пользователь с данным Email уже зарегистрирован")
	ErrCreateUser            = errors.New("Ошибка создания пользователя")
)

type User struct {
	ID           int     `json:"id"`
	Name         string  `json:"name"`
	Password     string  `json:"password"`
	Email        string  `json:"email"`
	RefreshToken *string `json:"refresh_token"`
}

func (u *User) HashPassword() error {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hashPassword)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}
