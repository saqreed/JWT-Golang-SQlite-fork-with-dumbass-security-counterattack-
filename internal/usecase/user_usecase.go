package usecase

import "JWT/internal/entity"

type UserUseCase struct {
	repo entity.UserRepository
}

func NewUserUseCase(repo entity.UserRepository) *UserUseCase {
	return &UserUseCase{repo}
}

func (u *UserUseCase) GetAll() ([]entity.User, error) {
	return u.repo.GetAll()
}

func (u *UserUseCase) GetUserByID(id int) (entity.User, error) {
	return u.repo.GetByID(id)
}

func (u *UserUseCase) GetUserByEmail(email string) (entity.User, error) {
	return u.repo.GetByEmail(email)
}

func (u *UserUseCase) DeleteUser(id int) error {
	return u.repo.Delete(id)
}

func (u *UserUseCase) CreateUser(user entity.User) (entity.User, error) {
	return u.repo.Create(user)
}

func (u *UserUseCase) Login(user entity.User, refresh string) error {
	return u.repo.Login(user, refresh)
}
