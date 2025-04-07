package repository

import (
	"JWT/internal/entity"
	"database/sql"
	"errors"
	"fmt"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) entity.UserRepository {
	return &userRepository{db}
}

func (u *userRepository) GetAll() ([]entity.User, error) {
	query := `SELECT * FROM users`
	users, err := u.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("Users: %w", entity.ErrSearchUsers)
	}

	var searchUsers []entity.User
	for users.Next() {
		var user entity.User
		if err := users.Scan(&user.ID, &user.Password, &user.Email, &user.Name); err != nil {
			return nil, fmt.Errorf("Users: %w", entity.NotFoundUser)
		}
		searchUsers = append(searchUsers, user)
	}
	return searchUsers, nil
}

func (u *userRepository) GetByID(id int) (entity.User, error) {
	query := `SELECT * FROM users WHERE id = $1`
	searchUser := u.db.QueryRow(query, id)

	var user entity.User
	if err := searchUser.Scan(&user.ID, &user.Password, &user.Email, &user.Name); err != nil {
		return entity.User{}, entity.NotFoundUser
	}
	return user, nil
}

func (u *userRepository) GetByEmail(email string) (entity.User, error) {
	query := `SELECT id, password, email, name, refresh_token FROM users WHERE email = $1`

	var user entity.User
	err := u.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Password,
		&user.Email,
		&user.Name,
		&user.RefreshToken,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.User{}, entity.NotFoundUser
		}
		return entity.User{}, fmt.Errorf("ошибка при поиске пользователя: %w", err)
	}
	return user, nil
}

func (u *userRepository) Delete(id int) error {
	query := `DELETE FROM users WHERE id = $1`
	res, err := u.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("User: %w", entity.ErrDeleteUser)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("Users: %w %w", entity.ErrDeleteUser, "затронуто 0 строк")
	}
	return nil
}

func (u *userRepository) Create(user entity.User) (entity.User, error) {
	query :=
		`INSERT INTO users(name, password, email)
         VALUES ($1, $2, $3)
         RETURNING id, name, password, email`

	if err := user.HashPassword(); err != nil {
		return entity.User{}, err
	}
	if _, err := u.GetByEmail(user.Email); err != nil {
		if !errors.Is(err, entity.NotFoundUser) {
			return entity.User{}, entity.ErrUserAlreadyRegistered
		}
	}

	var createUser entity.User
	err := u.db.QueryRow(
		query,
		user.Name,
		user.Password,
		user.Email,
	).Scan(
		&createUser.ID,
		&createUser.Name,
		&createUser.Password,
		&createUser.Email,
	)
	if err != nil {
		fmt.Println("-------------->", "Create Error")
		return entity.User{}, entity.ErrCreateUser
	}

	return createUser, nil
}

func (u *userRepository) Login(user entity.User, refresh string) error {
	query :=
		`UPDATE users
		 SET refresh_token = $1
		 WHERE id = $2;`

	res, err := u.db.Exec(query, refresh, user.ID)
	if err != nil {
		return fmt.Errorf("Ошибка обновления refresh токена: %w", err.Error())
	}
	resAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if resAffected == 0 {
		return fmt.Errorf("пользователь с ID %d не найден", user.ID)
	}
	return nil
}
