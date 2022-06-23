package repository

import (
	"auth-serice/internal/models"
	"context"
	"database/sql"
	"go.uber.org/zap"
	"time"
)

type UserRepository struct {
	db      *sql.DB
	timeout time.Duration
	logger  *zap.SugaredLogger
}

func newUserRepo(db *sql.DB, timeout time.Duration, logger *zap.SugaredLogger) *UserRepository {
	return &UserRepository{
		db:      db,
		timeout: timeout,
		logger:  logger,
	}
}

func (u *UserRepository) CreateUser(user *models.User) error {

	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()

	query := `INSERT INTO users (email, password) VALUES($1, $2) RETURNING id`
	if err := u.db.QueryRowContext(ctx, query, user.Email, user.Password).Scan(&user.ID); err != nil {
		u.logger.Errorf("Error occurred while querying to DB: %s", err.Error())
		return err
	}
	u.logger.Infof("User successfully created with ID: %d", user.ID)
	return nil
}

func (u *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()

	query := `SELECT public_id, email, password FROM users WHERE email = $1`
	if err := u.db.QueryRowContext(ctx, query, email).Scan(&user.PublicID, &user.Email, &user.Password); err != nil {
		u.logger.Errorf("Error occurred while querying to DB: %s", models.ErrUserDoesNotExist)
		return nil, err
	}
	u.logger.Infof("User successfully retrieved with ID: %d", user.ID)
	return &user, nil
}
