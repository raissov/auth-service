package repository

import (
	"auth-serice/internal/models"
	"database/sql"
	"github.com/go-redis/redis/v7"
	"go.uber.org/zap"
	"time"
)

type Repository struct {
	User
	TokenRepo
}

type User interface {
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
}

type TokenRepo interface {
	//SetTToken - method that sets refresh token in redis. Method takes token struct and returns error
	SetRTToken(token *models.Token) error
	//UnsetRTToken - method that unsets refresh token in redis. Method takes token struct and returns error
	UnsetRTToken(userPublicID string) error
	//GetToken - method that retrieves token from redis. Method takes token struct and returns error
	GetToken(userPublicID string) (string, error)
}

func NewRepository(db *sql.DB, redis *redis.Client, timeout time.Duration, logger *zap.SugaredLogger) *Repository {
	return &Repository{
		User:      newUserRepo(db, timeout, logger),
		TokenRepo: newTokenRepo(redis, logger),
	}
}
