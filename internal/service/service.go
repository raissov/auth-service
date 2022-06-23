package service

import (
	"auth-serice/config"
	"auth-serice/internal/models"
	"auth-serice/internal/repository"
	"go.uber.org/zap"
)

type Service struct {
	User
}

type User interface {
	CreateUser(creds *models.UserSignUpRequest) error
	SignInUser(creds *models.UserSignInRequest) (*models.Tokens, error)
	VerifyToken(tokenString string) (*models.Token, error)
	SignOut(tokeString string, userPublicID string) error
}

func NewService(repo *repository.Repository, cfg *config.Configs, logger *zap.SugaredLogger) *Service {
	return &Service{
		User: NewUserService(repo.User, repo.TokenRepo, cfg, logger),
	}
}
