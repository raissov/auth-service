package repository

import (
	"auth-serice/internal/models"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v7"
	"go.uber.org/zap"
)

type RedisToken struct {
	client *redis.Client
	log    *zap.SugaredLogger
}

func newTokenRepo(client *redis.Client, log *zap.SugaredLogger) *RedisToken {
	return &RedisToken{client: client, log: log}
}

func (r *RedisToken) SetRTToken(token *models.Token) error {
	key := token.UserPublicID
	r.log.Infof(token.ExpiresAt.String())
	if err := r.client.Set(key, token.TokenValue, token.ExpiresAt).Err(); err != nil {
		return fmt.Errorf("%w could not set refresh token to redis for TokenValue : %s: %v", models.ErrDBConn, token.TokenValue, err)
	}
	return nil
}

func (r *RedisToken) UnsetRTToken(userPublicID string) error {
	key := userPublicID
	if err := r.client.Del(key).Err(); err != nil {
		return fmt.Errorf("%w could not delete refresh token to redis for TokenValue : %v", models.ErrDBConn, err)
	}
	return nil
}

func (r *RedisToken) GetToken(userPublicID string) (string, error) {
	key := userPublicID
	value := r.client.Get(key)
	TokenValue, err := value.Result()
	if err != nil || TokenValue == "" {
		if errors.Is(err, redis.Nil) {
			return "", fmt.Errorf("token does not exist in storage: %w", models.ErrTokenExpired)
		}
		return "", fmt.Errorf("%w could not retrieve refresh token from redis for TokenValue : %v", models.ErrDBConn, err)
	}
	return TokenValue, nil
}
