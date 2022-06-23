package repository

import (
	"auth-serice/config"
	"github.com/go-redis/redis/v7"
)

//NewRedis - function for creating new redis client
func NewRedis(cfg *config.RedisConf) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Host + ":" + cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}
	return client, nil
}
