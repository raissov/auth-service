package config

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

//Configs- structure for holding other structures that holds the env variables
type Configs struct {
	DB    *DBConf    `yaml:"db"`
	App   *App       `yaml:"server"`
	Redis *RedisConf `yaml:"redis"`
	Token *TokenConf `yaml:"token"`
}

//DBConf - strucutre for holding env variables assosicated with database
type DBConf struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"db_name"`
	TimeOut  int    `yaml:"timeout"`
}

//RedisConf - structure for holding env variables associated with redis
type RedisConf struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

//App - structure for holding env variables associated with app
type App struct {
	AppPort         string `yaml:"port"`
	AppShutdownTime int    `yaml:"shutdown_time"`
}

type TokenConf struct {
	AccessToken  `yaml:"access_token"`
	RefreshToken `yaml:"refresh_token"`
}

type AccessToken struct {
	Secret        string `yaml:"secret"`
	AccessExpires int    `yaml:"time_to_live"`
}

type RefreshToken struct {
	Secret                  string `yaml:"secret"`
	RefreshExpires          int    `yaml:"time_to_live"`
	RefreshTokenLongExpires int    `yaml:"long_time_to_live"`
}

func New() (*Configs, error) {
	yamlBytes, err := os.ReadFile("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	// parse the YAML stored in the byte slice into the struct
	config := &Configs{}
	err = yaml.Unmarshal(yamlBytes, config)
	if err != nil {
		log.Fatal(err)
	}
	return config, err
}
