package models

import "errors"

var (
	ErrDBConn              = errors.New("DB_CONNECTION_ERROR")
	ErrTokenExpired        = errors.New("TOKEN_EXPIRED")
	ErrUserNotRegistered   = errors.New("USER_NOT_REGISTERED")
	ErrInvalidInput        = errors.New("INVALID_INPUT")
	ErrInternalServerError = errors.New("INTERNAL_SERVER_ERROR")
	ErrUserDoesNotExist    = errors.New("USER_DOES_NOT_EXIST")
	ErrWrongEmailFormat    = errors.New("WRONG_EMAIL_FORMAT")
	ErrWrongPasswordFormat = errors.New("WRONG_PASSWORD_FORMAT")
	ErrWrongCreds          = errors.New("WRONG_CREDENTIALS")
	ErrWrongUUIDFormat     = errors.New("WRONG_UUID_FORMAT")
	ErrInvalidToken        = errors.New("INVALID_TOKEN")
)
