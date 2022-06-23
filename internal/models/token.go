package models

import "time"

//Token - structure for holding all token related data
type Token struct {
	UserPublicID string
	TokenValue   string
	ExpiresAt    time.Duration
}

//Tokens - structure for holding access and refresh token
type Tokens struct {
	AccessToken  *Token
	RefreshToken *Token
}
