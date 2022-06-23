package models

type User struct {
	ID       int64  `json:"id"`
	PublicID string `json:"public_id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserSignInRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

type UserSignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
