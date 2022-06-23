package service

import (
	"auth-serice/config"
	"auth-serice/internal/models"
	"auth-serice/internal/repository"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type UserService struct {
	userRepo  repository.User
	tokenRepo repository.TokenRepo
	cfg       *config.Configs
	log       *zap.SugaredLogger
}

//jwtUserClaims - structure that holds the claims for the JWT token
type jwtUserClaims struct {
	UserPublicID string `json:"public_id"`
	jwt.StandardClaims
}

func hashAndSalt(pwd []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func NewUserService(userRepo repository.User, tokenRepo repository.TokenRepo, cfg *config.Configs, log *zap.SugaredLogger) *UserService {
	return &UserService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		cfg:       cfg,
		log:       log,
	}
}

func (u *UserService) CreateUser(creds *models.UserSignUpRequest) error {
	hashedPassword, err := hashAndSalt([]byte(creds.Password))
	if err != nil {
		return fmt.Errorf("error occured trying to hash password: %s %w", err.Error(), models.ErrInternalServerError)
	}

	user := &models.User{
		Email:    creds.Email,
		Password: hashedPassword,
	}
	err = u.userRepo.CreateUser(user)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserService) SignInUser(creds *models.UserSignInRequest) (*models.Tokens, error) {
	user, err := u.userRepo.GetUserByEmail(creds.Email)
	if err != nil {
		u.log.Errorf("Error occurred while getting user: %s", err.Error())
		return nil, err
	}
	if !CheckPasswordHash(creds.Password, user.Password) {
		u.log.Errorf("Invalid password")
		return nil, models.ErrWrongCreds
	}
	return u.GenerateTokens(user.PublicID, creds.RememberMe)
}

func (u *UserService) VerifyToken(tokenString string) (*models.Token, error) {
	return u.ParseToken(tokenString, u.cfg.Token.AccessToken.Secret)
}

//ParseToken - method that responsible for parsing jwt token. It checks if jwt token is valid, retrieves claims and returns user public id. In case of error returns error
func (s *UserService) ParseToken(tokenString string, tokenSecret string) (*models.Token, error) {
	s.log.Info("Token string: ", tokenString)
	token, err := jwt.ParseWithClaims(tokenString, &jwtUserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*jwtUserClaims); ok && token.Valid {
		token := &models.Token{
			UserPublicID: claims.UserPublicID,
			TokenValue:   tokenString,
		}
		return token, nil
	}
	return nil, fmt.Errorf("could not parse token: %s %w", err.Error(), models.ErrInvalidToken)
}

func (u *UserService) SignOut(tokeString string, userPublicID string) error {
	token, err := u.ParseToken(tokeString, u.cfg.Token.RefreshToken.Secret)
	if err != nil {
		return err
	}
	redisTokenString, err := u.tokenRepo.GetToken(userPublicID)
	if err != nil {
		return err
	}
	if redisTokenString != tokeString {
		return models.ErrTokenExpired
	}
	if userPublicID != token.UserPublicID {
		return models.ErrUserNotRegistered
	}
	return u.tokenRepo.UnsetRTToken(userPublicID)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (u *UserService) GenerateTokens(userPublicID string, rememberMe bool) (*models.Tokens, error) {
	accessToken, err := CreateAccessToken(userPublicID, u.cfg.Token.AccessToken.Secret, time.Second*time.Duration(u.cfg.Token.AccessToken.AccessExpires))
	if err != nil {
		u.log.Errorf("Error occurred while creating access token: %s", err.Error())
		return nil, err
	}
	var RTTL time.Duration
	if rememberMe {
		RTTL = time.Second * time.Duration(u.cfg.Token.RefreshToken.RefreshTokenLongExpires)
	} else {
		RTTL = time.Second * time.Duration(u.cfg.Token.RefreshToken.RefreshExpires)
	}
	refreshToken, err := CreateRefreshToken(userPublicID, u.cfg.Token.RefreshToken.Secret, RTTL)
	if err != nil {
		u.log.Errorf("Error occurred while creating refresh token: %s", err.Error())
		return nil, err
	}
	err = u.tokenRepo.SetRTToken(refreshToken)
	if err != nil {
		return nil, err
	}
	tokens := &models.Tokens{AccessToken: accessToken, RefreshToken: refreshToken}
	return tokens, nil
}

func CreateAccessToken(userID string, accessSecret string, ttl time.Duration) (*models.Token, error) {
	iat := time.Now().Unix()
	exp := time.Now().Add(ttl)
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["public_id"] = userID
	atClaims["iat"] = iat
	atClaims["exp"] = exp.Unix()

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	tokenString, err := at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	token := &models.Token{
		TokenValue:   tokenString,
		UserPublicID: userID,
		ExpiresAt:    time.Until(exp),
	}
	return token, nil
}

func CreateRefreshToken(userID string, refreshSecret string, rttl time.Duration) (*models.Token, error) {
	var err error
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	iat := time.Now().Unix()
	exp := time.Now().Add(rttl)
	rtClaims["authorized"] = true
	rtClaims["public_id"] = userID
	rtClaims["iat"] = iat
	rtClaims["exp"] = exp.Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	tokenString, err := at.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, err
	}
	token := &models.Token{
		TokenValue:   tokenString,
		UserPublicID: userID,
		ExpiresAt:    time.Until(exp),
	}
	return token, nil
}
