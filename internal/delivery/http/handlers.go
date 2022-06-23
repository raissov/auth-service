package delivery

import (
	"auth-serice/config"
	"auth-serice/internal/models"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"io/ioutil"
	"net/mail"
	"unicode"

	"auth-serice/internal/service"
	"go.uber.org/zap"
)

type Handler struct {
	service *service.Service
	logger  *zap.SugaredLogger
	cfg     *config.Configs
}

//UserSignUpRequest - struct that contains all the fields that are required for response with access and refresh tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

//RefreshTokenRequest - struct that contains all the fields that are required for refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

//VerifyTokenRequest - struct that contains all the fields that are required for verify token request
type VerifyTokenRequest struct {
	AccessToken string `json:"access_token"`
}

//VerifyTokenResponse - struct that contains all the fields that are required for response for verifyToken endpoint
type VerifyTokenResponse struct {
	UserPublicID string `json:"user_public_id"`
}

//NewHandler - function that creates new handler. It takes services, zap looger and configs as an argument, and returns handler
func NewHandler(services *service.Service, logger *zap.SugaredLogger, cfg *config.Configs) *Handler {
	return &Handler{
		service: services,
		logger:  logger,
		cfg:     cfg,
	}
}

func (h *Handler) InitRoutes() *gin.Engine {
	router := gin.Default()
	router.POST("/sign-up", h.SignUp)
	router.POST("/sign-in", h.SignIn)
	router.POST("/sign-out", h.SignOut)
	router.POST("/verify-token", h.VerifyToken)

	return router
}

func (h *Handler) SignUp(c *gin.Context) {
	requestBody, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.Errorf("Error occurred while reading request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput.Error(),
		})
		return
	}
	var signUpRequest *models.UserSignUpRequest
	err = json.Unmarshal(requestBody, &signUpRequest)
	if err != nil {
		h.logger.Errorf("Error occurred while unmarshalling request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput.Error(),
		})
		return
	}
	var errMsg string
	err = h.service.CreateUser(signUpRequest)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserDoesNotExist):
			errMsg = models.ErrUserDoesNotExist.Error()
		case errors.Is(err, models.ErrDBConn):
			errMsg = models.ErrDBConn.Error()
		default:
			h.logger.Errorf("Error occurred while creating new user: %s", err.Error())
			c.JSON(500, gin.H{
				"error": models.ErrInternalServerError,
			})
			return
		}
		h.logger.Errorf("Error occurred while creating new user: %s", err.Error())
		c.JSON(401, gin.H{
			"error": errMsg,
		})
		return
	}
	c.JSON(200, gin.H{
		"status": "OK",
	})
}

func (h *Handler) SignIn(c *gin.Context) {
	requestBody, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.Errorf("Error occurred while reading request body: %s", err.Error())
		c.JSON(200, gin.H{
			"error": models.ErrInvalidInput.Error()})
		return
	}
	var request *models.UserSignInRequest
	err = json.Unmarshal(requestBody, &request)
	if err != nil {
		h.logger.Errorf("Error occurred while unmarshalling request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput,
		})
		return
	}
	var errMsg string
	switch {
	case !validateEmail(request.Email):
		errMsg = models.ErrWrongEmailFormat.Error()
	case !validatePassword(request.Password):
		errMsg = models.ErrWrongPasswordFormat.Error()
	}
	if errMsg != "" {
		h.logger.Errorf("Error occurred while refreshing token: %s", err.Error())
		c.JSON(401, gin.H{
			"error": errMsg,
		})
		return
	}
	tokens, err := h.service.User.SignInUser(request)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserDoesNotExist):
			errMsg = models.ErrUserDoesNotExist.Error()
		case errors.Is(err, models.ErrDBConn):
			errMsg = models.ErrDBConn.Error()
		case errors.Is(err, models.ErrWrongCreds):
			errMsg = models.ErrWrongCreds.Error()
		default:
			h.logger.Error("Error occurred while login: %s", err.Error())
			c.JSON(500, gin.H{
				"error": models.ErrInternalServerError.Error(),
			})
			return
		}
		h.logger.Error("Error occurred while login: %s", err.Error())
		c.JSON(401, gin.H{
			"error": errMsg,
		})
		return
	}
	response := &TokenResponse{
		AccessToken:  tokens.AccessToken.TokenValue,
		RefreshToken: tokens.RefreshToken.TokenValue,
	}
	c.JSON(200, gin.H{
		"tokens": response,
	})
}

//SignOut - function that handles sign out request. Function returns gin.H, and it takes gin.Context as an argument
func (h *Handler) SignOut(c *gin.Context) {
	userPublicID := c.Request.Header.Get("wt-user")
	if !IsValidUUID(userPublicID) {
		h.logger.Errorf("Error occurred while retrieveing headers")
		c.JSON(401, gin.H{
			"errors": models.ErrWrongUUIDFormat.Error(),
		})
		return
	}
	requestBody, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.Errorf("Error occurred while reading request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput.Error(),
		})
		return
	}
	var request RefreshTokenRequest
	err = json.Unmarshal(requestBody, &request)
	if err != nil {
		h.logger.Errorf("Error occurred while unmarshalling request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput.Error(),
		})
		return
	}
	var errMsg string
	err = h.service.User.SignOut(request.RefreshToken, userPublicID)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrTokenExpired):
			errMsg = models.ErrTokenExpired.Error()
		default:
			h.logger.Errorf("Error occurred while verifing token: %s", err.Error())
			c.JSON(500, gin.H{
				"error": models.ErrInternalServerError.Error(),
			})
			return
		}
		h.logger.Errorf("Error occurred while verifing token: %s", err.Error())
		c.JSON(401, gin.H{
			"error": errMsg,
		})
		return
	}
	c.JSON(200, gin.H{
		"response": true,
	})
}

//VerifyToken - function that handles verify token request. Function returns gin.H, and it takes gin.Context as an argument
func (h *Handler) VerifyToken(c *gin.Context) {
	requestBody, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.Errorf("Error occurred while reading request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput.Error(),
		})
		return
	}
	request := &VerifyTokenRequest{}
	h.logger.Info("Request body: %s", string(requestBody))
	err = json.Unmarshal(requestBody, &request)
	if err != nil {
		h.logger.Errorf("Error occurred while unmarshalling request body: %s", err.Error())
		c.JSON(401, gin.H{
			"error": models.ErrInvalidInput.Error(),
		})
		return
	}
	h.logger.Infof("Verifying token: %s", request.AccessToken)
	token, err := h.service.User.VerifyToken(request.AccessToken)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidToken):
			h.logger.Errorf("Error occurred while verifing token: %s", err.Error())
			c.JSON(401, gin.H{
				"error": models.ErrInvalidToken.Error(),
			})
			return
		default:
			h.logger.Errorf("Error occurred while verifing token: %s", err.Error())
			c.JSON(500, gin.H{
				"error": models.ErrInternalServerError.Error(),
			})
			return
		}
	}
	response := &VerifyTokenResponse{
		UserPublicID: token.UserPublicID,
	}
	c.JSON(200, gin.H{
		"response": response,
	})

}

//IsValidUUID - function that checks if string is valid UUID
func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil && u != ""
}

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validatePassword(pass string) bool {
	if len(pass) < 8 || len(pass) > 16 {
		return false
	}
	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	for _, char := range pass {
		switch {
		case char == 39 || char == 96 || char == 34: // ' ` " symbols in password
			return false
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasNumber && hasSpecial
}
