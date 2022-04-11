package service

import (
	"crypto/sha1"
	"fmt"
	todo "restApiTest"
	"restApiTest/pkg/repository"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	salt       = "sgsfhru45y3n"
	signingKey = "eryq4623hejhetw"
	tokenTTL   = 12 * time.Hour
)

type AuthService struct {
	repo repository.Authorization
}

func NewAuthService(repo repository.Authorization) *AuthService {
	return &AuthService{repo: repo}
}
func (s *AuthService) CreateUser(user todo.User) (int, error) {
	user.Password = generatePasswordHash(user.Password)
	return s.repo.CreateUser(user)
}
func (s *AuthService) GenerateToken(username, password string) (string, error) {
	user, err := s.repo.GetUser(username, generatePasswordHash(password))
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(12 * time.Hour).Unix(), // токен перестанет быть валидным через 12 часов
		IssuedAt:  time.Now().Unix(),                     //время генерации токена
	})
	return token.SignedString([]byte(signingKey))
}

func generatePasswordHash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))
	return fmt.Sprintf("%x", hash.Sum([]byte(salt)))
}
