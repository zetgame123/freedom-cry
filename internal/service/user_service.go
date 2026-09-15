package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewUserService(db *gorm.DB, cfg *config.Config) *UserService {
	return &UserService{db: db, cfg: cfg}
}

type RegisterDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
}

func (s *UserService) Register(dto RegisterDTO) (*AuthResponse, error) {
	var count int64
	s.db.Model(&models.User{}).Where("email = ?", dto.Email).Count(&count)
	if count > 0 {
		return nil, errors.New("user with this email already exists")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := models.User{
		Email:        dto.Email,
		PasswordHash: string(hashed),
		Role:         models.RoleUser,
		Balance:      0.00,
		IsActive:     true,
	}

	if err := s.db.Create(&user).Error; err != nil {
		return nil, err
	}

	token, err := s.generateJWT(&user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{Token: token, User: &user}, nil
}

func (s *UserService) Login(dto LoginDTO) (*AuthResponse, error) {
	var user models.User
	if err := s.db.Where("email = ?", dto.Email).First(&user).Error; err != nil {
		return nil, errors.New("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(dto.Password)); err != nil {
		return nil, errors.New("invalid email or password")
	}

	if !user.IsActive {
		return nil, errors.New("account is suspended")
	}

	token, err := s.generateJWT(&user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{Token: token, User: &user}, nil
}

// NormalizeAccountNumber cleans spaces and hyphens and returns XXXX-XXXX-XXXX-XXXX
func NormalizeAccountNumber(raw string) string {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(raw, "-", ""), " ", "")
	if len(cleaned) == 16 {
		return fmt.Sprintf("%s-%s-%s-%s", cleaned[0:4], cleaned[4:8], cleaned[8:12], cleaned[12:16])
	}
	return raw
}

// CreateAnonymousAccount creates a Mullvad-style Zero-Knowledge account with a 16-digit account number.
// No email or password is required.
func (s *UserService) CreateAnonymousAccount() (*AuthResponse, error) {
	accNum, err := models.GenerateAccountNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate account number: %w", err)
	}

	user := models.User{
		AccountNumber: accNum,
		Role:          models.RoleUser,
		Balance:       0.00,
		IsActive:      true,
	}

	if err := s.db.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	token, err := s.generateJWT(&user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{Token: token, User: &user}, nil
}

// LoginByAccountNumber authenticates a user using only their 16-digit account number
func (s *UserService) LoginByAccountNumber(rawAccount string) (*AuthResponse, error) {
	norm := NormalizeAccountNumber(rawAccount)
	var user models.User
	if err := s.db.Where("account_number = ?", norm).First(&user).Error; err != nil {
		return nil, errors.New("invalid account number")
	}

	if !user.IsActive {
		return nil, errors.New("account is suspended")
	}

	token, err := s.generateJWT(&user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{Token: token, User: &user}, nil
}

func (s *UserService) GetByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := s.db.Preload("Subscriptions.Plan").First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserService) generateJWT(user *models.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":            user.ID.String(),
		"account_number": user.AccountNumber,
		"role":           string(user.Role),
		"exp":            time.Now().Add(s.cfg.JWT.Expiry).Unix(),
		"iat":            time.Now().Unix(),
	}
	if user.Email != "" {
		claims["email"] = user.Email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.Secret))
}

// HardDeleteUser physically purges all user data from PostgreSQL (GDPR Right-to-be-Forgotten / Privacy Hardening).
// Permanently erases user identity, subscriptions, client keys, and billing records without leaving soft-deleted rows.
func (s *UserService) HardDeleteUser(userID uuid.UUID) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var subIDs []uuid.UUID
		if err := tx.Model(&models.Subscription{}).Unscoped().Where("user_id = ?", userID).Pluck("id", &subIDs).Error; err != nil {
			return err
		}

		if len(subIDs) > 0 {
			if err := tx.Unscoped().Where("subscription_id IN ?", subIDs).Delete(&models.ClientKey{}).Error; err != nil {
				return err
			}
		}

		if err := tx.Unscoped().Where("user_id = ?", userID).Delete(&models.Subscription{}).Error; err != nil {
			return err
		}

		if err := tx.Unscoped().Where("user_id = ?", userID).Delete(&models.Transaction{}).Error; err != nil {
			return err
		}

		res := tx.Unscoped().Where("id = ?", userID).Delete(&models.User{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New("user not found")
		}

		return nil
	})
}
