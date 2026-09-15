package service

import (
	"errors"
	"strings"
	"time"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type InviteService struct {
	db       *gorm.DB
	cfg      *config.Config
	userServ *UserService
	subServ  *SubscriptionService
}

func NewInviteService(db *gorm.DB, cfg *config.Config, userServ *UserService, subServ *SubscriptionService) *InviteService {
	return &InviteService{
		db:       db,
		cfg:      cfg,
		userServ: userServ,
		subServ:  subServ,
	}
}

type InviteRegisterResponse struct {
	AccountNumber     string    `json:"account_number"`
	Token             string    `json:"token"`
	SubscriptionToken string    `json:"subscription_token"`
	PlanName          string    `json:"plan_name"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// RegisterWithInvite validates the invite code, provisions a new anonymous user account,
// and activates a real subscription with cryptographic keys for all available server nodes.
func (s *InviteService) RegisterWithInvite(rawCode string) (*InviteRegisterResponse, error) {
	code := strings.TrimSpace(rawCode)
	if code == "" {
		return nil, errors.New("invite code is required")
	}

	var matchedInvite *models.InviteCode
	isMaster := false

	// 1. Check master invite code
	if s.cfg.App.MasterInviteCode != "" && strings.EqualFold(code, s.cfg.App.MasterInviteCode) {
		isMaster = true
	}

	// 2. If not master, look up in database
	if !isMaster {
		var invite models.InviteCode
		err := s.db.Where("LOWER(code) = LOWER(?) AND is_active = ?", code, true).First(&invite).Error
		if err != nil {
			return nil, errors.New("invalid or expired invite code")
		}

		if invite.MaxUses > 0 && invite.UsesCount >= invite.MaxUses {
			s.db.Model(&invite).Update("is_active", false)
			return nil, errors.New("invite code has reached its usage limit")
		}

		matchedInvite = &invite
	}

	// 3. Create anonymous user account (Zero-Knowledge 16-digit account number)
	authResp, err := s.userServ.CreateAnonymousAccount()
	if err != nil {
		return nil, err
	}

	// 4. Select subscription plan
	var plan models.Plan
	if matchedInvite != nil && matchedInvite.PlanID != nil {
		if err := s.db.First(&plan, "id = ?", *matchedInvite.PlanID).Error; err != nil {
			if err := s.db.Where("is_active = ?", true).Order("duration_days asc").First(&plan).Error; err != nil {
				return nil, errors.New("no active plans available")
			}
		}
	} else {
		if err := s.db.Where("is_active = ?", true).Order("duration_days asc").First(&plan).Error; err != nil {
			return nil, errors.New("no active plans available")
		}
	}

	// 5. Create real subscription and provision client keys for all active nodes
	sub, err := s.subServ.CreateSubscription(authResp.User.ID, plan.ID)
	if err != nil {
		return nil, err
	}

	// 6. Increment usage count for DB invites
	if matchedInvite != nil {
		s.db.Model(matchedInvite).Updates(map[string]interface{}{
			"uses_count": gorm.Expr("uses_count + 1"),
			"is_active":  gorm.Expr("CASE WHEN max_uses > 0 AND uses_count + 1 >= max_uses THEN false ELSE true END"),
		})
	}

	return &InviteRegisterResponse{
		AccountNumber:     authResp.User.AccountNumber,
		Token:             authResp.Token,
		SubscriptionToken: sub.Token,
		PlanName:          plan.Name,
		ExpiresAt:         sub.ExpiresAt,
	}, nil
}

// ValidateInvite checks if a given invite code is currently valid without consuming it.
func (s *InviteService) ValidateInvite(rawCode string) (bool, error) {
	code := strings.TrimSpace(rawCode)
	if code == "" {
		return false, nil
	}
	if s.cfg.App.MasterInviteCode != "" && strings.EqualFold(code, s.cfg.App.MasterInviteCode) {
		return true, nil
	}

	var invite models.InviteCode
	err := s.db.Where("LOWER(code) = LOWER(?) AND is_active = ?", code, true).First(&invite).Error
	if err != nil {
		return false, nil
	}
	if invite.MaxUses > 0 && invite.UsesCount >= invite.MaxUses {
		return false, nil
	}
	return true, nil
}

// CreateInvite creates a new invite code with custom usage limit.
func (s *InviteService) CreateInvite(code, description string, maxUses int, planID *uuid.UUID) (*models.InviteCode, error) {
	var err error
	if code == "" {
		code, err = models.GenerateInviteCode("FC")
		if err != nil {
			return nil, err
		}
	}

	invite := models.InviteCode{
		Code:        code,
		Description: description,
		MaxUses:     maxUses,
		UsesCount:   0,
		IsActive:    true,
		PlanID:      planID,
	}

	if err := s.db.Create(&invite).Error; err != nil {
		return nil, err
	}

	return &invite, nil
}

// ListInvites retrieves all invite codes for admin dashboard.
func (s *InviteService) ListInvites() ([]models.InviteCode, error) {
	var list []models.InviteCode
	if err := s.db.Preload("Plan").Order("created_at desc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

// RevokeInvite deactivates an invite code.
func (s *InviteService) RevokeInvite(id uuid.UUID) error {
	return s.db.Model(&models.InviteCode{}).Where("id = ?", id).Update("is_active", false).Error
}
