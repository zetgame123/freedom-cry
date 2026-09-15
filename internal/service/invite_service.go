package service

import (
	"errors"
	"strings"
	"time"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// RegisterWithInvite validates the invite code with row-level locking (FC-SEC-05),
// provisions a new anonymous user account, and activates a real subscription.
func (s *InviteService) RegisterWithInvite(rawCode string) (*InviteRegisterResponse, error) {
	code := strings.TrimSpace(rawCode)
	if code == "" {
		return nil, errors.New("invite code is required")
	}

	var resp *InviteRegisterResponse

	err := s.db.Transaction(func(tx *gorm.DB) error {
		var matchedInvite *models.InviteCode
		isMaster := false

		// 1. Check master invite code
		if s.cfg.App.MasterInviteCode != "" && strings.EqualFold(code, s.cfg.App.MasterInviteCode) {
			isMaster = true
		}

		// 2. If not master, look up in database with row-level locking
		if !isMaster {
			var invite models.InviteCode
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("LOWER(code) = LOWER(?) AND is_active = ?", code, true).
				First(&invite).Error
			if err != nil {
				return errors.New("invalid or expired invite code")
			}

			if invite.MaxUses > 0 && invite.UsesCount >= invite.MaxUses {
				tx.Model(&invite).Update("is_active", false)
				return errors.New("invite code has reached its usage limit")
			}

			matchedInvite = &invite
		}

		// 3. Create anonymous user account (Zero-Knowledge 16-digit account number)
		authResp, err := s.userServ.CreateAnonymousAccount()
		if err != nil {
			return err
		}

		// 4. Select subscription plan
		var plan models.Plan
		if matchedInvite != nil && matchedInvite.PlanID != nil {
			if err := tx.First(&plan, "id = ?", *matchedInvite.PlanID).Error; err != nil {
				if err := tx.Where("is_active = ?", true).Order("duration_days asc").First(&plan).Error; err != nil {
					return errors.New("no active plans available")
				}
			}
		} else {
			if err := tx.Where("is_active = ?", true).Order("duration_days asc").First(&plan).Error; err != nil {
				return errors.New("no active plans available")
			}
		}

		// 5. Create real subscription and provision client keys for all active nodes
		sub, err := s.subServ.CreateSubscription(authResp.User.ID, plan.ID)
		if err != nil {
			return err
		}

		// 6. Atomically increment usage count for DB invites
		if matchedInvite != nil {
			newUses := matchedInvite.UsesCount + 1
			isActive := true
			if matchedInvite.MaxUses > 0 && newUses >= matchedInvite.MaxUses {
				isActive = false
			}

			if err := tx.Model(matchedInvite).Updates(map[string]interface{}{
				"uses_count": newUses,
				"is_active":  isActive,
			}).Error; err != nil {
				return err
			}
		}

		resp = &InviteRegisterResponse{
			AccountNumber:     authResp.User.AccountNumber,
			Token:             authResp.Token,
			SubscriptionToken: sub.Token,
			PlanName:          plan.Name,
			ExpiresAt:         sub.ExpiresAt,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
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
