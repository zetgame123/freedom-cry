package service

import (
	"errors"
	"fmt"

	"freedom-cry/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BillingService struct {
	db      *gorm.DB
	subServ *SubscriptionService
}

func NewBillingService(db *gorm.DB, subServ *SubscriptionService) *BillingService {
	return &BillingService{db: db, subServ: subServ}
}

type DepositDTO struct {
	UserID   uuid.UUID `json:"user_id"`
	Amount   float64   `json:"amount" binding:"required,gt=0"`
	Provider string    `json:"provider" binding:"required"` // "stars", "crypto", "manual"
}

func (s *BillingService) CreateDeposit(dto DepositDTO) (*models.Transaction, error) {
	tx := models.Transaction{
		UserID:      dto.UserID,
		Amount:      dto.Amount,
		Currency:    "RUB",
		Description: fmt.Sprintf("Account balance top-up via %s", dto.Provider),
		Provider:    dto.Provider,
		Status:      models.TxPending,
	}

	if err := s.db.Create(&tx).Error; err != nil {
		return nil, err
	}

	return &tx, nil
}

func (s *BillingService) CompleteDeposit(txID uuid.UUID, providerTxID string) (*models.Transaction, error) {
	var transaction models.Transaction

	err := s.db.Transaction(func(dbTx *gorm.DB) error {
		if err := dbTx.First(&transaction, "id = ?", txID).Error; err != nil {
			return errors.New("transaction not found")
		}

		if transaction.Status == models.TxCompleted {
			return errors.New("transaction already completed")
		}

		transaction.Status = models.TxCompleted
		transaction.ProviderTxID = providerTxID

		if err := dbTx.Save(&transaction).Error; err != nil {
			return err
		}

		// Update user balance
		if err := dbTx.Model(&models.User{}).
			Where("id = ?", transaction.UserID).
			Update("balance", gorm.Expr("balance + ?", transaction.Amount)).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &transaction, nil
}

func (s *BillingService) PurchaseSubscription(userID, planID uuid.UUID) (*models.Subscription, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		return nil, errors.New("user not found")
	}

	var plan models.Plan
	if err := s.db.First(&plan, "id = ?", planID).Error; err != nil {
		return nil, errors.New("plan not found")
	}

	if user.Balance < plan.Price {
		return nil, fmt.Errorf("insufficient balance: need %.2f, currently have %.2f", plan.Price, user.Balance)
	}

	var subscription *models.Subscription

	err := s.db.Transaction(func(dbTx *gorm.DB) error {
		// Deduct balance
		res := dbTx.Model(&models.User{}).
			Where("id = ? AND balance >= ?", userID, plan.Price).
			Update("balance", gorm.Expr("balance - ?", plan.Price))
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New("insufficient balance or concurrency conflict")
		}

		// Log transaction
		txRecord := models.Transaction{
			UserID:      userID,
			Amount:      plan.Price,
			Currency:    "RUB",
			Description: fmt.Sprintf("Purchased subscription '%s'", plan.Name),
			Provider:    "balance",
			Status:      models.TxCompleted,
		}
		if err := dbTx.Create(&txRecord).Error; err != nil {
			return err
		}

		var err error
		subscription, err = s.subServ.CreateSubscription(userID, planID)
		return err
	})

	if err != nil {
		return nil, err
	}

	return subscription, nil
}
