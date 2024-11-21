package models

import (
	"github.com/google/uuid"
)

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
}

func (u *User) GenerateUUID() {
	u.ID = uuid.New()
}
