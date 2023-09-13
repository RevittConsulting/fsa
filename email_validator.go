package auth

import (
	"net/mail"
)

type EmailValidator struct {
	Ev IEmailValidator
}

func NewEmailValidator() *EmailValidator {
	return &EmailValidator{}
}

func (ev *EmailValidator) Validate(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
