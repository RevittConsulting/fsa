package fsa

import (
	"sync"
	"time"
)

type Db struct {
	mu sync.Mutex
}

func NewMemDb() *Db {
	return &Db{}
}

type Code struct {
	Code      string
	ExpiresAt time.Time
}

var vercodemap = make(map[string]*Code)

func (d *Db) StoreVerificationCode(email string, code string, expiresAt time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	vercodemap[email] = &Code{
		Code:      code,
		ExpiresAt: expiresAt,
	}
	return nil
}

func (d *Db) GetVerificationCode(email string) (string, time.Time, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	code := vercodemap[email]

	if code == nil {
		return "", time.Time{}, nil
	}

	if code.ExpiresAt.Before(time.Now()) {
		return "", time.Time{}, nil
	}

	delete(vercodemap, email)

	return code.Code, code.ExpiresAt, nil
}

func (d *Db) RemoveVerificationCode(email string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(vercodemap, email)
	return nil
}
