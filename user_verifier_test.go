package auth

import (
	"testing"
)

func Test_UserVerifier(t *testing.T) {
	uv := NewUserVerifier()

	newConfigTrue := func() *Config {
		return &Config{
			AllowAllLogins: true,
		}
	}

	newConfigFalse := func() *Config {
		return &Config{
			AllowAllLogins: false,
		}
	}

	if uv.CanLogin(true) != true {
		t.Errorf("Expected: %v, Actual: %v", true, uv.CanLogin(true))
	}

	if uv.CanLogin(false) != false {
		t.Errorf("Expected: %v, Actual: %v", false, uv.CanLogin(false))
	}

	if uv.CanLogin(newConfigTrue().AllowAllLogins) != true {
		t.Errorf("Expected: %v, Actual: %v", true, uv.CanLogin(newConfigTrue().AllowAllLogins))
	}

	if uv.CanLogin(newConfigFalse().AllowAllLogins) != false {
		t.Errorf("Expected: %v, Actual: %v", false, uv.CanLogin(newConfigFalse().AllowAllLogins))
	}
}
