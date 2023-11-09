package auth

import (
	"testing"
)

func Test_UserIdentityVerifier(t *testing.T) {
	uv := NewUserIdentityVerifier()

	newConfigTrue := func() *Config {
		return &Config{
			UseIdentity: true,
		}
	}

	newConfigFalse := func() *Config {
		return &Config{
			UseIdentity: false,
		}
	}

	testData := map[string]struct {
		description string
		config      *Config
		email       string
		expected    bool
	}{
		"With identity": {
			config:   newConfigTrue(),
			email:    "test1@example.com",
			expected: true,
		},
		"Without identity": {
			config:   newConfigFalse(),
			email:    "test2@example.com",
			expected: true,
		},
	}

	for name, td := range testData {
		t.Run(name, func(t *testing.T) {
			uv.SetEmail(td.email)
			result, _, err := uv.CanLogin(td.email)
			if err != nil {
				t.Errorf("test %v: unexpected error: %v", name, err)
			}

			if result != td.expected {
				t.Errorf("test %v: result %v did not match expected %v", name, result, td.expected)
			}
		})
	}
}
