package auth

type UserIdentityVerifier struct {
	Uv IUserIdentityVerifier

	email string
}

func (uv *UserIdentityVerifier) SetEmail(email string) {
	uv.email = email
}

func NewUserIdentityVerifier() *UserIdentityVerifier {
	return &UserIdentityVerifier{}
}

func (uv *UserIdentityVerifier) CanLogin(email string) (bool, string, error) {
	if email == uv.email {
		return true, "", nil
	}
	return false, "user not found", nil
}
