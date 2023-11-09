package auth

type UserVerifier struct {
	Uv IUserVerifier
}

func NewUserVerifier() *UserVerifier {
	return &UserVerifier{}
}

func (uv *UserVerifier) CanLogin(condition bool) bool {
	return condition
}
