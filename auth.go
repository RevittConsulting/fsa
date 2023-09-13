package auth

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"bytes"
	"context"
	"github.com/golang-jwt/jwt/v4"
	"html/template"
	"path/filepath"
	"runtime"
)

type IAuthDb interface {
	StoreVerificationCode(email string, code string, expiresAt time.Time) error
	GetVerificationCode(email string) (code string, expiresAt time.Time, error error)
	RemoveVerificationCode(email string) error
}

type IUserCreator interface {
	CreateEmailVerifiedUserIfNotExists(ctx context.Context, email string) (newUser bool, err error)
}

type ICodeSender interface {
	Send(to string, subject string, body string) error
}

type IEmailValidator interface {
	Validate(email string) bool
}

type Key string

const ClaimsKey Key = "claims"
const UserEmailKey Key = "userEmail"

type Config struct {
	AppName string

	CodeValidityPeriod         time.Duration
	AccessTokenValidityPeriod  time.Duration
	RefreshTokenValidityPeriod time.Duration

	AccessTokenSecret  string
	RefreshTokenSecret string

	RateLimitPerSecond int

	ReturnUrls []string
}

type Token struct {
	Token       string
	TokenExpiry time.Time
}

type TokenResponse struct {
	AccessToken  *Token
	RefreshToken *Token
}

type EmailData struct {
	Link       string
	Code       string
	AppName    string
	AppNameL1  string
	AppNameEnd string
}

type Auth struct {
	Db     IAuthDb
	Sender ICodeSender
	Uc     IUserCreator
	Ev     IEmailValidator

	EmailTemplate *template.Template

	Cfg *Config
}

func New(db IAuthDb, sender ICodeSender, uc IUserCreator, ev IEmailValidator, et *template.Template, cfg *Config) *Auth {
	return &Auth{
		Db:     db,
		Sender: sender,
		Uc:     uc,
		Ev:     ev,

		EmailTemplate: et,

		Cfg: cfg,
	}
}

func NewWithMemDbAndDefaultTemplate(sender ICodeSender, uc IUserCreator, cfg *Config) *Auth {
	return New(NewMemDb(), sender, uc, NewEmailValidator(), nil, cfg)
}

func (a *Auth) LoginStep1SendVerificationCode(ctx context.Context, email, returnUrl string) error {

	validEmail := a.Ev.Validate(email)
	if !validEmail {
		return fmt.Errorf("invalid email")
	}

	code := generateCode()
	expiresAt := time.Now().Add(a.Cfg.CodeValidityPeriod)

	err := a.Db.StoreVerificationCode(email, code, expiresAt)
	if err != nil {
		return err
	}

	// send the code
	link := fmt.Sprintf("%s?code=%s&email=%s", returnUrl, code, email)
	body := a.ParseTemplate(link, code)
	err = a.Sender.Send(email, "Login Verification Code", body)
	if err != nil {
		err = a.Db.RemoveVerificationCode(email)
		return err
	}

	return nil
}

func (a *Auth) LoginStep2ConfirmCode(ctx context.Context, email string, code string) (bool, *TokenResponse, error) {
	dbCode, expiresAt, err := a.Db.GetVerificationCode(email)
	if err != nil {
		return false, nil, err
	}

	if code != dbCode {
		return false, nil, nil
	}
	if expiresAt.Before(time.Now()) {
		return false, nil, nil
	}

	// create user if not exists
	_, err = a.Uc.CreateEmailVerifiedUserIfNotExists(ctx, email)
	if err != nil {
		return false, nil, err
	}

	accessToken, err := createToken(map[string]interface{}{
		"email": email,
	}, a.Cfg.AccessTokenSecret, a.Cfg.AccessTokenValidityPeriod)
	if err != nil {
		return false, nil, err
	}

	refreshToken, err := createRefreshToken(email, a.Cfg.RefreshTokenSecret, a.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		return false, nil, err
	}

	return true, &TokenResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}, nil
}

func (a *Auth) RefreshToken(ctx context.Context, rt string) (*TokenResponse, error) {
	token, err := jwt.Parse(rt, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.Cfg.RefreshTokenSecret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	accessToken, err := createToken(map[string]interface{}{
		"email": email,
	}, a.Cfg.AccessTokenSecret, a.Cfg.AccessTokenValidityPeriod)
	if err != nil {
		return nil, err
	}

	refreshToken, err := createRefreshToken(email, a.Cfg.RefreshTokenSecret, a.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}, nil
}

func generateCode() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	var code string
	for i := 0; i < 6; i++ {
		code += strconv.Itoa(r.Intn(10))
	}
	return code
}

func createToken(claims map[string]interface{}, secret string, validityPeriod time.Duration) (*Token, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	expiresAt := time.Now().Add(validityPeriod)

	claims["exp"] = expiresAt.Unix()
	token.Claims = jwt.MapClaims(claims)

	mySigningKey := []byte(secret)
	str, err := token.SignedString(mySigningKey)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:       str,
		TokenExpiry: expiresAt,
	}, nil
}

func createRefreshToken(email, secret string, validityPeriod time.Duration) (*Token, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	expiresAt := time.Now().Add(validityPeriod)

	claims := jwt.MapClaims{
		"email": email,
		"exp":   expiresAt.Unix(),
	}
	token.Claims = claims

	mySigningKey := []byte(secret)
	str, err := token.SignedString(mySigningKey)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:       str,
		TokenExpiry: expiresAt,
	}, nil
}

func (a *Auth) ParseTemplate(link, code string) string {
	data := EmailData{
		Link:    link,
		Code:    code,
		AppName: a.Cfg.AppName,
	}

	r := []rune(a.Cfg.AppName)
	data.AppNameL1 = string(r[0])
	data.AppNameEnd = string(r[1:])

	tpl := a.EmailTemplate

	if a.EmailTemplate == nil {
		_, filename, _, ok := runtime.Caller(0)
		if !ok {
			panic("No caller information")
		}
		templatePath := filepath.Join(filepath.Dir(filename), "email_template.gohtml")
		var err error
		tpl, err = template.ParseFiles(templatePath)
		if err != nil {
			panic(err)
		}
	}

	var body bytes.Buffer
	err := tpl.ExecuteTemplate(&body, "email", data)
	if err != nil {
		panic(err)
	}

	return body.String()
}
