# FSA

F***ing Simple Auth. A simple authentication library for Go.

Send email verification codes. Get JWT tokens.

## Usage

- Create a new instance of the authenticator
  - `New()` takes in a Config (defined in auth.go), a database connection (for code storage), a user creator, a mailer, and a Go Template - these should implement IAuthDb, IUserCreator, and ICodeSender
  - `NewWithMemDbAndDefaultTemplate()` takes in a Config, a user creator and a mailer, and uses an in-memory database, and the default template
- There is a chi middleware which can be wired up with the Config (call `NewAuthMiddleware`) to verify JWTs
- `LoginStep1SendVerificationCode` sends a verification code to the passed email address
- `LoginStep2ConfirmCode` takes in an email and a code, calls the CreatUserIfNotExists on IUserCreator, and returns a JWT if the code is accepted
  - This JWT contains AccessToken and RefreshToken which both contain email and expiry claims only (This is deliberately kept lightweight)

## IAuthDb
This is an interface which should satisfy the requirement for storing and retrieving codes. Out of the box you can use NewWithMemDbAndDefaultTemplate() to get an in-memory implementation.

## IUserCreator
This is an interface which should satisfy the requirement for creating a user in your system, if they don't already exist.

## ICodeSender
This is an interface which should satisfy the requirement for sending a code to a user, for example it could send to a queue, or via SMTP/SMS API.

## Todo

- [ ] Pass in CORS config to the middleware
- [ ] Store/invalidate used refresh tokens
- [ ] Add a simple sender implementation for SMTP (Mailhog is a good option for testing)