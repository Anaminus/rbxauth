package rbxauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Each of these constants define the default value used when the corresponding
// Endpoint field in Config is an empty string.
const (
	DefaultLoginEndpoint  = "https://auth.roblox.com/v2/login"
	DefaultLogoutEndpoint = "https://auth.roblox.com/v2/logout"
	DefaultVerifyEndpoint = "https://auth.roblox.com/v2/twostepverification/verify"
	DefaultResendEndpoint = "https://auth.roblox.com/v2/twostepverification/resend"

	// The %d verb is replaced with a user ID.
	DefaultUserIDEndpoint = "https://api.roblox.com/users/%d"
)

const tokenHeader = "X-CSRF-TOKEN"

////////////////////////////////////////////////////////////////////////////////

// statusError represents an error derived from the status code of an HTTP
// response. It also wraps an API error response.
type statusError struct {
	code int
	resp error
}

// Error implements the error interface.
func (err statusError) Error() string {
	if err.resp == nil {
		return "http status " + strconv.Itoa(err.code) + ": " + http.StatusText(err.code)
	}
	return "http status " + strconv.Itoa(err.code) + ": " + err.resp.Error()
}

// Unwrap implements the Unwrap interface.
func (err statusError) Unwrap() error {
	return err.resp
}

// StatusCode returns the status code of the error.
func (err statusError) StatusCode() int {
	return err.code
}

// if Status wraps err in a statusError if code is not 2XX, and returns err
// otherwise.
func ifStatus(code int, err error) error {
	if code < 200 || code >= 300 {
		return &statusError{code: code, resp: err}
	}
	return err
}

////////////////////////////////////////////////////////////////////////////////

// Config configures an authentication action. Authentication endpoints must
// implement Roblox's Auth v2 API. When an endpoint is an empty string, the
// value of the corresponding Default constant is used instead.
type Config struct {
	// Client is used to make requests. If nil, the http.DefaultClient is used.
	Client *http.Client

	// Token is a string passed through requests to prevent cross-site request
	// forgery. The config automatically sets the this value from the previous
	// request.
	Token string

	// LoginEndpoint specifies the URL used for logging in.
	LoginEndpoint string
	// LogoutEndpoint specifies the URL used for logging out.
	LogoutEndpoint string
	// VerifyEndpoint specifies the URL used for verifying a two-step
	// authentication code.
	VerifyEndpoint string
	// ResendEndpoint specifies the URL used for resending a two-step
	// authentication code.
	ResendEndpoint string
	// UserIDEndpoint specifies the URL used to fetch a username from an ID. The
	// URL must contain a "%d" format verb, which is replaced with the user ID.
	UserIDEndpoint string
}

func (c *Config) requestAPI(req *http.Request, apiResp interface{}) (resp *http.Response, err error) {
	if c.Token != "" {
		req.Header.Set(tokenHeader, c.Token)
	}

	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if token := resp.Header.Get(tokenHeader); token != "" {
		c.Token = token
	}

	jd := json.NewDecoder(resp.Body)
	if err = jd.Decode(apiResp); err != nil {
		return resp, ifStatus(resp.StatusCode, err)
	}

	if e, ok := apiResp.(interface{ errResp() errorsResponse }); ok && e != nil {
		if errResp := e.errResp(); len(errResp.Errors) > 0 {
			if resp.StatusCode == 403 &&
				errResp.Errors[0].Code == 0 &&
				req.Header.Get(tokenHeader) == "" {
				// Failed token validation, retry with new token.
				return c.requestAPI(req.Clone(context.Background()), apiResp)
			}
			return nil, ifStatus(resp.StatusCode, errResp)
		}
	}

	return resp, ifStatus(resp.StatusCode, nil)
}

// LoginCred attempts to authenticate a user by using the provided credentials.
//
// The cred argument specifies the credentials associated with the account to be
// authenticated. As a special case, if the Type field is "UserID", then the
// Ident field is interpreted as an integer, indicating the user ID of the
// account. Note that an initial request must be made in order to associate the
// ID with its corresponding credentials.
//
// The password argument is specified as a slice for future compatibility, where
// the password may be handled within secured memory.
//
// On success, a list of HTTP cookies representing the session are returned. If
// multi-step authentication is required, then a Step object is additionally
// returned.
//
// If a response has a non-2XX status, then this function returns an error that
// implements `interface { StatusCode() int }`.
func (c Config) LoginCred(cred Cred, password []byte) (cookies []*http.Cookie, step *Step, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("login: %w", err)
		}
	}()

	if strings.ToLower(cred.Type) == "userid" {
		userID, err := strconv.ParseInt(cred.Ident, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("parse user ID: %w", err)
		}
		cred.Type = "Username"
		cred.Ident, err = c.getUsername(userID)
		if err != nil {
			return nil, nil, err
		}
	}

	body, _ := json.Marshal(&loginRequest{
		CredType:  cred.Type,
		CredValue: cred.Ident,
		Password:  string(password),
	})

	endpoint := c.LoginEndpoint
	if endpoint == "" {
		endpoint = DefaultLoginEndpoint
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var apiResp loginResponse
	resp, err := c.requestAPI(req, &apiResp)
	if err != nil {
		return nil, nil, err
	}

	if apiResp.TwoStepVerificationData != nil {
		step := &Step{
			cfg:       c,
			MediaType: apiResp.TwoStepVerificationData.MediaType,
			req: twoStepVerificationVerifyRequest{
				twoStepVerificationTicketRequest: twoStepVerificationTicketRequest{
					Username:   apiResp.User.Name,
					Ticket:     apiResp.TwoStepVerificationData.Ticket,
					ActionType: "Login",
				},
			},
		}
		return resp.Cookies(), step, nil
	}

	return resp.Cookies(), nil, nil
}

// Login wraps LoginCred, using a username for the credentials.
func (c Config) Login(username string, password []byte) ([]*http.Cookie, *Step, error) {
	return c.LoginCred(Cred{Type: Username, Ident: username}, password)
}

// LoginID wraps LoginCred, deriving credentials from the given user ID. Note
// that an initial request must be made in order to associate the ID with its
// corresponding credentials.
func (c Config) LoginID(userID int64, password []byte) ([]*http.Cookie, *Step, error) {
	username, err := c.getUsername(userID)
	if err != nil {
		return nil, nil, err
	}
	return c.LoginCred(Cred{Type: Username, Ident: username}, password)
}

func (c Config) Logout(cookies []*http.Cookie) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("logout: %w", err)
		}
	}()

	endpoint := c.LogoutEndpoint
	if endpoint == "" {
		endpoint = DefaultLogoutEndpoint
	}
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	_, err = c.requestAPI(req, &errorsResponse{})
	return err
}

func (c Config) getUsername(userID int64) (name string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("user from ID: %w", err)
		}
	}()
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := c.UserIDEndpoint
	if endpoint == "" {
		endpoint = DefaultUserIDEndpoint
	}
	req, err := http.NewRequest("GET", fmt.Sprintf(endpoint, userID), nil)
	if err != nil {
		return "", err
	}
	var apiResp struct {
		Username string
		errorsResponse
	}
	if _, err = c.requestAPI(req, &apiResp); err != nil {
		return "", err
	}
	return apiResp.Username, nil
}

////////////////////////////////////////////////////////////////////////////////

// These constants define canonical strings used for Cred.Type, and are known to
// be accepted by the Auth v2 API.
const (
	Username    string = "Username"    // The username associated with the account.
	Email       string = "Email"       // The email associated with the account.
	PhoneNumber string = "PhoneNumber" // The phone number associated with the account.
)

// Cred holds credentials used to identify an account.
type Cred struct {
	Type  string // Type specifies the kind of identifier.
	Ident string // Ident is the identifier itself.
}
