// The rbxauth package is a wrapper for the Roblox authentication API (v2).
//
// https://auth.roblox.com/docs
//
package rbxauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// DefaultHost defines the default host to use when none is specified.
const DefaultHost = "roblox.com"

const authSubdomain = "auth"
const loginPath = "/v2/login"
const logoutPath = "/v2/logout"
const verifyPath = "/v2/twostepverification/verify"
const resendPath = "/v2/twostepverification/resend"

func buildURL(sub, host, path string) *url.URL {
	if host == "" {
		host = DefaultHost
	}
	return &url.URL{
		Scheme: "https",
		Host:   sub + "." + host,
		Path:   path,
	}
}

type errorResponse struct {
	errors Errors `json: ",omitempty"`
}

// Config configures an authentication action.
type Config struct {
	// Host is the domain on which to authenticate. Interpreted as DefaultHost
	// if empty.
	Host string
}

type userInfo struct {
	id   int64
	name string
}

type twoStepInfo struct {
	mediaType string
	ticket    string
}

type loginResponse struct {
	user                    *userInfo
	twoStepVerificationData *twoStepInfo
}

// Cred holds information used to identify an account.
type Cred struct {
	// Type specifies the kind of identifier. The following types are known to
	// be accepted by the auth API:
	//
	//     "Username"    : The username associated with the account.
	//     "Email"       : The email associated with the account.
	//     "PhoneNumber" : The phone number associated with the account.
	//
	Type string
	// Ident is the identifier itself.
	Ident string
}

// LoginCred attempts to authenticate a user by using the provided
// credentials.
//
// The cred argument specifies the credentials associated with the account to
// be authenticated. As a special case, if the Type field is "UserID", then
// the Ident field is interpreted as an integer, indicating the user ID of the
// account.
//
// The password argument is specified as a slice for future compatibility,
// where the password may be handled within secured memory.
//
// If multi-step authentication is required, then a Step object is returned.
// Otherwise, HTTP cookies representing the session are returned.
func (cfg *Config) LoginCred(cred Cred, password []byte) ([]*http.Cookie, *Step, error) {
	host := cfg.Host

	if strings.ToLower(cred.Type) == "UserID" {
		userID, err := strconv.ParseInt(cred.Ident, 10, 64)
		if err != nil {
			return nil, nil, err
		}
		cred.Type = "Username"
		cred.Ident, err = getUsername(host, userID)
		if err != nil {
			return nil, nil, err
		}
	}

	type loginRequest struct {
		ctype    string `json: ",omitempty"`
		cvalue   string `json: ",omitempty"`
		password string `json: ",omitempty"`
	}
	body, _ := json.Marshal(&loginRequest{
		ctype:    cred.Type,
		cvalue:   cred.Ident,
		password: string(password),
	})

	req, err := http.NewRequest(
		"POST",
		buildURL(authSubdomain, host, loginPath).String(),
		bytes.NewReader(body),
	)
	if err != nil {
		// Bad URL.
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	jd := json.NewDecoder(resp.Body)
	var apiResp struct {
		loginResponse
		errorResponse
	}
	if err = jd.Decode(&apiResp); err != nil {
		return nil, nil, err
	}

	if len(apiResp.errors) > 0 {
		return nil, nil, apiResp.errors
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return nil, nil, StatusError(resp.StatusCode)
	}

	if apiResp.twoStepVerificationData != nil {
		step := &Step{
			cfg:       Config{Host: host}, // ensure host isn't mutated.
			MediaType: apiResp.twoStepVerificationData.mediaType,
			req: stepRequest{
				resendRequest: resendRequest{
					username:   apiResp.user.name,
					ticket:     apiResp.twoStepVerificationData.ticket,
					actionType: "Login",
				},
			},
		}
		return nil, step, nil
	}

	return resp.Cookies(), nil, nil
}

// Login wraps LoginCred, using a username for the credentials.
func (cfg *Config) Login(username string, password []byte) ([]*http.Cookie, *Step, error) {
	return cfg.LoginCred(Cred{Type: "Username", Ident: username}, password)
}

func getUsername(host string, userID int64) (string, error) {
	const apiSubdomain = "api"
	const usersPath = "/users"
	client := &http.Client{}
	resp, err := client.Get(
		buildURL(apiSubdomain, host, usersPath+"/"+strconv.FormatInt(userID, 10)).String(),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	type userResponse struct {
		Username string
		errorResponse
	}
	jd := json.NewDecoder(resp.Body)
	var apiResp userResponse
	if err = jd.Decode(&apiResp); err != nil {
		return "", err
	}

	if len(apiResp.errors) > 0 {
		return "", apiResp.errors
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return "", StatusError(resp.StatusCode)
	}

	return apiResp.Username, nil
}

// LoginID wraps LoginCred, deriving credentials from the given user ID.
func (cfg *Config) LoginID(userID int64, password []byte) ([]*http.Cookie, *Step, error) {
	username, err := getUsername(cfg.Host, userID)
	if err != nil {
		return nil, nil, err
	}
	return cfg.LoginCred(Cred{Type: "Username", Ident: username}, password)
}

// Logout destroys the session associated with the given cookies, ensuring
// that the account has been logged out.
func (cfg *Config) Logout(cookies []*http.Cookie) error {
	req, err := http.NewRequest(
		"POST",
		buildURL(authSubdomain, cfg.Host, logoutPath).String(),
		nil,
	)
	if err != nil {
		// Bad URL.
		return err
	}
	req.Header.Set("Accept", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	jd := json.NewDecoder(resp.Body)
	var apiResp errorResponse
	if err = jd.Decode(&apiResp); err != nil {
		return err
	}

	if len(apiResp.errors) > 0 {
		return apiResp.errors
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return StatusError(resp.StatusCode)
	}

	return nil
}

// Errors represents a list of errors returned from an API response.
type Errors []Error

// Error implements the error interface.
func (errs Errors) Error() string {
	s := make([]string, len(errs))
	for i, err := range errs {
		s[i] = err.Error()
	}
	return strings.Join(s, "; ")
}

// Error represents an error return from an API response.
type Error struct {
	Code    int    `json: "code"`
	Message string `json: "message"`
}

// Error implements the error interface.
func (err Error) Error() string {
	return strconv.Itoa(err.Code) + ": " + err.Message
}

// StatusError represents an error derived from the status code of an HTTP
// response.
type StatusError int

// Error implements the error interface.
func (err StatusError) Error() string {
	return strconv.Itoa(int(err)) + ": " + http.StatusText(int(err))
}

// Step holds the state of a multi-step verification action.
type Step struct {
	cfg Config
	req stepRequest

	// MediaType indicates the means by which the verification code was sent.
	MediaType string
}

type stepRequest struct {
	resendRequest
	code           string `json: ",omitempty"`
	rememberDevice bool   `json: ",omitempty"`
}

type resendRequest struct {
	username   string `json: ",omitempty"`
	ticket     string `json: ",omitempty"`
	actionType string `json: ",omitempty"`
}

// Verify receives a verification code to complete authentication. If
// successful, returns HTTP cookies representing the authenticated session.
//
// The remember argument specifies whether the current device should be
// remembered for future authentication.
func (s *Step) Verify(code string, remember bool) ([]*http.Cookie, error) {
	apiReq := s.req
	apiReq.code = code
	apiReq.rememberDevice = remember
	body, _ := json.Marshal(&apiReq)

	req, err := http.NewRequest(
		"POST",
		buildURL(authSubdomain, s.cfg.Host, verifyPath).String(),
		bytes.NewReader(body),
	)
	if err != nil {
		// Bad URL.
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jd := json.NewDecoder(resp.Body)
	var apiResp errorResponse
	if err = jd.Decode(&apiResp); err != nil {
		return nil, err
	}

	if len(apiResp.errors) > 0 {
		return nil, apiResp.errors
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return nil, StatusError(resp.StatusCode)
	}

	return resp.Cookies(), nil
}

// Resend retransmits a two-step verification message.
func (s *Step) Resend() error {
	body, _ := json.Marshal(&s.req.resendRequest)

	req, err := http.NewRequest(
		"POST",
		buildURL(authSubdomain, s.cfg.Host, resendPath).String(),
		bytes.NewReader(body),
	)
	if err != nil {
		// Bad URL.
		return err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	jd := json.NewDecoder(resp.Body)
	var apiResp struct {
		twoStepInfo
		errorResponse
	}
	if err = jd.Decode(&apiResp); err != nil {
		return err
	}

	if len(apiResp.errors) > 0 {
		return apiResp.errors
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return StatusError(resp.StatusCode)
	}

	s.MediaType = apiResp.mediaType
	s.req.ticket = apiResp.ticket

	return nil
}
