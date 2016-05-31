package rbxauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

const (
	defaultHost = `www.roblox.com`
	loginPath   = `/Services/Secure/LoginService.asmx/ValidateLogin`
	logoutPath  = `/authentication/logout`
)

var ErrLoggedIn = errors.New("client is already logged in")

type ErrLoginFailed struct {
	ErrorCode string
	Message   string
}

func (err ErrLoginFailed) Error() string {
	return fmt.Sprintf("error code %s: \"%s\"", err.ErrorCode, err.Message)
}

type ErrStatus int

func (err ErrStatus) Error() string {
	return fmt.Sprintf("%d: %s", int(err), http.StatusText(int(err)))
}

// assertStatus checks whether a HTTP response has a non-2XX status code. The
// response body is closed in this case.
func assertStatus(resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return resp, err
	}
	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		resp.Body.Close()
		return resp, ErrStatus(resp.StatusCode)
	}
	return resp, nil
}

// Client is used to perform various authentication methods for Roblox, such
// as logging in to a user account. Client embeds a http.Client.
type Client struct {
	http.Client
}

// Login securely logs a user in by setting session cookies on the client.
//
// The host argument is the website to login to. Defaults to "www.roblox.com"
// if left empty.
func (client *Client) Login(host, username string, password []byte) (err error) {
	// Set default host.
	if host == "" {
		host = defaultHost
	}

	loginURL := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   loginPath,
	}

	// Make sure client isn't already logged in.
	if client.Jar == nil {
		client.Jar, _ = cookiejar.New(&cookiejar.Options{})
	}
	cookies := client.Jar.Cookies(loginURL)
	for _, cookie := range cookies {
		if cookie.Name == ".ROBLOSECURITY" {
			return ErrLoggedIn
		}
	}

	// Build login request body.
	type loginReq struct {
		UserName        string `json:"userName"`
		Password        string `json:"password"`
		IsCaptchaOn     bool   `json:"isCaptchaOn"`
		Challenge       string `json:"challenge"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	reqBody, _ := json.Marshal(&loginReq{
		UserName:        username,
		Password:        string(password),
		IsCaptchaOn:     false,
		Challenge:       "",
		CaptchaResponse: "",
	})

	// Do login request.
	req, _ := http.NewRequest("POST", loginURL.String(), bytes.NewReader(reqBody))
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	resp, err := assertStatus(client.Do(req))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read login response.
	type loginRespSub struct {
		SLTranslate string `json:"sl_translate"`
		IsValid     bool   `json:"IsValid"`
		Message     string `json:"Message"`
		ErrorCode   string `json:"ErrorCode"`
	}
	type loginResp struct {
		D loginRespSub `json:"d"`
	}
	respData := loginResp{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return err
	}
	if !respData.D.IsValid {
		return &ErrLoginFailed{ErrorCode: respData.D.ErrorCode, Message: respData.D.Message}
	}

	return nil
}

// Logout logs the client out of the current user account by requesting from
// the website to clear session cookies. No error is returned if the client is
// not already logged in.
//
// The host argument is the website to login to. Defaults to "www.roblox.com"
// if left empty.
func (client *Client) Logout(host string) (err error) {
	// Set default host.
	if host == "" {
		host = defaultHost
	}

	logoutURL := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   logoutPath,
	}

	// Do logout request.
	req, _ := http.NewRequest("POST", logoutURL.String(), nil)
	resp, err := assertStatus(client.Do(req))
	if err != nil {
		return err
	}
	resp.Body.Close()

	return nil
}
