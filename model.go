package rbxauth

import (
	"strconv"
	"strings"
)

// ErrorResponse implements the error response model of the API.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// Error implements the error interface.
func (err ErrorResponse) Error() string {
	return "response code " + strconv.Itoa(err.Code) + ": " + err.Message
}

// errorsResponse implements the errors response model of the API.
type errorsResponse struct {
	Errors []ErrorResponse `json:"errors,omitempty"`
}

// Error implements the error interface.
func (err errorsResponse) Error() string {
	s := make([]string, len(err.Errors))
	for i, e := range err.Errors {
		s[i] = e.Error()
	}
	return strings.Join(s, "; ")
}

// Unwrap implements the Unwrap interface by returning the first error in the
// list.
func (err errorsResponse) Unwrap() error {
	if len(err.Errors) == 0 {
		return nil
	}
	return err.Errors[0]
}

// errResp returns the errorsResponse.
func (err errorsResponse) errResp() errorsResponse {
	return err
}

// loginRequest implements the LoginRequest API model.
type loginRequest struct {
	CredType        string `json:"ctype,omitempty"`
	CredValue       string `json:"cvalue,omitempty"`
	Password        string `json:"password,omitempty"`
	CaptchaToken    string `json:"captchaToken,omitempty"`
	CaptchaProvider string `json:"captchaProvider,omitempty"`
}

// loginResponse implements the LoginResponse API model.
type loginResponse struct {
	User                    *userResponseV2                  `json:"user,omitempty"`
	TwoStepVerificationData *twoStepVerificationSentResponse `json:"twoStepVerificationData,omitempty"`
	errorsResponse
}

// userResponseV2 implements the UserResponseV2 API model.
type userResponseV2 struct {
	ID   int64  `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// twoStepVerificationSentResponse implements the
// TwoStepVerificationSentResponse API model.
type twoStepVerificationSentResponse struct {
	// The media type the two step verification code was sent on (Email, SMS).
	MediaType string `json:"mediaType,omitempty"`
	// The two step verification ticket.
	Ticket string `json:"ticket,omitempty"`
}

// userResponse implements the response to a UserIDEndpoint request.
type userResponse struct {
	ID          int64   `json:"Id"`
	Username    string  `json:"Username"`
	AvatarURI   *string `json:"AvatarUri,omitempty"`
	AvatarFinal bool    `json:"AvatarFinal"`
	IsOnline    bool    `json:"IsOnline"`
	errorsResponse
}

// twoStepVerificationVerifyRequest implements the
// TwoStepVerificationVerifyRequest API model.
type twoStepVerificationVerifyRequest struct {
	twoStepVerificationTicketRequest
	Code           string `json:"code,omitempty"`
	RememberDevice bool   `json:"rememberDevice,omitempty"`
}

// twoStepVerificationTicketRequest implements the
// TwoStepVerificationTicketRequest API model.
type twoStepVerificationTicketRequest struct {
	Username   string `json:"username,omitempty"`
	Ticket     string `json:"ticket,omitempty"`
	ActionType string `json:"actionType,omitempty"`
}
