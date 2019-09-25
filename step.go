package rbxauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Step holds the state of a multi-step verification action.
type Step struct {
	cfg Config
	req twoStepVerificationVerifyRequest

	// MediaType indicates the means by which the verification code was sent.
	MediaType string
}

// Verify receives a verification code to complete authentication. If
// successful, returns HTTP cookies representing the authenticated session.
//
// The remember argument specifies whether the current device should be
// remembered for future authentication.
func (s *Step) Verify(code string, remember bool) (cookies []*http.Cookie, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("verify: %w", err)
		}
	}()
	apiReq := s.req
	apiReq.Code = code
	apiReq.RememberDevice = remember
	body, _ := json.Marshal(&apiReq)

	endpoint := s.cfg.VerifyEndpoint
	if endpoint == "" {
		endpoint = DefaultVerifyEndpoint
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.requestAPI(req, &errorsResponse{})
	if err != nil {
		return nil, err
	}
	return resp.Cookies(), nil
}

// Resend retransmits a two-step verification message.
func (s *Step) Resend() (err error) {
	func() {
		if err != nil {
			err = fmt.Errorf("resend: %w", err)
		}
	}()

	body, _ := json.Marshal(&s.req.twoStepVerificationTicketRequest)

	endpoint := s.cfg.ResendEndpoint
	if endpoint == "" {
		endpoint = DefaultResendEndpoint
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	var apiResp struct {
		twoStepVerificationSentResponse
		errorsResponse
	}
	if _, err = s.cfg.requestAPI(req, &apiResp); err != nil {
		return err
	}
	s.MediaType = apiResp.MediaType
	s.req.Ticket = apiResp.Ticket
	return nil
}
