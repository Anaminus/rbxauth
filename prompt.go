package rbxauth

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"net/http"
	"os"
	"strings"
	"syscall"
)

// PromptCred prompts a user to login through standard input. Handles
// multi-step verification, if necessary.
//
// If cred.Type and/or cred.Ident are empty, then they will be prompted as
// well.
//
// Returns the updated cred and cookies, or any error that may have occurred.
func (cfg *Config) PromptCred(cred Cred) (Cred, []*http.Cookie, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanLines)

	// Prompt for credential type.
	for cred.Type == "" {
		fmt.Fprintf(os.Stderr, "Enter credential type (Username|Email|PhoneNumber): ")
		if scanner.Scan(); scanner.Err() != nil {
			return cred, nil, scanner.Err()
		}
		cred.Type = scanner.Text()
	}

	// Prompt for identifier.
	for cred.Ident == "" {
		var msg string
		switch strings.ToLower(cred.Type) {
		case "username":
			msg = "Enter username: "
		case "email":
			msg = "Enter email: "
		case "phonenumber":
			msg = "Enter phone number: "
		default:
			msg = "Enter " + cred.Type + ": "
		}
		fmt.Fprintf(os.Stderr, msg)
		if scanner.Scan(); scanner.Err() != nil {
			return cred, nil, scanner.Err()
		}
		cred.Ident = scanner.Text()
	}

	// Prompt for password.
	fmt.Fprintf(os.Stderr, "Enter password for %s: ", cred.Ident)
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return cred, nil, err
	}

	// Login.
	cookies, step, err := cfg.LoginCred(cred, password)
	if err != nil {
		return cred, nil, err
	}

	if step != nil {
		var code string
		var remember bool

		// Prompt for verification code.
		fmt.Fprintf(os.Stderr, "Two-step verification code sent via %s\n", step.MediaType)
		for {
			fmt.Fprintf(os.Stderr, "Enter code (leave empty to resend): ", cred.Ident)
			if scanner.Scan(); scanner.Err() != nil {
				return cred, nil, scanner.Err()
			}
			if code = scanner.Text(); code != "" {
				break
			}
			if err := step.Resend(); err != nil {
				return cred, nil, err
			}
			fmt.Fprintf(os.Stderr, "Resent verification code via %s\n", step.MediaType)
		}

		// Prompt for remember device.
	loop:
		for {
			fmt.Fprintf(os.Stderr, "Remember device? (y/N): ")
			if scanner.Scan(); scanner.Err() != nil {
				return cred, nil, scanner.Err()
			}
			switch text := strings.ToLower(scanner.Text()); text {
			case "y":
				if text == "y" {
					remember = true
				}
				fallthrough
			case "n", "":
				break loop
			}
		}

		// Verify code.
		if cookies, err = step.Verify(code, remember); err != nil {
			return cred, nil, err
		}
	}

	return cred, cookies, nil
}

// Prompt wraps PromptCred, using a username for the credentials.
func (cfg *Config) Prompt(username string) (Cred, []*http.Cookie, error) {
	return cfg.PromptCred(Cred{Type: "Username", Ident: username})
}

// PromptID wraps PromptCred, deriving credentials from the given user ID.
func (cfg *Config) PromptID(userID int64) (Cred, []*http.Cookie, error) {
	username, err := getUsername(cfg.Host, userID)
	if err != nil {
		return Cred{}, nil, err
	}
	return cfg.PromptCred(Cred{Type: "Username", Ident: username})
}
